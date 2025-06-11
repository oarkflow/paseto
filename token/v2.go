// token/token.go
package token

import (
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/oarkflow/shamir"
	"golang.org/x/crypto/chacha20poly1305"
)

var (
	// ErrInvalidToken is returned for any failure during decode/verify/decrypt/expiry/blacklist/revocation
	ErrInvalidToken = errors.New("token invalid or expired")
	// Default clock skew allows small clock drift when checking expiration/not-before
	defaultClockSkew = 1 * time.Minute
	// Maximum token size to prevent resource exhaustion attacks
	maxTokenSize = 8192
)

// Global clock skew with safe access
var (
	clockSkew   = defaultClockSkew
	clockSkewMu sync.RWMutex
)

// SetClockSkew updates the allowed clock skew globally
func SetClockSkew(skew time.Duration) {
	clockSkewMu.Lock()
	defer clockSkewMu.Unlock()
	clockSkew = skew
}

// GetClockSkew returns the current clock skew setting
func GetClockSkew() time.Duration {
	clockSkewMu.RLock()
	defer clockSkewMu.RUnlock()
	return clockSkew
}

// RevocationStore interface for persistent revocation storage
type RevocationStore interface {
	Revoke(id string, expiresAt time.Time) error
	IsRevoked(id string) (bool, error)
}

// In-memory store for revoked token IDs (jti)
var (
	revokedStore RevocationStore = &defaultRevocationStore{
		revoked: make(map[string]time.Time),
	}
	revokedMutex sync.RWMutex
)

type defaultRevocationStore struct {
	revoked map[string]time.Time // jti -> expiration time
}

func (s *defaultRevocationStore) Revoke(id string, expiresAt time.Time) error {
	revokedMutex.Lock()
	defer revokedMutex.Unlock()
	s.revoked[id] = expiresAt
	return nil
}

func (s *defaultRevocationStore) IsRevoked(id string) (bool, error) {
	revokedMutex.RLock()
	defer revokedMutex.RUnlock()
	expiry, ok := s.revoked[id]
	if !ok {
		return false, nil
	}

	// Clean up expired revocations
	if time.Now().UTC().After(expiry.Add(GetClockSkew())) {
		revokedMutex.RUnlock()
		revokedMutex.Lock()
		delete(s.revoked, id)
		revokedMutex.Unlock()
		revokedMutex.RLock()
		return false, nil
	}
	return true, nil
}

// SetRevocationStore sets a custom revocation store implementation
func SetRevocationStore(store RevocationStore) {
	revokedMutex.Lock()
	defer revokedMutex.Unlock()
	revokedStore = store
}

// Token represents the core token data with enhanced security features
type Token struct {
	Header      map[string]string // Metadata: version, alg, kid, etc.
	ID          string            // unique identifier (jti)
	IssuedAt    time.Time
	NotBefore   time.Time // nbf
	ExpiresAt   time.Time
	Claims      map[string]any
	Footer      map[string]string
	Blacklisted bool
}

type SignedToken struct {
	Payload   []byte
	Signature []byte
}

// Header constants
const (
	HeaderVersion = "v"
	HeaderAlg     = "alg"
	HeaderKeyID   = "kid"
)

// Algorithm types
const (
	AlgEncrypt = "XC20P" // XChaCha20-Poly1305
	AlgSign    = "EdDSA" // Ed25519
)

// ValidateKey ensures the symmetric key is 32 bytes for XChaCha20-Poly1305.
func ValidateKey(key []byte) error {
	if len(key) != chacha20poly1305.KeySize {
		return errors.New("invalid key length")
	}
	return nil
}

// CreateToken issues a new token with security headers
func CreateToken(ttl time.Duration, alg string, ids ...string) *Token {
	var keyID string
	if len(ids) > 0 {
		keyID = strings.TrimSpace(ids[0])
	}
	now := time.Now().UTC()
	idBytes := make([]byte, 16)
	_, _ = io.ReadFull(rand.Reader, idBytes)
	id := base64.RawURLEncoding.EncodeToString(idBytes)

	header := map[string]string{
		HeaderVersion: "1",
		HeaderAlg:     alg,
	}
	if keyID != "" {
		header[HeaderKeyID] = keyID
	}

	return &Token{
		Header:      header,
		ID:          id,
		IssuedAt:    now,
		NotBefore:   now,
		ExpiresAt:   now.Add(ttl),
		Claims:      make(map[string]any),
		Footer:      make(map[string]string),
		Blacklisted: false,
	}
}

// CreateRefreshToken issues a refresh token
func CreateRefreshToken(ttl time.Duration, ids ...string) *Token {
	var keyID string
	if len(ids) > 0 {
		keyID = strings.TrimSpace(ids[0])
	}
	t := CreateToken(ttl, AlgEncrypt, keyID)
	t.Footer["type"] = "refresh"
	return t
}

// BindToContext binds token to client context (IP, User-Agent)
func BindToContext(t *Token, ip, userAgent string) error {
	if t == nil {
		return errors.New("token is nil")
	}
	if err := RegisterFooter(t, "bind_ip", ip); err != nil {
		return err
	}
	return RegisterFooter(t, "bind_ua", userAgent)
}

// VerifyBinding checks token binding against client context
func VerifyBinding(t *Token, ip, userAgent string) bool {
	if t == nil {
		return false
	}

	storedIP, ok1 := t.Footer["bind_ip"]
	storedUA, ok2 := t.Footer["bind_ua"]

	if !ok1 || !ok2 {
		return false
	}

	// Constant-time comparisons to prevent timing attacks
	ipMatch := subtle.ConstantTimeCompare([]byte(storedIP), []byte(ip)) == 1
	uaMatch := subtle.ConstantTimeCompare([]byte(storedUA), []byte(userAgent)) == 1

	return ipMatch && uaMatch
}

// RegisterClaim adds or updates a single claim key→value.
func RegisterClaim(t *Token, key string, value any) error {
	if t == nil {
		return errors.New("token is nil")
	}
	if key == "" {
		return errors.New("claim key required")
	}
	if t.Claims == nil {
		t.Claims = make(map[string]any)
	}
	t.Claims[key] = value
	return nil
}

// RegisterClaims adds multiple claims at once.
func RegisterClaims(t *Token, claims map[string]any) error {
	if t == nil {
		return errors.New("token is nil")
	}
	if t.Claims == nil {
		t.Claims = make(map[string]any)
	}
	for k, v := range claims {
		if k == "" {
			return errors.New("claim key required")
		}
		t.Claims[k] = v
	}
	return nil
}

// RemoveClaim deletes a claim by key.
func RemoveClaim(t *Token, key string) error {
	if t == nil {
		return errors.New("token is nil")
	}
	delete(t.Claims, key)
	return nil
}

// GetClaim returns the value for a claim, and a boolean indicating presence.
func GetClaim(t *Token, key string) (any, bool) {
	if t == nil || t.Claims == nil {
		return nil, false
	}
	val, ok := t.Claims[key]
	return val, ok
}

// RegisterFooter adds or updates a footer entry.
func RegisterFooter(t *Token, key, value string) error {
	if t == nil {
		return errors.New("token is nil")
	}
	if key == "" {
		return errors.New("footer key required")
	}
	if t.Footer == nil {
		t.Footer = make(map[string]string)
	}
	t.Footer[key] = value
	return nil
}

// RemoveFooter deletes a footer entry by key.
func RemoveFooter(t *Token, key string) error {
	if t == nil {
		return errors.New("token is nil")
	}
	delete(t.Footer, key)
	return nil
}

// GetFooter returns the value for a footer entry and a boolean indicating presence.
func GetFooter(t *Token, key string) (string, bool) {
	if t == nil || t.Footer == nil {
		return "", false
	}
	val, ok := t.Footer[key]
	return val, ok
}

// BlacklistToken flags the token as blacklisted and revokes its jti.
func BlacklistToken(t *Token) error {
	if t == nil {
		return errors.New("token is nil")
	}
	t.Blacklisted = true
	return RevokeID(t.ID, t.ExpiresAt)
}

// RevokeID marks a token ID as revoked until its expiration
func RevokeID(id string, expiresAt time.Time) error {
	return revokedStore.Revoke(id, expiresAt)
}

// IsRevokedID checks if a token ID has been revoked.
func IsRevokedID(id string) (bool, error) {
	return revokedStore.IsRevoked(id)
}

// IsExpired checks whether the token is past its expiration + allowed clock skew.
func IsExpired(t *Token) bool {
	if t == nil {
		return true
	}
	now := time.Now().UTC()
	return now.After(t.ExpiresAt.Add(GetClockSkew()))
}

// IsNotYetValid checks whether the token is before its NotBefore - allowed skew.
func IsNotYetValid(t *Token) bool {
	if t == nil {
		return true
	}
	now := time.Now().UTC()
	return now.Add(GetClockSkew()).Before(t.NotBefore)
}

// IsBlacklisted returns the in-memory Blacklisted flag.
func IsBlacklisted(t *Token) bool {
	if t == nil {
		return false
	}
	return t.Blacklisted
}

// RemainingTTL returns the duration until expiration (or zero if expired).
func RemainingTTL(t *Token) time.Duration {
	if t == nil {
		return 0
	}
	now := time.Now().UTC()
	if now.After(t.ExpiresAt) {
		return 0
	}
	return t.ExpiresAt.Sub(now)
}

// ScanClaims iterates over claims; stops if fn returns false.
func ScanClaims(t *Token, fn func(key string, value any) bool) {
	if t == nil || t.Claims == nil {
		return
	}
	for k, v := range t.Claims {
		if !fn(k, v) {
			break
		}
	}
}

//  SERIALIZATION / DESERIALIZATION (MANUAL, ZERO-ALLOC BEYOND POOL)

// bytePool holds a reusable byte slice to minimize allocations.
var bytePool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 4096)
		return &b
	},
}

// appendString appends length-prefixed string to buf: [uint16(len)] + bytes.
func appendString(buf *[]byte, s string) {
	b := *buf
	n := len(s)
	b = append(b, byte(n>>8), byte(n))
	b = append(b, s...)
	*buf = b
}

// readString reads a length-prefixed string from data starting at idx.
func readString(data []byte, idx *int) (string, error) {
	if *idx+2 > len(data) {
		return "", ErrInvalidToken
	}
	length := int(data[*idx])<<8 | int(data[*idx+1])
	*idx += 2
	if *idx+length > len(data) {
		return "", ErrInvalidToken
	}
	s := string(data[*idx : *idx+length])
	*idx += length
	return s, nil
}

// Add pools for reusing key slices.
var headerKeysPool = sync.Pool{
	New: func() interface{} { return make([]string, 0, 8) },
}

var claimKeysPool = sync.Pool{
	New: func() interface{} { return make([]string, 0, 8) },
}

var footerKeysPool = sync.Pool{
	New: func() interface{} { return make([]string, 0, 8) },
}

// Add a pool for reusing nonce slices.
var noncePool = sync.Pool{
	New: func() interface{} {
		nonce := make([]byte, chacha20poly1305.NonceSizeX)
		return &nonce
	},
}

// serializeToken manually encodes the Token into a byte slice
func serializeToken(t *Token) ([]byte, error) {
	if t == nil {
		return nil, ErrInvalidToken
	}
	if t.Header == nil || t.Header[HeaderVersion] == "" || t.Header[HeaderAlg] == "" {
		return nil, ErrInvalidToken
	}

	// Validate state
	if IsExpired(t) || IsNotYetValid(t) || t.Blacklisted {
		return nil, ErrInvalidToken
	}
	if revoked, err := IsRevokedID(t.ID); err != nil || revoked {
		return nil, ErrInvalidToken
	}

	// Grab buffer from pool
	ptr := bytePool.Get().(*[]byte)
	buf := *ptr
	buf = buf[:0] // reset

	// HEADER: count (uint16) + sorted key/value
	hkeys := headerKeysPool.Get().([]string)
	hkeys = hkeys[:0]
	for k := range t.Header {
		hkeys = append(hkeys, k)
	}
	sort.Strings(hkeys)
	hcount := len(hkeys)
	buf = append(buf, byte(hcount>>8), byte(hcount))
	for _, k := range hkeys {
		v := t.Header[k]
		appendString(&buf, k)
		appendString(&buf, v)
	}
	headerKeysPool.Put(hkeys)

	// ID
	appendString(&buf, t.ID)

	// Times: IssuedAt, NotBefore, ExpiresAt (UnixNano each, 8 bytes)
	ts := []time.Time{t.IssuedAt, t.NotBefore, t.ExpiresAt}
	for _, tm := range ts {
		nano := tm.UnixNano()
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(nano))
		buf = append(buf, b[:]...)
	}

	// CLAIMS: count + sorted key/value, JSON-encode values
	keys := claimKeysPool.Get().([]string)
	keys = keys[:0]
	for k := range t.Claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	count := len(keys)
	buf = append(buf, byte(count>>8), byte(count))
	for _, k := range keys {
		v := t.Claims[k]
		jsonVal, err := json.Marshal(v)
		if err != nil {
			bytePool.Put(ptr)
			claimKeysPool.Put(keys)
			return nil, ErrInvalidToken
		}
		appendString(&buf, k)
		appendString(&buf, string(jsonVal))
	}
	claimKeysPool.Put(keys)

	// FOOTER: count + sorted key/value
	fkeys := footerKeysPool.Get().([]string)
	fkeys = fkeys[:0]
	for k := range t.Footer {
		fkeys = append(fkeys, k)
	}
	sort.Strings(fkeys)
	fcount := len(fkeys)
	buf = append(buf, byte(fcount>>8), byte(fcount))
	for _, k := range fkeys {
		v := t.Footer[k]
		appendString(&buf, k)
		appendString(&buf, v)
	}
	footerKeysPool.Put(fkeys)

	// BLACKLISTED FLAG
	if t.Blacklisted {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}

	*ptr = buf
	return buf, nil
}

// deserializeToken manually decodes a byte slice into a Token struct
func deserializeToken(data []byte) (*Token, error) {
	if len(data) == 0 {
		return nil, ErrInvalidToken
	}
	idx := 0

	// HEADER
	if idx+2 > len(data) {
		return nil, ErrInvalidToken
	}
	hcount := int(data[idx])<<8 | int(data[idx+1])
	idx += 2
	header := make(map[string]string, hcount)
	for i := 0; i < hcount; i++ {
		k, err := readString(data, &idx)
		if err != nil {
			return nil, ErrInvalidToken
		}
		v, err := readString(data, &idx)
		if err != nil {
			return nil, ErrInvalidToken
		}
		header[k] = v
	}

	// Validate header
	if header[HeaderVersion] != "1" ||
		(header[HeaderAlg] != AlgEncrypt && header[HeaderAlg] != AlgSign) {
		return nil, ErrInvalidToken
	}

	// ID
	readID, err := readString(data, &idx)
	if err != nil {
		return nil, ErrInvalidToken
	}

	// Times
	if idx+8*3 > len(data) {
		return nil, ErrInvalidToken
	}
	issuedAt := int64(binary.BigEndian.Uint64(data[idx : idx+8]))
	idx += 8
	notBefore := int64(binary.BigEndian.Uint64(data[idx : idx+8]))
	idx += 8
	expiresAt := int64(binary.BigEndian.Uint64(data[idx : idx+8]))
	idx += 8

	// CLAIMS
	if idx+2 > len(data) {
		return nil, ErrInvalidToken
	}
	count := int(data[idx])<<8 | int(data[idx+1])
	idx += 2
	claims := make(map[string]any, count)
	for i := 0; i < count; i++ {
		k, err := readString(data, &idx)
		if err != nil {
			return nil, ErrInvalidToken
		}
		v, err := readString(data, &idx)
		if err != nil {
			return nil, ErrInvalidToken
		}
		var val any
		if err := json.Unmarshal([]byte(v), &val); err != nil {
			return nil, ErrInvalidToken
		}
		claims[k] = val
	}

	// FOOTER
	if idx+2 > len(data) {
		return nil, ErrInvalidToken
	}
	fcount := int(data[idx])<<8 | int(data[idx+1])
	idx += 2
	footer := make(map[string]string, fcount)
	for i := 0; i < fcount; i++ {
		k, err := readString(data, &idx)
		if err != nil {
			return nil, ErrInvalidToken
		}
		v, err := readString(data, &idx)
		if err != nil {
			return nil, ErrInvalidToken
		}
		footer[k] = v
	}

	// BLACKLISTED FLAG
	if idx+1 > len(data) {
		return nil, ErrInvalidToken
	}
	black := data[idx] == 1

	t := &Token{
		Header:      header,
		ID:          readID,
		IssuedAt:    time.Unix(0, issuedAt).UTC(),
		NotBefore:   time.Unix(0, notBefore).UTC(),
		ExpiresAt:   time.Unix(0, expiresAt).UTC(),
		Claims:      claims,
		Footer:      footer,
		Blacklisted: black,
	}

	// Validate state
	if IsExpired(t) || IsNotYetValid(t) || t.Blacklisted {
		return nil, ErrInvalidToken
	}
	if revoked, err := IsRevokedID(t.ID); err != nil || revoked {
		return nil, ErrInvalidToken
	}

	return t, nil
}

//  AEAD POOL FOR EFFICIENT XChaCha20‐POLY1305

var aeadPool = sync.Pool{
	New: func() any {
		return &struct {
			aead cipher.AEAD
			key  []byte
		}{}
	},
}

// EncryptionAEAD produces a new XChaCha20‐Poly1305 AEAD instance
func EncryptionAEAD(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.NewX(key)
}

// Encrypt performs XChaCha20‐Poly1305 AEAD encryption, minimizing heap churn
func Encrypt(key, plaintext []byte) ([]byte, error) {
	if err := ValidateKey(key); err != nil {
		return nil, err
	}

	aeadItem := aeadPool.Get().(*struct {
		aead cipher.AEAD
		key  []byte
	})

	var aead cipher.AEAD
	var err error
	if aeadItem.aead != nil && subtle.ConstantTimeCompare(aeadItem.key, key) == 1 {
		aead = aeadItem.aead
	} else {
		aead, err = EncryptionAEAD(key)
		if err != nil {
			aeadPool.Put(aeadItem)
			return nil, err
		}
		aeadItem.aead = aead
		aeadItem.key = key
	}
	defer aeadPool.Put(aeadItem)

	// Get a nonce slice from the pool.
	np := noncePool.Get().(*[]byte)
	nonce := *np
	if _, err := rand.Read(nonce); err != nil {
		noncePool.Put(np)
		return nil, err
	}

	// Pre-calculate output length and allocate one result slice.
	outputLen := len(nonce) + len(plaintext) + aead.Overhead()
	dst := make([]byte, outputLen)
	// Copy nonce into dst.
	copy(dst, nonce)
	// The actual nonce length.
	dst = dst[:len(nonce)]
	// Seal appends ciphertext.
	dst = aead.Seal(dst, nonce, plaintext, nil)

	// Return nonce slice to the pool.
	noncePool.Put(np)

	return dst, nil
}

// Decrypt performs AEAD.Open with XChaCha20‐Poly1305
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	if err := ValidateKey(key); err != nil {
		return nil, ErrInvalidToken
	}
	if len(ciphertext) < chacha20poly1305.NonceSizeX {
		return nil, ErrInvalidToken
	}

	aeadItem := aeadPool.Get().(*struct {
		aead cipher.AEAD
		key  []byte
	})

	var aead cipher.AEAD
	var err error
	if aeadItem.aead != nil && subtle.ConstantTimeCompare(aeadItem.key, key) == 1 {
		aead = aeadItem.aead
	} else {
		aead, err = chacha20poly1305.NewX(key)
		if err != nil {
			aeadPool.Put(aeadItem)
			return nil, ErrInvalidToken
		}
		aeadItem.aead = aead
		aeadItem.key = key
	}
	defer aeadPool.Put(aeadItem)

	nonce := ciphertext[:chacha20poly1305.NonceSizeX]
	enc := ciphertext[chacha20poly1305.NonceSizeX:]
	plain, err := aead.Open(nil, nonce, enc, nil)
	if err != nil {
		return nil, ErrInvalidToken
	}
	return plain, nil
}

// EncodeBase64URL returns raw URL-safe base64 encoding
func EncodeBase64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// DecodeBase64URL decodes URL-safe base64 string
func DecodeBase64URL(data string) ([]byte, error) {
	if len(data) > maxTokenSize {
		return nil, ErrInvalidToken
	}
	raw, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		return nil, ErrInvalidToken
	}
	return raw, nil
}

// EncryptToken serializes then encrypts the Token
func EncryptToken(t *Token, key []byte, ids ...string) (string, error) {
	var keyID string
	if len(ids) > 0 {
		keyID = strings.TrimSpace(ids[0])
	}
	if t.Header == nil {
		t.Header = make(map[string]string)
	}
	t.Header[HeaderAlg] = AlgEncrypt
	if keyID != "" {
		t.Header[HeaderKeyID] = keyID
	}

	plain, err := serializeToken(t)
	if err != nil {
		return "", ErrInvalidToken
	}
	cipher, err := Encrypt(key, plain)
	if err != nil {
		return "", ErrInvalidToken
	}
	return EncodeBase64URL(cipher), nil
}

// DecryptToken decrypts and deserializes into Token
func DecryptToken(encoded string, key []byte) (*Token, error) {
	if len(encoded) > maxTokenSize {
		return nil, ErrInvalidToken
	}
	cipher, err := DecodeBase64URL(encoded)
	if err != nil {
		return nil, ErrInvalidToken
	}
	plain, err := Decrypt(key, cipher)
	if err != nil {
		return nil, ErrInvalidToken
	}
	return deserializeToken(plain)
}

// SignToken serializes t, then signs the bytes
func SignToken(t *Token, priv ed25519.PrivateKey, ids ...string) (*SignedToken, error) {
	var keyID string
	if len(ids) > 0 {
		keyID = strings.TrimSpace(ids[0])
	}
	if t.Header == nil {
		t.Header = make(map[string]string)
	}
	t.Header[HeaderAlg] = AlgSign
	if keyID != "" {
		t.Header[HeaderKeyID] = keyID
	}

	payload, err := serializeToken(t)
	if err != nil {
		return nil, ErrInvalidToken
	}
	sig := ed25519.Sign(priv, payload)
	return &SignedToken{Payload: payload, Signature: sig}, nil
}

// VerifyToken checks the signature and deserializes the Token
func VerifyToken(s *SignedToken, pub ed25519.PublicKey) (*Token, error) {
	if s == nil || len(s.Payload) == 0 || len(s.Signature) != ed25519.SignatureSize {
		return nil, ErrInvalidToken
	}
	if !ed25519.Verify(pub, s.Payload, s.Signature) {
		return nil, ErrInvalidToken
	}
	return deserializeToken(s.Payload)
}

// EncodeSignedToken returns "Base64URL(payload).Base64URL(signature)"
func EncodeSignedToken(st *SignedToken) string {
	return EncodeBase64URL(st.Payload) + "." + EncodeBase64URL(st.Signature)
}

// DecodeSignedToken splits and decodes both parts
func DecodeSignedToken(encoded string) (*SignedToken, error) {
	if len(encoded) > maxTokenSize {
		return nil, ErrInvalidToken
	}
	parts := strings.Split(encoded, ".")
	if len(parts) != 2 {
		return nil, ErrInvalidToken
	}
	payload, err := DecodeBase64URL(parts[0])
	if err != nil {
		return nil, ErrInvalidToken
	}
	sig, err := DecodeBase64URL(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}
	return &SignedToken{Payload: payload, Signature: sig}, nil
}

// RefreshToken handles token refresh with revocation
func RefreshToken(refreshTokenEncoded string, key []byte, newTTL time.Duration) (string, error) {
	rt, err := DecryptToken(refreshTokenEncoded, key)
	if err != nil {
		return "", ErrInvalidToken
	}
	if rt.Footer["type"] != "refresh" {
		return "", ErrInvalidToken
	}

	// Revoke old token
	if err := RevokeID(rt.ID, rt.ExpiresAt); err != nil {
		return "", err
	}

	// Create new token
	keyID := rt.Header[HeaderKeyID]
	newToken := CreateToken(newTTL, AlgEncrypt, keyID)

	// Copy claims and footer
	for k, v := range rt.Claims {
		newToken.Claims[k] = v
	}
	for k, v := range rt.Footer {
		newToken.Footer[k] = v
	}
	delete(newToken.Footer, "type")

	return EncryptToken(newToken, key, keyID)
}

// DeterministicToken for reproducible tests
func DeterministicToken(
	now time.Time,
	claims map[string]any,
	footer map[string]string,
	ttl time.Duration,
	ids ...string,
) *Token {
	var keyID string
	if len(ids) > 0 && ids[0] != "" {
		keyID = strings.TrimSpace(ids[0])
	}
	idBytes := make([]byte, 16)
	_, _ = io.ReadFull(rand.Reader, idBytes)
	id := base64.RawURLEncoding.EncodeToString(idBytes)
	return &Token{
		Header: map[string]string{
			HeaderVersion: "1",
			HeaderAlg:     AlgEncrypt,
			HeaderKeyID:   keyID,
		},
		ID:          id,
		IssuedAt:    now,
		NotBefore:   now,
		ExpiresAt:   now.Add(ttl),
		Claims:      copyClaims(claims),
		Footer:      copyFooter(footer),
		Blacklisted: false,
	}
}

func copyClaims(src map[string]any) map[string]any {
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func copyFooter(src map[string]string) map[string]string {
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// RevokeToken revokes a token given its encrypted string
func RevokeToken(encoded string, key []byte) error {
	t, err := parseTokenRaw(encoded, key)
	if err != nil {
		return ErrInvalidToken
	}
	return RevokeID(t.ID, t.ExpiresAt)
}

// IsRevokedToken checks if a token has been revoked
func IsRevokedToken(encoded string, key []byte) (bool, error) {
	t, err := parseTokenRaw(encoded, key)
	if err != nil {
		return false, ErrInvalidToken
	}
	return IsRevokedID(t.ID)
}

// IsValidToken returns true if token passes all checks
func IsValidToken(encoded string, key []byte) bool {
	_, err := DecryptToken(encoded, key)
	return err == nil
}

// parseTokenRaw decrypts without validation
func parseTokenRaw(encoded string, key []byte) (*Token, error) {
	if len(encoded) > maxTokenSize {
		return nil, ErrInvalidToken
	}
	cipher, err := DecodeBase64URL(encoded)
	if err != nil {
		return nil, ErrInvalidToken
	}
	plain, err := Decrypt(key, cipher)
	if err != nil {
		return nil, ErrInvalidToken
	}
	return deserializeTokenRaw(plain)
}

func deserializeTokenRaw(data []byte) (*Token, error) {
	if len(data) == 0 {
		return nil, ErrInvalidToken
	}
	idx := 0

	// HEADER
	if idx+2 > len(data) {
		return nil, ErrInvalidToken
	}
	hcount := int(data[idx])<<8 | int(data[idx+1])
	idx += 2
	header := make(map[string]string, hcount)
	for i := 0; i < hcount; i++ {
		k, err := readString(data, &idx)
		if err != nil {
			return nil, ErrInvalidToken
		}
		v, err := readString(data, &idx)
		if err != nil {
			return nil, ErrInvalidToken
		}
		header[k] = v
	}

	// ID
	readID, err := readString(data, &idx)
	if err != nil {
		return nil, ErrInvalidToken
	}

	// Times
	if idx+8*3 > len(data) {
		return nil, ErrInvalidToken
	}
	issuedAt := int64(binary.BigEndian.Uint64(data[idx : idx+8]))
	idx += 8
	notBefore := int64(binary.BigEndian.Uint64(data[idx : idx+8]))
	idx += 8
	expiresAt := int64(binary.BigEndian.Uint64(data[idx : idx+8]))
	idx += 8

	// CLAIMS
	if idx+2 > len(data) {
		return nil, ErrInvalidToken
	}
	count := int(data[idx])<<8 | int(data[idx+1])
	idx += 2
	claims := make(map[string]any, count)
	for i := 0; i < count; i++ {
		k, err := readString(data, &idx)
		if err != nil {
			return nil, ErrInvalidToken
		}
		v, err := readString(data, &idx)
		if err != nil {
			return nil, ErrInvalidToken
		}
		var val any
		if err := json.Unmarshal([]byte(v), &val); err != nil {
			return nil, ErrInvalidToken
		}
		claims[k] = val
	}

	// FOOTER
	if idx+2 > len(data) {
		return nil, ErrInvalidToken
	}
	fcount := int(data[idx])<<8 | int(data[idx+1])
	idx += 2
	footer := make(map[string]string, fcount)
	for i := 0; i < fcount; i++ {
		k, err := readString(data, &idx)
		if err != nil {
			return nil, ErrInvalidToken
		}
		v, err := readString(data, &idx)
		if err != nil {
			return nil, ErrInvalidToken
		}
		footer[k] = v
	}

	// BLACKLISTED FLAG
	if idx+1 > len(data) {
		return nil, ErrInvalidToken
	}
	black := data[idx] == 1

	t := &Token{
		Header:      header,
		ID:          readID,
		IssuedAt:    time.Unix(0, issuedAt).UTC(),
		NotBefore:   time.Unix(0, notBefore).UTC(),
		ExpiresAt:   time.Unix(0, expiresAt).UTC(),
		Claims:      claims,
		Footer:      footer,
		Blacklisted: black,
	}
	return t, nil
}

// KeyManager holds a small ring of currently valid symmetric keys (keyID→keyBytes).
// Each rotation generates a fresh 32-byte key, splits it via Shamir, and stores both the key
// and its shares.  Older keys are pruned after a configurable period.
type KeyManager struct {
	sync.RWMutex
	// keyRing maps keyID → (keyBytes, expiresAt)
	keyRing        map[string]keyInfo
	rotationPeriod time.Duration
	cacheLimit     int
	// sharesMap maps keyID → the [][]byte shares produced by shamir.Split,
	// so that later you can persist or re‐combine them.
	sharesMap map[string][][]byte
}

type keyInfo struct {
	keyBytes  []byte
	expiresAt time.Time
}

// NewKeyManager initializes a manager that rotates every rotationPeriod.
// cacheLimit is how many keys to keep in memory at once.  N = total shares, M = threshold.
func NewKeyManager(rotationPeriod time.Duration, cacheLimit, totalShares, threshold int) (*KeyManager, error) {
	if cacheLimit < 1 {
		return nil, errors.New("cacheLimit must be ≥1")
	}

	km := &KeyManager{
		keyRing:        make(map[string]keyInfo),
		rotationPeriod: rotationPeriod,
		cacheLimit:     cacheLimit,
		sharesMap:      make(map[string][][]byte),
	}

	// Immediately generate the first key
	if err := km.rotateInternal(totalShares, threshold); err != nil {
		return nil, err
	}

	// Schedule subsequent rotations
	ticker := time.NewTicker(rotationPeriod)
	go func() {
		for range ticker.C {
			_ = km.rotateInternal(totalShares, threshold)
		}
	}()

	return km, nil
}

// rotateInternal generates a new 32-byte key, Shamir-splits it, and prunes old keys.
func (km *KeyManager) rotateInternal(N, M int) error {
	km.Lock()
	defer km.Unlock()

	// 1) Generate fresh 32-byte key
	masterKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(masterKey); err != nil {
		return err
	}

	// 2) Construct a new keyID (timestamp-based)
	keyID := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	expiry := time.Now().UTC().Add(km.rotationPeriod)
	km.keyRing[keyID] = keyInfo{keyBytes: masterKey, expiresAt: expiry}

	// 3) Split via Shamir into N shares (threshold M)
	shares, err := shamir.Split(masterKey, N, M)
	if err != nil {
		return err
	}
	// Store them in-memory—for real use, persist these shares to secure storage.
	km.sharesMap[keyID] = shares

	// 4) Prune older keys beyond cacheLimit
	if len(km.keyRing) > km.cacheLimit {
		type pair struct {
			id  string
			exp time.Time
		}
		var lst []pair
		for id, info := range km.keyRing {
			lst = append(lst, pair{id: id, exp: info.expiresAt})
		}
		sort.Slice(lst, func(i, j int) bool {
			return lst[i].exp.Before(lst[j].exp)
		})
		for i := 0; i < len(lst)-km.cacheLimit; i++ {
			delete(km.keyRing, lst[i].id)
			delete(km.sharesMap, lst[i].id)
		}
	}

	return nil
}

// GetCurrentKey returns (keyID, keyBytes) for encryption—the newest key in the ring.
func (km *KeyManager) GetCurrentKey() (string, []byte) {
	km.RLock()
	defer km.RUnlock()

	var newestID string
	var newestTime time.Time
	for id, info := range km.keyRing {
		if info.expiresAt.After(newestTime) {
			newestTime = info.expiresAt
			newestID = id
		}
	}
	if newestID == "" {
		return "", nil
	}
	return newestID, km.keyRing[newestID].keyBytes
}

// LookupKey returns the keyBytes for a given keyID, if it’s still in the ring and not expired.
func (km *KeyManager) LookupKey(keyID string) ([]byte, bool) {
	km.RLock()
	defer km.RUnlock()
	info, ok := km.keyRing[keyID]
	if !ok {
		return nil, false
	}
	if time.Now().UTC().After(info.expiresAt.Add(GetClockSkew())) {
		return nil, false
	}
	return info.keyBytes, true
}

// SharesForKey returns the stored Shamir shares for a given keyID (nil if none).
func (km *KeyManager) SharesForKey(keyID string) [][]byte {
	km.RLock()
	defer km.RUnlock()
	return km.sharesMap[keyID]
}

// ImportKeyFromShares reconstructs a key from its Shamir shares and re‐inserts it under keyID.
func (km *KeyManager) ImportKeyFromShares(keyID string, shares [][]byte, expiresAt time.Time) error {
	km.Lock()
	defer km.Unlock()
	secret, err := shamir.Combine(shares)
	if err != nil {
		return err
	}
	km.keyRing[keyID] = keyInfo{keyBytes: secret, expiresAt: expiresAt}
	return nil
}

// EncryptWithKM looks up the current key from km, sets Header["kid"], then encrypts.
func EncryptWithKM(km *KeyManager, t *Token) (string, error) {
	keyID, keyBytes := km.GetCurrentKey()
	if keyID == "" {
		return "", errors.New("no active key available")
	}
	return EncryptToken(t, keyBytes, keyID)
}

// DecryptWithKM reads Header["kid"] from the decrypted header bytes, then fetches the correct keyBytes.
func DecryptWithKM(km *KeyManager, encoded string) (*Token, error) {
	// 1) Decode base64
	ciphertext, err := DecodeBase64URL(encoded)
	if err != nil {
		return nil, ErrInvalidToken
	}
	// 2) We need to peek at the decryption to extract keyID from the header.
	//    We'll attempt with every key in the ring until one succeeds,
	//    but we can optimize by inspecting the header prefix after a partial decrypt.
	for keyID, info := range km.keyRing {
		if time.Now().UTC().After(info.expiresAt.Add(GetClockSkew())) {
			continue
		}
		// Try decrypt
		plaintext, err2 := Decrypt(info.keyBytes, ciphertext)
		if err2 != nil {
			continue
		}
		// Now read the header from plaintext
		decodedHeader, err3 := parseHeaderOnly(plaintext)
		if err3 != nil {
			continue
		}
		// If the header’s kid matches this keyID, we have a winner:
		if decodedHeader[HeaderKeyID] == keyID {
			// Full deserialize/validation
			return deserializeToken(plaintext)
		}
	}
	return nil, ErrInvalidToken
}

// parseHeaderOnly is a minimal pass to extract the header map from the decrypted plaintext.
func parseHeaderOnly(data []byte) (map[string]string, error) {
	idx := 0
	if idx+2 > len(data) {
		return nil, ErrInvalidToken
	}
	hcount := int(data[idx])<<8 | int(data[idx+1])
	idx += 2
	header := make(map[string]string, hcount)
	for i := 0; i < hcount; i++ {
		k, err := readString(data, &idx)
		if err != nil {
			return nil, ErrInvalidToken
		}
		v, err := readString(data, &idx)
		if err != nil {
			return nil, ErrInvalidToken
		}
		header[k] = v
	}
	return header, nil
}
