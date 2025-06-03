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
	"io"
	"sort"
	"strings"
	"sync"
	"time"

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
	if len(ids) > 0 && ids[0] != "" {
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
	if len(ids) > 0 && ids[0] != "" {
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

// bytePool holds a reusable byte slice buffer to minimize allocations.
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

// serializeToken manually encodes the Token into a byte slice
func serializeToken(t *Token) ([]byte, error) {
	if t == nil {
		return nil, ErrInvalidToken
	}
	if t.Header == nil || t.Header[HeaderVersion] == "" || t.Header[HeaderAlg] == "" {
		return nil, ErrInvalidToken
	}

	// Grab buffer from pool
	ptr := bytePool.Get().(*[]byte)
	buf := *ptr
	buf = buf[:0] // reset

	// Header: write count (uint16), then sorted key/value
	hkeys := make([]string, 0, len(t.Header))
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

	// ID
	appendString(&buf, t.ID)

	// Times: IssuedAt, NotBefore, ExpiresAt as UnixNano (8 bytes each)
	ts := []time.Time{t.IssuedAt, t.NotBefore, t.ExpiresAt}
	for _, tm := range ts {
		n := tm.UnixNano()
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(n))
		buf = append(buf, b[:]...)
	}

	// Claims: write count (uint16), then sorted key/value
	keys := make([]string, 0, len(t.Claims))
	for k := range t.Claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	count := len(keys)
	buf = append(buf, byte(count>>8), byte(count))
	for _, k := range keys {
		v := t.Claims[k]
		// JSON encode values for deterministic serialization
		jsonVal, err := json.Marshal(v)
		if err != nil {
			bytePool.Put(ptr)
			return nil, ErrInvalidToken
		}
		appendString(&buf, k)
		appendString(&buf, string(jsonVal))
	}

	// Footer: write count, then sorted key/value
	fkeys := make([]string, 0, len(t.Footer))
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

	// Blacklisted flag (1 byte)
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

	// Header
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

	// Claims
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

		// JSON decode values
		var val any
		if err := json.Unmarshal([]byte(v), &val); err != nil {
			return nil, ErrInvalidToken
		}
		claims[k] = val
	}

	// Footer
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

	// Blacklisted flag
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

	// Validate time/blacklist/revocation
	if IsExpired(t) || IsNotYetValid(t) || t.Blacklisted {
		return nil, ErrInvalidToken
	}

	// Check revocation status
	if revoked, err := IsRevokedID(t.ID); err != nil || revoked {
		return nil, ErrInvalidToken
	}

	return t, nil
}

// AEAD pool for efficient encryption/decryption
var aeadPool = sync.Pool{
	New: func() any {
		return &struct {
			aead cipher.AEAD
			key  []byte
		}{}
	},
}

// Encrypt performs XChaCha20-Poly1305 AEAD encryption
func Encrypt(key, plaintext []byte) ([]byte, error) {
	if err := ValidateKey(key); err != nil {
		return nil, err
	}

	// Get AEAD from pool or create new
	aeadItem := aeadPool.Get().(*struct {
		aead cipher.AEAD
		key  []byte
	})

	// Reuse if same key, else create new
	var aead cipher.AEAD
	var err error
	if aeadItem.aead != nil && subtle.ConstantTimeCompare(aeadItem.key, key) == 1 {
		aead = aeadItem.aead
	} else {
		aead, err = chacha20poly1305.NewX(key)
		if err != nil {
			aeadPool.Put(aeadItem)
			return nil, err
		}
		aeadItem.aead = aead
		aeadItem.key = key
	}
	defer aeadPool.Put(aeadItem)

	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// Preallocate dst: nonce + plaintext + tag
	dst := make([]byte, 0, len(nonce)+len(plaintext)+aead.Overhead())
	dst = append(dst, nonce...)
	dst = aead.Seal(dst, nonce, plaintext, nil)
	return dst, nil
}

// Decrypt performs AEAD.Open with XChaCha20-Poly1305
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	if err := ValidateKey(key); err != nil {
		return nil, ErrInvalidToken
	}
	if len(ciphertext) < chacha20poly1305.NonceSizeX {
		return nil, ErrInvalidToken
	}

	// Get AEAD from pool or create new
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
	if len(ids) > 0 && ids[0] != "" {
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

// Sign returns an Ed25519 signature
func Sign(privateKey ed25519.PrivateKey, payload []byte) []byte {
	return ed25519.Sign(privateKey, payload)
}

// VerifySignature verifies an Ed25519 signature
func VerifySignature(publicKey ed25519.PublicKey, payload, sig []byte) bool {
	return ed25519.Verify(publicKey, payload, sig)
}

// SignToken serializes t, then signs the bytes
func SignToken(t *Token, priv ed25519.PrivateKey, ids ...string) (*SignedToken, error) {
	var keyID string
	if len(ids) > 0 && ids[0] != "" {
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
	sig := Sign(priv, payload)
	return &SignedToken{Payload: payload, Signature: sig}, nil
}

// VerifyToken checks the signature and deserializes the Token
func VerifyToken(s *SignedToken, pub ed25519.PublicKey) (*Token, error) {
	if s == nil || len(s.Payload) == 0 || len(s.Signature) != ed25519.SignatureSize {
		return nil, ErrInvalidToken
	}
	if !VerifySignature(pub, s.Payload, s.Signature) {
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
func DeterministicToken(now time.Time, claims map[string]any, footer map[string]string, ttl time.Duration, ids ...string) *Token {
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

// deserializeTokenRaw decodes without validation
func deserializeTokenRaw(data []byte) (*Token, error) {
	if len(data) == 0 {
		return nil, ErrInvalidToken
	}
	idx := 0

	// Header
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

	// Claims
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

		// JSON decode values
		var val any
		if err := json.Unmarshal([]byte(v), &val); err != nil {
			return nil, ErrInvalidToken
		}
		claims[k] = val
	}

	// Footer
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

	// Blacklisted flag
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
