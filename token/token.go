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
	Header       map[string]string // Metadata: version, alg, kid, etc.
	ID           string            // unique identifier (jti)
	IssuedAt     time.Time
	NotBefore    time.Time // nbf
	ExpiresAt    time.Time
	Claims       map[string]any    // JSON-serializable claims
	BinaryClaims map[string][]byte // Efficient binary claims
	RawClaim     []byte            // Single raw claim payload
	Footer       map[string]string
	Blacklisted  bool
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
	HeaderRawFlag = "raw"
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

func generateTokenID() string {
	idBytes := make([]byte, 16)
	_, _ = io.ReadFull(rand.Reader, idBytes)
	return base64.RawURLEncoding.EncodeToString(idBytes)
}

// CreateToken issues a new token with security headers
func CreateToken(ttl time.Duration, alg string, ids ...string) *Token {
	var keyID string
	if len(ids) > 0 {
		keyID = strings.TrimSpace(ids[0])
	}
	now := time.Now().UTC()
	id := generateTokenID()

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
func (t *Token) BindToContext(ip, userAgent string) error {
	if t == nil {
		return errors.New("token is nil")
	}
	if err := t.RegisterFooter("bind_ip", ip); err != nil {
		return err
	}
	return t.RegisterFooter("bind_ua", userAgent)
}

// VerifyBinding checks token binding against client context
func (t *Token) VerifyBinding(ip, userAgent string) bool {
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
func (t *Token) RegisterClaim(key string, value any) error {
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
func (t *Token) RegisterClaims(claims map[string]any) error {
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
func (t *Token) RemoveClaim(key string) error {
	if t == nil {
		return errors.New("token is nil")
	}
	delete(t.Claims, key)
	return nil
}

// GetClaim returns the value for a claim, and a boolean indicating presence.
func (t *Token) GetClaim(key string) (any, bool) {
	if t == nil || t.Claims == nil {
		return nil, false
	}
	val, ok := t.Claims[key]
	return val, ok
}

// RegisterBinaryClaim adds or updates a binary claim key→value.
func (t *Token) RegisterBinaryClaim(key string, value []byte) error {
	if t == nil {
		return errors.New("token is nil")
	}
	if key == "" {
		return errors.New("binary claim key required")
	}
	if t.BinaryClaims == nil {
		t.BinaryClaims = make(map[string][]byte)
	}
	// Copy the value to avoid external mutations
	t.BinaryClaims[key] = append([]byte(nil), value...)
	return nil
}

// RegisterByte stores a single raw claim payload without a key.
func (t *Token) RegisterByte(value []byte) error {
	if t == nil {
		return errors.New("token is nil")
	}
	if len(value) == 0 {
		t.RawClaim = nil
		return nil
	}
	if cap(t.RawClaim) >= len(value) {
		t.RawClaim = t.RawClaim[:len(value)]
		copy(t.RawClaim, value)
		return nil
	}
	t.RawClaim = append([]byte(nil), value...)
	return nil
}

// RegisterBinaryClaims adds multiple binary claims at once.
func (t *Token) RegisterBinaryClaims(claims map[string][]byte) error {
	if t == nil {
		return errors.New("token is nil")
	}
	if t.BinaryClaims == nil {
		t.BinaryClaims = make(map[string][]byte)
	}
	for k, v := range claims {
		if k == "" {
			return errors.New("binary claim key required")
		}
		t.BinaryClaims[k] = append([]byte(nil), v...)
	}
	return nil
}

// RemoveBinaryClaim deletes a binary claim by key.
func (t *Token) RemoveBinaryClaim(key string) error {
	if t == nil {
		return errors.New("token is nil")
	}
	delete(t.BinaryClaims, key)
	return nil
}

// GetBinaryClaim returns the value for a binary claim, and a boolean indicating presence.
func (t *Token) GetBinaryClaim(key string) ([]byte, bool) {
	if t == nil || t.BinaryClaims == nil {
		return nil, false
	}
	val, ok := t.BinaryClaims[key]
	return val, ok
}

// RegisterFooter adds or updates a footer entry.
func (t *Token) RegisterFooter(key, value string) error {
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
func (t *Token) RemoveFooter(key string) error {
	if t == nil {
		return errors.New("token is nil")
	}
	delete(t.Footer, key)
	return nil
}

// GetFooter returns the value for a footer entry and a boolean indicating presence.
func (t *Token) GetFooter(key string) (string, bool) {
	if t == nil || t.Footer == nil {
		return "", false
	}
	val, ok := t.Footer[key]
	return val, ok
}

// BlacklistToken flags the token as blacklisted and revokes its jti.
func (t *Token) BlacklistToken() error {
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
func (t *Token) IsExpired() bool {
	if t == nil {
		return true
	}
	now := time.Now().UTC()
	return now.After(t.ExpiresAt.Add(GetClockSkew()))
}

// IsNotYetValid checks whether the token is before its NotBefore - allowed skew.
func (t *Token) IsNotYetValid() bool {
	if t == nil {
		return true
	}
	now := time.Now().UTC()
	return now.Add(GetClockSkew()).Before(t.NotBefore)
}

// IsBlacklisted returns the in-memory Blacklisted flag.
func (t *Token) IsBlacklisted() bool {
	if t == nil {
		return false
	}
	return t.Blacklisted
}

// RemainingTTL returns the duration until expiration (or zero if expired).
func (t *Token) RemainingTTL() time.Duration {
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
func (t *Token) ScanClaims(fn func(key string, value any) bool) {
	if t == nil || t.Claims == nil {
		return
	}
	for k, v := range t.Claims {
		if !fn(k, v) {
			break
		}
	}
}

// SerializeToken manually encodes the Token into a byte slice
func (t *Token) SerializeToken() ([]byte, error) {
	sb, err := t.encode()
	if err != nil {
		return nil, err
	}
	return sb.Detach(), nil
}

func (t *Token) encode() (*serializedBuffer, error) {
	if t == nil {
		return nil, ErrInvalidToken
	}
	if t.Header == nil || t.Header[HeaderVersion] == "" || t.Header[HeaderAlg] == "" {
		return nil, ErrInvalidToken
	}
	if len(t.RawClaim) > 0 {
		t.Header[HeaderRawFlag] = "1"
	} else {
		delete(t.Header, HeaderRawFlag)
	}

	// Validate state
	if t.IsExpired() || t.IsNotYetValid() || t.Blacklisted {
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
			claimKeysPool.Put(keys)
			bytePool.Put(ptr)
			return nil, ErrInvalidToken
		}
		appendString(&buf, k)
		appendString(&buf, string(jsonVal))
	}
	claimKeysPool.Put(keys)

	// BINARY CLAIMS: count + sorted key/value, stored as binary
	bkeys := claimKeysPool.Get().([]string)
	bkeys = bkeys[:0]
	for k := range t.BinaryClaims {
		bkeys = append(bkeys, k)
	}
	sort.Strings(bkeys)
	bcount := len(bkeys)
	buf = append(buf, byte(bcount>>8), byte(bcount))
	for _, k := range bkeys {
		v := t.BinaryClaims[k]
		appendString(&buf, k)
		// Store binary value with length prefix
		vlen := len(v)
		buf = append(buf, byte(vlen>>24), byte(vlen>>16), byte(vlen>>8), byte(vlen))
		buf = append(buf, v...)
	}
	claimKeysPool.Put(bkeys)

	if len(t.RawClaim) > 0 {
		rlen := len(t.RawClaim)
		buf = append(buf, byte(rlen>>24), byte(rlen>>16), byte(rlen>>8), byte(rlen))
		buf = append(buf, t.RawClaim...)
	}

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
	return &serializedBuffer{ptr: ptr, buf: buf}, nil
}

// deserializeToken manually decodes a byte slice into a Token struct
func deserializeToken(data []byte) (*Token, error) {
	return decodeToken(data, true)
}

func decodeToken(data []byte, strict bool) (*Token, error) {
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
	hasRaw := header[HeaderRawFlag] == "1"

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

	// BINARY CLAIMS
	if idx+2 > len(data) {
		return nil, ErrInvalidToken
	}
	bcount := int(data[idx])<<8 | int(data[idx+1])
	idx += 2
	binaryClaims := make(map[string][]byte, bcount)
	for i := 0; i < bcount; i++ {
		k, err := readString(data, &idx)
		if err != nil {
			return nil, ErrInvalidToken
		}
		// Read binary value with 4-byte length prefix
		if idx+4 > len(data) {
			return nil, ErrInvalidToken
		}
		vlen := int(data[idx])<<24 | int(data[idx+1])<<16 | int(data[idx+2])<<8 | int(data[idx+3])
		idx += 4
		if idx+vlen > len(data) {
			return nil, ErrInvalidToken
		}
		v := make([]byte, vlen)
		copy(v, data[idx:idx+vlen])
		idx += vlen
		binaryClaims[k] = v
	}

	var rawClaim []byte
	if hasRaw {
		if idx+4 > len(data) {
			return nil, ErrInvalidToken
		}
		rlen := int(data[idx])<<24 | int(data[idx+1])<<16 | int(data[idx+2])<<8 | int(data[idx+3])
		idx += 4
		if rlen < 0 || idx+rlen > len(data) {
			return nil, ErrInvalidToken
		}
		if rlen > 0 {
			rawClaim = make([]byte, rlen)
			copy(rawClaim, data[idx:idx+rlen])
		}
		idx += rlen
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
		Header:       header,
		ID:           readID,
		IssuedAt:     time.Unix(0, issuedAt).UTC(),
		NotBefore:    time.Unix(0, notBefore).UTC(),
		ExpiresAt:    time.Unix(0, expiresAt).UTC(),
		Claims:       claims,
		BinaryClaims: binaryClaims,
		RawClaim:     rawClaim,
		Footer:       footer,
		Blacklisted:  black,
	}

	if strict {
		if t.IsExpired() || t.IsNotYetValid() || t.Blacklisted {
			return nil, ErrInvalidToken
		}
		if revoked, err := IsRevokedID(t.ID); err != nil || revoked {
			return nil, ErrInvalidToken
		}
	}

	return t, nil
}

// deserializeTokenRaw decodes without enforcing staleness/blacklist checks.
func deserializeTokenRaw(data []byte) (*Token, error) {
	return decodeToken(data, false)
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

func (t *Token) EncryptToken(key []byte, ids ...string) (string, error) {
	return EncryptToken(t, key, ids...)
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

	sb, err := t.encode()
	if err != nil {
		return "", ErrInvalidToken
	}
	defer sb.Release()
	cipher, err := Encrypt(key, sb.Bytes())
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

func (t *Token) SignToken(priv ed25519.PrivateKey, ids ...string) (*SignedToken, error) {
	return SignToken(t, priv, ids...)
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

	sb, err := t.encode()
	if err != nil {
		return nil, ErrInvalidToken
	}
	payload := sb.Detach()
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
	for k, v := range rt.BinaryClaims {
		newToken.BinaryClaims[k] = append([]byte(nil), v...)
	}
	if len(rt.RawClaim) > 0 {
		newToken.RawClaim = append([]byte(nil), rt.RawClaim...)
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
	binaryClaims map[string][]byte,
	footer map[string]string,
	ttl time.Duration,
	ids ...string,
) *Token {
	var keyID string
	if len(ids) > 0 && ids[0] != "" {
		keyID = strings.TrimSpace(ids[0])
	}
	id := generateTokenID()
	return &Token{
		Header: map[string]string{
			HeaderVersion: "1",
			HeaderAlg:     AlgEncrypt,
			HeaderKeyID:   keyID,
		},
		ID:           id,
		IssuedAt:     now,
		NotBefore:    now,
		ExpiresAt:    now.Add(ttl),
		Claims:       copyClaims(claims),
		BinaryClaims: copyBinaryClaims(binaryClaims),
		Footer:       copyFooter(footer),
		Blacklisted:  false,
	}
}

func copyClaims(src map[string]any) map[string]any {
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func copyBinaryClaims(src map[string][]byte) map[string][]byte {
	dst := make(map[string][]byte, len(src))
	for k, v := range src {
		dst[k] = append([]byte(nil), v...)
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

func mergeClaims(dst map[string]any, src map[string]any) {
	if len(src) == 0 || dst == nil {
		return
	}
	for k, v := range src {
		if k == "" {
			continue
		}
		dst[k] = v
	}
}

func mergeBinaryClaims(dst map[string][]byte, src map[string][]byte) {
	if len(src) == 0 || dst == nil {
		return
	}
	for k, v := range src {
		if k == "" {
			continue
		}
		dst[k] = append([]byte(nil), v...)
	}
}

func mergeFooter(dst map[string]string, src map[string]string) {
	if len(src) == 0 || dst == nil {
		return
	}
	for k, v := range src {
		if k == "" {
			continue
		}
		dst[k] = v
	}
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

// JWT compatibility types and functions

// MapClaims is a map of string to any, compatible with jwt.MapClaims
// Provides validation helpers for exp, nbf, iat, etc.
type MapClaims map[string]any

// Valid validates time-based claims (exp, nbf, iat)
func (m MapClaims) Valid() error {
	now := time.Now().UTC().Unix()
	if exp, ok := m["exp"]; ok {
		switch v := exp.(type) {
		case float64:
			if now > int64(v) {
				return ErrInvalidToken
			}
		case int64:
			if now > v {
				return ErrInvalidToken
			}
		}
	}
	if nbf, ok := m["nbf"]; ok {
		switch v := nbf.(type) {
		case float64:
			if now < int64(v) {
				return ErrInvalidToken
			}
		case int64:
			if now < v {
				return ErrInvalidToken
			}
		}
	}
	if iat, ok := m["iat"]; ok {
		switch v := iat.(type) {
		case float64:
			if now < int64(v) {
				return ErrInvalidToken
			}
		case int64:
			if now < v {
				return ErrInvalidToken
			}
		}
	}
	return nil
}

// NewWithClaims creates a new token with the specified signing method and claims (JWT compatible)
func NewWithClaims(method SigningMethod, claims MapClaims) *Token {
	t := CreateToken(1*time.Hour, method.Alg()) // Default 1h TTL, override as needed
	for k, v := range claims {
		t.Claims[k] = v
	}
	return t
}

// Parse parses a JWT-like token string and validates its signature (JWT compatible)
func Parse(tokenString string, key any, method SigningMethod) (*Token, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) == 2 {
		// Signed token: payload.signature
		payload, err := DecodeBase64URL(parts[0])
		if err != nil {
			return nil, ErrInvalidToken
		}
		sig, err := DecodeBase64URL(parts[1])
		if err != nil {
			return nil, ErrInvalidToken
		}
		if err := method.Verify(string(payload), sig, key); err != nil {
			return nil, ErrInvalidToken
		}
		t, err := deserializeToken(payload)
		if err != nil {
			return nil, ErrInvalidToken
		}
		return t, nil
	}
	return nil, ErrInvalidToken
}

// ParseWithClaims parses a JWT-like token string, validates its signature, and fills the provided claims (JWT compatible)
func ParseWithClaims(tokenString string, claims MapClaims, key any, method SigningMethod) (*Token, error) {
	t, err := Parse(tokenString, key, method)
	if err != nil {
		return nil, err
	}
	// Copy claims from token to provided claims map
	for k, v := range t.Claims {
		claims[k] = v
	}
	return t, nil
}
