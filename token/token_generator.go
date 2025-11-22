package token

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"
)

// TokenGenerator issues encrypted or signed tokens while reusing pooled Token structs.
type TokenGenerator struct {
	ttl          time.Duration
	nowFn        func() time.Time
	symmetricKey []byte
	signingKey   ed25519.PrivateKey
	keyID        string
	km           *KeyManager
}

// GeneratorOption customizes a TokenGenerator.
type GeneratorOption func(*TokenGenerator)

// WithGeneratorKeyID forces a static key identifier on generated tokens.
func WithGeneratorKeyID(keyID string) GeneratorOption {
	return func(g *TokenGenerator) {
		g.keyID = strings.TrimSpace(keyID)
	}
}

// WithGeneratorNow injects a deterministic clock source (useful for tests).
func WithGeneratorNow(fn func() time.Time) GeneratorOption {
	return func(g *TokenGenerator) {
		if fn != nil {
			g.nowFn = fn
		}
	}
}

func defaultNow() time.Time { return time.Now().UTC() }

func (g *TokenGenerator) applyOptions(opts ...GeneratorOption) {
	for _, opt := range opts {
		if opt != nil {
			opt(g)
		}
	}
	if g.nowFn == nil {
		g.nowFn = defaultNow
	}
}

// NewSymmetricGenerator builds an encrypting generator using a static key.
func NewSymmetricGenerator(key []byte, ttl time.Duration, opts ...GeneratorOption) (*TokenGenerator, error) {
	if err := ValidateKey(key); err != nil {
		return nil, err
	}
	g := &TokenGenerator{
		ttl:          ttl,
		symmetricKey: append([]byte(nil), key...),
	}
	g.applyOptions(opts...)
	return g, nil
}

// NewKeyManagerGenerator encrypts tokens using rotating keys from a KeyManager.
func NewKeyManagerGenerator(km *KeyManager, ttl time.Duration, opts ...GeneratorOption) (*TokenGenerator, error) {
	if km == nil {
		return nil, errors.New("key manager is nil")
	}
	g := &TokenGenerator{ttl: ttl, km: km}
	g.applyOptions(opts...)
	return g, nil
}

// NewSigningGenerator signs tokens with Ed25519 keys.
func NewSigningGenerator(priv ed25519.PrivateKey, ttl time.Duration, opts ...GeneratorOption) (*TokenGenerator, error) {
	if l := len(priv); l != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key size: %d", len(priv))
	}
	g := &TokenGenerator{
		ttl:        ttl,
		signingKey: append(ed25519.PrivateKey(nil), priv...),
	}
	g.applyOptions(opts...)
	return g, nil
}

// Generate produces a fully encoded token string (encrypted or signed).
func (g *TokenGenerator) Generate(claims map[string]any, binaryClaims map[string][]byte, footer map[string]string, ttlOverride ...time.Duration) (string, error) {
	if g == nil {
		return "", errors.New("token generator is nil")
	}
	ttl := g.ttl
	if len(ttlOverride) > 0 && ttlOverride[0] > 0 {
		ttl = ttlOverride[0]
	}
	if ttl <= 0 {
		return "", errors.New("token TTL must be positive")
	}
	alg, kid, keyBytes, err := g.resolveKey()
	if err != nil {
		return "", err
	}
	t := acquireToken()
	defer releaseToken(t)
	now := g.nowFn()
	t.Header[HeaderVersion] = "1"
	t.Header[HeaderAlg] = alg
	if kid != "" {
		t.Header[HeaderKeyID] = kid
	}
	t.ID = generateTokenID()
	t.IssuedAt = now
	t.NotBefore = now
	t.ExpiresAt = now.Add(ttl)
	mergeClaims(t.Claims, claims)
	mergeBinaryClaims(t.BinaryClaims, binaryClaims)
	mergeFooter(t.Footer, footer)
	if alg == AlgEncrypt {
		return g.encryptWithKey(keyBytes, t)
	}
	return g.signToken(t)
}

func (g *TokenGenerator) resolveKey() (string, string, []byte, error) {
	switch {
	case g == nil:
		return "", "", nil, errors.New("token generator is nil")
	case g.signingKey != nil:
		return AlgSign, g.keyID, g.signingKey, nil
	case g.km != nil:
		kid, key := g.km.GetCurrentKey()
		if kid == "" || len(key) == 0 {
			return "", "", nil, errors.New("no active key available")
		}
		return AlgEncrypt, kid, key, nil
	case len(g.symmetricKey) > 0:
		return AlgEncrypt, g.keyID, g.symmetricKey, nil
	default:
		return "", "", nil, errors.New("generator missing key material")
	}
}

func (g *TokenGenerator) encryptWithKey(key []byte, t *Token) (string, error) {
	if err := ValidateKey(key); err != nil {
		return "", err
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

func (g *TokenGenerator) signToken(t *Token) (string, error) {
	sb, err := t.encode()
	if err != nil {
		return "", ErrInvalidToken
	}
	payload := sb.Detach()
	sig := ed25519.Sign(g.signingKey, payload)
	return EncodeBase64URL(payload) + "." + EncodeBase64URL(sig), nil
}

// TokenVerifier rapidly validates encrypted or signed tokens.
type TokenVerifier struct {
	symmetricKey []byte
	publicKey    ed25519.PublicKey
	km           *KeyManager
}

// NewSymmetricVerifier verifies XC20P tokens with a static key.
func NewSymmetricVerifier(key []byte) (*TokenVerifier, error) {
	if err := ValidateKey(key); err != nil {
		return nil, err
	}
	return &TokenVerifier{symmetricKey: append([]byte(nil), key...)}, nil
}

// NewKeyManagerVerifier resolves keys through a shared KeyManager.
func NewKeyManagerVerifier(km *KeyManager) (*TokenVerifier, error) {
	if km == nil {
		return nil, errors.New("key manager is nil")
	}
	return &TokenVerifier{km: km}, nil
}

// NewSigningVerifier verifies Ed25519 signed tokens.
func NewSigningVerifier(pub ed25519.PublicKey) (*TokenVerifier, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key size: %d", len(pub))
	}
	return &TokenVerifier{publicKey: append(ed25519.PublicKey(nil), pub...)}, nil
}

// Verify checks the supplied encoded token and returns its parsed representation.
func (v *TokenVerifier) Verify(encoded string) (*Token, error) {
	switch {
	case v == nil:
		return nil, errors.New("token verifier is nil")
	case v.km != nil:
		return DecryptWithKM(v.km, encoded)
	case len(v.symmetricKey) > 0:
		return DecryptToken(encoded, v.symmetricKey)
	case len(v.publicKey) > 0:
		st, err := DecodeSignedToken(encoded)
		if err != nil {
			return nil, ErrInvalidToken
		}
		return VerifyToken(st, v.publicKey)
	default:
		return nil, errors.New("verifier missing key material")
	}
}
