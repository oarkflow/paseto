package token

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

// SigningMethod is compatible with jwt.SigningMethod
// Provides methods for signing and verifying tokens
// Only EdDSA and XC20P supported here

type SigningMethod interface {
	Alg() string
	Sign(signingString string, key any) ([]byte, error)
	Verify(signingString string, sig []byte, key any) error
}

// SigningMethodEdDSA implements EdDSA signing
var SigningMethodEdDSA = &signingMethodEdDSA{}

type signingMethodEdDSA struct{}

func (m *signingMethodEdDSA) Alg() string { return AlgSign }
func (m *signingMethodEdDSA) Sign(signingString string, key any) ([]byte, error) {
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("invalid Ed25519 private key")
	}
	return ed25519.Sign(priv, []byte(signingString)), nil
}
func (m *signingMethodEdDSA) Verify(signingString string, sig []byte, key any) error {
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return errors.New("invalid Ed25519 public key")
	}
	if !ed25519.Verify(pub, []byte(signingString), sig) {
		return ErrInvalidToken
	}
	return nil
}

// SigningMethodXC20P implements symmetric encryption (not JWT standard, but for compatibility)
var SigningMethodXC20P = &signingMethodXC20P{}

type signingMethodXC20P struct{}

func (m *signingMethodXC20P) Alg() string { return AlgEncrypt }
func (m *signingMethodXC20P) Sign(signingString string, key any) ([]byte, error) {
	k, ok := key.([]byte)
	if !ok {
		return nil, errors.New("invalid XC20P key")
	}
	return Encrypt(k, []byte(signingString))
}
func (m *signingMethodXC20P) Verify(signingString string, sig []byte, key any) error {
	k, ok := key.([]byte)
	if !ok {
		return errors.New("invalid XC20P key")
	}
	plaintext, err := Decrypt(k, sig)
	if err != nil {
		return ErrInvalidToken
	}
	if string(plaintext) != signingString {
		return ErrInvalidToken
	}
	return nil
}

// SigningMethodHS256 implements HMAC SHA256 signing (JWT standard)
var SigningMethodHS256 = &signingMethodHS256{}

type signingMethodHS256 struct{}

func (m *signingMethodHS256) Alg() string { return "HS256" }
func (m *signingMethodHS256) Sign(signingString string, key any) ([]byte, error) {
	k, ok := key.([]byte)
	if !ok {
		return nil, errors.New("invalid HS256 key")
	}
	// Use standard HMAC SHA256
	h := hmac.New(sha256.New, k)
	h.Write([]byte(signingString))
	return h.Sum(nil), nil
}
func (m *signingMethodHS256) Verify(signingString string, sig []byte, key any) error {
	k, ok := key.([]byte)
	if !ok {
		return errors.New("invalid HS256 key")
	}
	h := hmac.New(sha256.New, k)
	h.Write([]byte(signingString))
	expected := h.Sum(nil)
	if !hmac.Equal(expected, sig) {
		return ErrInvalidToken
	}
	return nil
}
