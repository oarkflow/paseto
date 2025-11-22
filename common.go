package paseto

import (
	"errors"
)

// ErrWrongKey occurred when the given key is not intended for a specified version of PASETO.
var ErrWrongKey = errors.New("the given key is not intended for this version of PASETO")

type purpose string

const (
	purposeLocal purpose = "local"

	purposePublic purpose = "public"
)

// Version denotes a PASETO version which will be used.
type Version int32

const (
	Version2           Version = 2
	Version3           Version = 3
	Version4           Version = 4
	SymmetricKeyLength         = 32
)

// key abstracts raw key material for extra safety.
type key struct {
	keyMaterial []byte
	version     Version
}

// SymKey is a symmetric key abstraction for usage inside PASETO.
type SymKey struct {
	key
}

// AsymSecretKey is an asymmetric key abstraction for usage inside PASETO on sign.
type AsymSecretKey struct {
	key
}

// AsymPublicKey is an asymmetric key abstraction for usage inside PASETO on verify.
type AsymPublicKey struct {
	key
}

func (k *AsymPublicKey) isValidFor(v Version, p purpose) bool {
	return k.version == v && p == purposePublic
}

// NewAsymmetricPublicKey is a constructor-like function for AsymPublicKey which is a wrapper for raw key material used inside PASETO.
func NewAsymmetricPublicKey(keyMaterial []byte, version Version) *AsymPublicKey {
	return &AsymPublicKey{key: key{keyMaterial: keyMaterial, version: version}}
}

// NewAsymmetricSecretKey is a constructor-like function for AsymSecretKey which is a wrapper for raw key material used inside PASETO.
func NewAsymmetricSecretKey(keyMaterial []byte, version Version) *AsymSecretKey {
	return &AsymSecretKey{key{keyMaterial: keyMaterial, version: version}}
}

// NewSymmetricKey is a constructor-like function for SymKey which is a wrapper for raw key material used inside PASETO
func NewSymmetricKey(keyMaterial []byte, version Version) (*SymKey, error) {
	if len(keyMaterial) != SymmetricKeyLength {
		return nil, errors.New("invalid key length")
	}
	return &SymKey{key: key{keyMaterial: keyMaterial, version: version}}, nil
}

func (k *AsymSecretKey) isValidFor(v Version, p purpose) bool {
	return k.version == v && p == purposePublic
}

func (k *SymKey) isValidFor(v Version, p purpose) bool {
	return k.version == v && p == purposeLocal
}

// optional includes optional arguments which is non-mandatory to PASETO.
type optional struct {
	footer    any
	assertion []byte
}

// ProvidedOption is the type of constructor options.
type ProvidedOption func(*optional) error

// WithFooter adds PASETO footer to the token.
func WithFooter(footer any) ProvidedOption {
	return func(o *optional) error {
		if footer == nil {
			return errors.New("nil footer was passed to WithFooter function")
		}
		o.footer = footer
		return nil
	}
}

// WithAssert adds implicit assertion to PASETO token
// Implicit assertion is unencrypted but authenticated data.
func WithAssert(assertion []byte) ProvidedOption {
	return func(o *optional) error {
		if assertion == nil {
			return errors.New("nil assertion was passed to WithAssert function")
		}
		o.assertion = assertion
		return nil
	}
}

// ErrMalformedToken indicates that obtained token was not properly formed
var ErrMalformedToken = errors.New("token is malformed")

// ErrInvalidSignature is returned when signature in invalid for provided message.
var ErrInvalidSignature = errors.New("invalid token signature")

// SymmetricKey is used in encryption and decryption routines.
type SymmetricKey []byte

var headerPurposePublic = "public"
