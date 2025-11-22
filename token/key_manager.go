package token

import (
	"crypto/rand"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/oarkflow/shamir"
	"golang.org/x/crypto/chacha20poly1305"
)

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
