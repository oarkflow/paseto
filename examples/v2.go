// example/main.go
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"
	"time"

	"github.com/oarkflow/shamir"

	"github.com/oarkflow/paseto/token"
)

func main() {
	start := time.Now()
	symmetricTest()
	fmt.Println("Elapsed:", time.Since(start))

	asymmetricTest()
	claimOperationsTest()
	deterministicVectorTest()
	refreshTokenTest()
	revocationTest()
	revokeByStringTest()
	checkRevokedStringTest()

	// New examples for Shamir Secret Sharing and rotating secret keys:
	shamirSSSTest()
	rotateSecretWithKMTest()
}

func symmetricTest() {
	fmt.Println("=== Symmetric Encryption Test ===")
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	t := token.CreateToken(10*time.Minute, token.AlgEncrypt)
	_ = token.RegisterClaim(t, "u", "42")

	encrypted, err := token.EncryptToken(t, key)
	if err != nil {
		log.Fatal("encrypt failed:", err)
	}
	fmt.Println("Encrypted Token:", encrypted)

	decrypted, err := token.DecryptToken(encrypted, key)
	if err != nil {
		log.Fatal("decrypt failed:", err)
	}
	fmt.Println("Decrypted Claim:", decrypted.Claims)
	fmt.Println()
}

func asymmetricTest() {
	fmt.Println("=== Asymmetric Signing Test ===")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal("keygen failed:", err)
	}

	t := token.CreateToken(1*time.Hour, token.AlgSign, "key-123")
	_ = token.RegisterClaim(t, "role", "admin")
	_ = token.RegisterFooter(t, "kid", "key-123")

	signed, err := token.SignToken(t, priv, "key-123")
	if err != nil {
		log.Fatal("signing failed:", err)
	}

	encoded := token.EncodeSignedToken(signed)
	fmt.Println("Signed Token:", encoded)

	decoded, err := token.DecodeSignedToken(encoded)
	if err != nil {
		log.Fatal("decode failed:", err)
	}
	verified, err := token.VerifyToken(decoded, pub)
	if err != nil {
		log.Fatal("verify failed:", err)
	}
	fmt.Println("Verified Claim role:", verified.Claims["role"])
	fmt.Println("Footer kid:", verified.Footer["kid"])
	fmt.Println()
}

func claimOperationsTest() {
	fmt.Println("=== Claim Operations Test ===")
	t := token.CreateToken(30*time.Minute, token.AlgEncrypt)
	_ = token.RegisterClaim(t, "email", "alice@example.com")
	_ = token.RegisterClaim(t, "scope", "read:all")
	_ = token.RegisterFooter(t, "purpose", "test")

	token.ScanClaims(t, func(k string, v any) bool {
		fmt.Printf("Claim: %s = %v\n", k, v)
		return true
	})

	fmt.Println("Blacklisted?", token.IsBlacklisted(t))
	fmt.Println()
}

func deterministicVectorTest() {
	fmt.Println("=== Deterministic Token Vector Test ===")
	now := time.Unix(1700000000, 0)
	claims := map[string]any{"id": "abc123"}
	footer := map[string]string{"aud": "service"}

	t := token.DeterministicToken(now, claims, footer, 10*time.Minute)
	fmt.Println("Header:", t.Header)
	fmt.Println("Issued:", t.IssuedAt.UTC())
	fmt.Println("NotBefore:", t.NotBefore.UTC())
	fmt.Println("Expires:", t.ExpiresAt.UTC())
	fmt.Println("Claims:", t.Claims)
	fmt.Println("Footer:", t.Footer)
	fmt.Println()
}

func refreshTokenTest() {
	fmt.Println("=== Refresh Token Test ===")
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	rt := token.CreateRefreshToken(24 * time.Hour)
	_ = token.RegisterClaim(rt, "user_id", "42")

	encryptedRT, err := token.EncryptToken(rt, key)
	if err != nil {
		log.Fatal("refresh encrypt failed:", err)
	}
	fmt.Println("Encrypted Refresh Token:", encryptedRT)

	newAccess, err := token.RefreshToken(encryptedRT, key, 15*time.Minute)
	if err != nil {
		log.Fatal("refresh failed:", err)
	}
	fmt.Println("New Access Token:", newAccess)

	decryptedAccess, err := token.DecryptToken(newAccess, key)
	if err != nil {
		log.Fatal("decrypt new access failed:", err)
	}
	fmt.Println("Decrypted New Claim user_id:", decryptedAccess.Claims["user_id"])
	fmt.Println()
}

func revocationTest() {
	fmt.Println("=== Revocation Test ===")
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	t := token.CreateToken(5*time.Minute, token.AlgEncrypt)
	_ = token.RegisterClaim(t, "user", "bob")

	encrypted, err := token.EncryptToken(t, key)
	if err != nil {
		log.Fatal("encrypt failed:", err)
	}
	fmt.Println("Token before revocation:", encrypted)

	_ = token.RevokeID(t.ID, t.ExpiresAt)

	_, err = token.DecryptToken(encrypted, key)
	if err != nil {
		fmt.Println("Revocation succeeded, token invalid:", err)
	} else {
		fmt.Println("Revocation failed, token should be invalid")
	}
	fmt.Println()
}

func revokeByStringTest() {
	fmt.Println("=== Revoke By String Test ===")
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	t := token.CreateToken(5*time.Minute, token.AlgEncrypt)
	_ = token.RegisterClaim(t, "user", "charlie")

	encrypted, err := token.EncryptToken(t, key)
	if err != nil {
		log.Fatal("encrypt failed:", err)
	}
	fmt.Println("Token before RevokeToken:", encrypted)

	err = token.RevokeToken(encrypted, key)
	if err != nil {
		log.Fatal("RevokeToken failed:", err)
	}
	fmt.Println("RevokeToken succeeded")

	_, err = token.DecryptToken(encrypted, key)
	if err != nil {
		fmt.Println("Decrypt after RevokeToken invalid as expected:", err)
	} else {
		fmt.Println("Decrypt unexpectedly succeeded after RevokeToken")
	}
	fmt.Println()
}

func checkRevokedStringTest() {
	fmt.Println("=== IsRevokedToken Test ===")
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	t := token.CreateToken(5*time.Minute, token.AlgEncrypt)
	_ = token.RegisterClaim(t, "user", "dave")

	encrypted, err := token.EncryptToken(t, key)
	if err != nil {
		log.Fatal("encrypt failed:", err)
	}
	fmt.Println("Token before any revocation:", encrypted)

	revoked, err := token.IsRevokedToken(encrypted, key)
	if err != nil {
		log.Fatal("IsRevokedToken failed:", err)
	}
	fmt.Println("Initially revoked?", revoked)

	_ = token.RevokeID(t.ID, t.ExpiresAt)
	revoked, err = token.IsRevokedToken(encrypted, key)
	if err != nil {
		log.Fatal("IsRevokedToken failed after RevokeID:", err)
	}
	fmt.Println("Revoked after RevokeID?", revoked)

	t2 := token.CreateToken(5*time.Minute, token.AlgEncrypt)
	_ = token.RegisterClaim(t2, "user", "eve")
	encrypted2, _ := token.EncryptToken(t2, key)

	revoked2, _ := token.IsRevokedToken(encrypted2, key)
	fmt.Println("Token2 initially revoked?", revoked2)

	err = token.RevokeToken(encrypted2, key)
	if err != nil {
		log.Fatal("RevokeToken failed on Token2:", err)
	}
	revoked2, err = token.IsRevokedToken(encrypted2, key)
	if err != nil {
		log.Fatal("IsRevokedToken failed on Token2 after RevokeToken:", err)
	}
	fmt.Println("Token2 revoked after RevokeToken?", revoked2)
	fmt.Println()
}

// shamirSSSTest demonstrates splitting a 32-byte master key into shares,
// reconstructing it from any threshold subset, and using it to encrypt/decrypt.
func shamirSSSTest() {
	fmt.Println("=== Shamir Secret Sharing Test ===")

	// 1) Generate a 32-byte master key.
	masterKey := make([]byte, 32)
	_, _ = rand.Read(masterKey)
	fmt.Printf("Master Key: %x\n", masterKey)

	// 2) Split into N=5 shares with threshold M=3.
	threshold, totalShares := 3, 5
	shares, err := shamir.Split(masterKey, threshold, totalShares)
	if err != nil {
		log.Fatal("shamir.Split failed:", err)
	}
	fmt.Println("Shares:")
	for i, share := range shares {
		fmt.Printf("  Share %d: %x\n", i+1, share)
	}
	fmt.Println()

	// 3) Reconstruct from any 3 shares (e.g., shares[0], shares[2], shares[4]).
	comb := [][]byte{shares[0], shares[2], shares[4]}
	recovered, err := shamir.Combine(comb)
	if err != nil {
		log.Fatal("shamir.Combine failed:", err)
	}
	fmt.Printf("Reconstructed Key: %x\n", recovered)
	fmt.Println()

	// 4) Verify that recovered == masterKey.
	if !compare(masterKey, recovered) {
		log.Fatal("Recovered key does not match master key")
	}
	fmt.Println("Shamir reconstruction succeeded!")

	// 5) Use recovered as encryption key to encrypt a token.
	t := token.CreateToken(10*time.Minute, token.AlgEncrypt)
	_ = token.RegisterClaim(t, "user_id", "1001")

	encrypted, err := token.EncryptToken(t, recovered)
	if err != nil {
		log.Fatal("encrypt failed:", err)
	}
	fmt.Println("Encrypted with recovered key:", encrypted)

	// 6) Decrypt with recovered key.
	decrypted, err := token.DecryptToken(encrypted, recovered)
	if err != nil {
		log.Fatal("decrypt failed:", err)
	}
	fmt.Println("Decrypted Claim:", decrypted.Claims)
	fmt.Println()
}

// rotateSecretWithKMTest demonstrates rotating keys via KeyManager, and using DecryptWithKM
// so that tokens encrypted under "old" and "new" keys remain valid until expiry.
func rotateSecretWithKMTest() {
	fmt.Println("=== Rotate Secret Key with KeyManager Test ===")

	// 1) Create a KeyManager that rotates every 10 seconds, keeps up to 2 old keys,
	//    and uses N=5 total shares with threshold M=3.
	km, err := token.NewKeyManager(10*time.Second, 2, 3, 5)
	if err != nil {
		log.Fatal("NewKeyManager failed:", err)
	}

	// 2) Obtain current (initial) key from KeyManager.
	initialKeyID, initialKey := km.GetCurrentKey()
	fmt.Printf("Initial KeyID: %s, Key: %x\n", initialKeyID, initialKey)

	// 3) Encrypt a token using KeyManager helper (EncryptWithKM) so header["kid"]=initialKeyID.
	t := token.CreateToken(1*time.Minute, token.AlgEncrypt)
	_ = token.RegisterClaim(t, "session", "abc123")

	encrypted, err := token.EncryptWithKM(km, t)
	if err != nil {
		log.Fatal("EncryptWithKM failed:", err)
	}
	fmt.Printf("Token encrypted under KeyID %s: %s\n", initialKeyID, encrypted)

	// 4) Decrypt immediately via KeyManager (DecryptWithKM).
	decrypted, err := token.DecryptWithKM(km, encrypted)
	if err != nil {
		log.Fatal("DecryptWithKM failed:", err)
	}
	fmt.Println("Decrypted payload with initial key:", decrypted.Claims)

	// 5) Wait for rotation (sleep > rotationPeriod). This forces KeyManager to generate a new key.
	time.Sleep(11 * time.Second)

	// 6) Get new current key from KeyManager.
	newKeyID, newKey := km.GetCurrentKey()
	fmt.Printf("New KeyID: %s, Key: %x\n", newKeyID, newKey)

	// 7) Encrypt a fresh token under the new key.
	t2 := token.CreateToken(1*time.Minute, token.AlgEncrypt)
	_ = token.RegisterClaim(t2, "session", "def456")

	encrypted2, err := token.EncryptWithKM(km, t2)
	if err != nil {
		log.Fatal("EncryptWithKM for new token failed:", err)
	}
	fmt.Printf("New token encrypted under KeyID %s: %s\n", newKeyID, encrypted2)

	// 8) Decrypt the first (old) token using DecryptWithKM; KeyManager will try both oldKeyID and newKeyID.
	decryptedOldAgain, err := token.DecryptWithKM(km, encrypted)
	if err != nil {
		log.Fatal("Old token no longer decryptable by DecryptWithKM:", err)
	}
	fmt.Println("Old token still decrypts via DecryptWithKM:", decryptedOldAgain.Claims)

	// 9) Decrypt the new token with DecryptWithKM (should pick up newKeyID).
	decryptedNew, err := token.DecryptWithKM(km, encrypted2)
	if err != nil {
		log.Fatal("New token not decryptable by DecryptWithKM:", err)
	}
	fmt.Println("New token decrypts via DecryptWithKM:", decryptedNew.Claims)

	fmt.Println()
}

// compare returns true if two byte slices are equal.
func compare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
