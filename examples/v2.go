// example/main.go
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"
	"time"

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

	// Create a refresh token with custom TTL
	rt := token.CreateRefreshToken(24 * time.Hour)
	_ = token.RegisterClaim(rt, "user_id", "42")

	encryptedRT, err := token.EncryptToken(rt, key)
	if err != nil {
		log.Fatal("refresh encrypt failed:", err)
	}
	fmt.Println("Encrypted Refresh Token:", encryptedRT)

	// Simulate using the refresh token to issue a new access token
	newAccess, err := token.RefreshToken(encryptedRT, key, 15*time.Minute)
	if err != nil {
		log.Fatal("refresh failed:", err)
	}
	fmt.Println("New Access Token:", newAccess)

	// Decrypt the new access token and inspect claims
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

	// Create a token and encrypt it
	t := token.CreateToken(5*time.Minute, token.AlgEncrypt)
	_ = token.RegisterClaim(t, "user", "bob")

	encrypted, err := token.EncryptToken(t, key)
	if err != nil {
		log.Fatal("encrypt failed:", err)
	}
	fmt.Println("Token before revocation:", encrypted)

	// Revoke by ID
	_ = token.RevokeID(t.ID, t.ExpiresAt)

	// Attempt to decrypt after revocation
	_, err = token.DecryptToken(encrypted, key)
	if err != nil {
		fmt.Println("Revocation succeeded, token invalid:", err)
	} else {
		fmt.Println("Revocation failed, token should be invalid")
	}
	fmt.Println()
}

// revokeByStringTest demonstrates revoking directly by the encrypted string.
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

// checkRevokedStringTest demonstrates checking if a token string is revoked.
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

	// Revoke by ID directly
	_ = token.RevokeID(t.ID, t.ExpiresAt)
	revoked, err = token.IsRevokedToken(encrypted, key)
	if err != nil {
		log.Fatal("IsRevokedToken failed after RevokeID:", err)
	}
	fmt.Println("Revoked after RevokeID?", revoked)

	// Also test revocation via string:
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
