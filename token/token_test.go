// benchmark_test.go
package token_test

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/oarkflow/paseto"
	"github.com/oarkflow/paseto/token"
)

var (
	ourKey     []byte
	pasetoKey  *paseto.SymKey
	pasetoV4   = paseto.NewPV4Local()
	ourToken   *token.Token
	pasetoOpts paseto.RegisteredClaims
)

func init() {
	// Initialize a 32-byte symmetric key for our token implementation
	ourKey = make([]byte, 32)
	_, _ = rand.Read(ourKey)

	secret := "OdR4DlWhZk6osDd0qXLdVT88lHOvj14K"
	key, _ := paseto.NewSymmetricKey([]byte(secret), paseto.Version4)
	pasetoKey = key

	// Prepare a sample Token for our implementation
	ourToken = token.CreateToken(time.Minute, token.AlgEncrypt)
	_ = token.RegisterClaim(ourToken, "user_id", "42")
	_ = token.RegisterFooter(ourToken, "aud", "internal")

	// Prepare RegisteredClaims for PASETO
	now := time.Now()
	pasetoOpts = paseto.RegisteredClaims{
		Issuer:     "oarkflow.com",
		Subject:    "test",
		Audience:   "auth.oarkflow.com",
		Expiration: paseto.TimePtr(now.Add(time.Minute)),
		NotBefore:  paseto.TimePtr(now),
		IssuedAt:   paseto.TimePtr(now),
		TokenID:    "benchmark",
	}
}

func BenchmarkOurEncrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := token.EncryptToken(ourToken, ourKey)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOurDecrypt(b *testing.B) {
	encrypted, _ := token.EncryptToken(ourToken, ourKey)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := token.DecryptToken(encrypted, ourKey)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPasetoEncrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := pasetoV4.Encrypt(pasetoKey, &pasetoOpts)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPasetoDecrypt(b *testing.B) {
	encrypted, _ := pasetoV4.Encrypt(pasetoKey, &pasetoOpts)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decrypted := pasetoV4.Decrypt(encrypted, pasetoKey)
		if decrypted.Err() != nil {
			b.Fatal(decrypted.Err())
		}
	}
}
