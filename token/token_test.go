// benchmark_test.go
package token_test

import (
	"bytes"
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
	_ = ourToken.RegisterClaim("user_id", "42")
	_ = ourToken.RegisterFooter("aud", "internal")

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

func TestRegisterByteRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to seed key: %v", err)
	}
	raw := []byte("opaque-payload")
	tok := token.CreateToken(time.Minute, token.AlgEncrypt)
	if err := tok.RegisterByte(raw); err != nil {
		t.Fatalf("RegisterByte failed: %v", err)
	}
	encoded, err := token.EncryptToken(tok, key)
	if err != nil {
		t.Fatalf("EncryptToken failed: %v", err)
	}
	decoded, err := token.DecryptToken(encoded, key)
	if err != nil {
		t.Fatalf("DecryptToken failed: %v", err)
	}
	if !bytes.Equal(decoded.RawClaim, raw) {
		t.Fatalf("raw claim mismatch: got %q", decoded.RawClaim)
	}
}
