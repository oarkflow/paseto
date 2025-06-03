package main

import (
	"fmt"
	"time"

	"github.com/oarkflow/paseto"
)

func main() {
	start := time.Now()
	secret := "OdR4DlWhZk6osDd0qXLdVT88lHOvj14K"
	v4 := paseto.NewPV4Local()
	key, err := paseto.NewSymmetricKey([]byte(secret), paseto.Version4)
	if err != nil {
		panic(err)
	}
	encrypted, err := v4.Encrypt(key, &paseto.RegisteredClaims{
		Issuer:     "oarkflow.com",
		Subject:    "test",
		Audience:   "auth.oarkflow.com",
		Expiration: paseto.TimePtr(time.Now().Add(time.Minute)),
		NotBefore:  paseto.TimePtr(time.Now()),
		IssuedAt:   paseto.TimePtr(time.Now()),
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(encrypted)
	decrypted := v4.Decrypt(encrypted, key)
	if decrypted.Err() != nil {
		panic(decrypted.Err())
	}
	fmt.Println("Since, elapsed:", time.Since(start))
	var claim paseto.RegisteredClaims
	err = decrypted.ScanClaims(&claim)
	if err != nil {
		panic(err)
	}
	fmt.Println(claim, claim.TokenID)
}
