package jwtauth

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/rs/xid"
	"github.com/stretchr/testify/assert"
)

// Generate RSA public and private keys in PEM format
func generateKeys() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return private, new(rsa.PublicKey), fmt.Errorf("error in generating key %s", err)
	}
	if err := private.Validate(); err != nil {
		return private, new(rsa.PublicKey), fmt.Errorf("error in validating private key %s", err)
	}
	public := private.Public()
	rsaPub, ok := public.(*rsa.PublicKey)
	if !ok {
		return private, new(rsa.PublicKey), fmt.Errorf("unable to convert to rsa public key")
	}
	return private, rsaPub, nil
}

func TestEncode(t *testing.T) {
	private, public, err := generateKeys()
	if err != nil {
		t.Error(err)
	}
	ja := NewJwtAuth(jwt.SigningMethodRS512, private, public)
	claims := jwt.StandardClaims{
		Issuer:    "dictyBase",
		Subject:   "dictyBase login token",
		ExpiresAt: time.Now().Add(time.Hour * 240).Unix(),
		IssuedAt:  time.Now().Unix(),
		NotBefore: time.Now().Unix(),
		Id:        xid.New().String(),
		Audience:  "user",
	}
	_, err = ja.Encode(claims)
	assert := assert.New(t)
	assert.NoError(err, "expect to no error for jwt encoding")
}
