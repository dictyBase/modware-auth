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
	assert.NoError(err, "expect no error for jwt encoding")
}

func TestVerify(t *testing.T) {
	assert := assert.New(t)
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
	val, err := ja.Encode(claims)
	assert.NoError(err, "expect no error for jwt encoding")
	_, err = ja.Verify(val)
	assert.NoError(err, "expect no error when verifying valid jwt")

	claimsBadExpiresAt := jwt.StandardClaims{
		Issuer:    "dictyBase",
		Subject:   "dictyBase login token",
		ExpiresAt: time.Now().Unix() - 1000000, // make expired
		IssuedAt:  time.Now().Unix(),
		NotBefore: time.Now().Unix(),
		Id:        xid.New().String(),
		Audience:  "user",
	}
	val2, err := ja.Encode(claimsBadExpiresAt)
	assert.NoError(err, "expect no error for jwt encoding")
	_, err = ja.Verify(val2)
	assert.Error(err, "expect error with expired jwt token")

	claimsBadIssuedAt := jwt.StandardClaims{
		Issuer:    "dictyBase",
		Subject:   "dictyBase login token",
		ExpiresAt: time.Now().Add(time.Hour * 240).Unix(),
		IssuedAt:  time.Now().Unix() + 100000, // set issued time in future
		NotBefore: time.Now().Unix(),
		Id:        xid.New().String(),
		Audience:  "user",
	}
	val3, err := ja.Encode(claimsBadIssuedAt)
	assert.NoError(err, "expect no error for jwt encoding")
	_, err = ja.Verify(val3)
	assert.Error(err, "expect error with bad issued at time")

	claimsBadNotBefore := jwt.StandardClaims{
		Issuer:    "dictyBase",
		Subject:   "dictyBase login token",
		ExpiresAt: time.Now().Add(time.Hour * 240).Unix(),
		IssuedAt:  time.Now().Unix(),
		NotBefore: time.Now().Unix() + 100000, // make token not valid yet
		Id:        xid.New().String(),
		Audience:  "user",
	}
	val4, err := ja.Encode(claimsBadNotBefore)
	assert.NoError(err, "expect no error for jwt encoding")
	_, err = ja.Verify(val4)
	assert.Error(err, "expect error with not valid yet token")

	_, err = ja.Verify("")
	assert.Error(err, "expect error with empty token string")

	ja.signer = jwt.SigningMethodES256
	_, err = ja.Verify(val)
	assert.Error(err, "expect error when signing algorithms are different")

}
