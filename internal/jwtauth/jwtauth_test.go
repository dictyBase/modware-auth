package jwtauth

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/rs/xid"
	"github.com/stretchr/testify/assert"
)

// Generate RSA public and private keys in PEM format
func generateKeys() (string, string, error) {
	var prv, pub bytes.Buffer
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return prv.String(), pub.String(), fmt.Errorf("error in generating key %s", err)
	}
	if err := private.Validate(); err != nil {
		return prv.String(), pub.String(), fmt.Errorf("error in validating private key %s", err)
	}
	prvPem := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(private),
	}
	public := private.Public()
	pubCont, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return prv.String(), pub.String(), fmt.Errorf("unable to marshall private key %s", err)
	}
	pubPem := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubCont,
	}
	if err := pem.Encode(&prv, prvPem); err != nil {
		return prv.String(), pub.String(), fmt.Errorf("unable to write private key %s", err)
	}
	if err := pem.Encode(&pub, pubPem); err != nil {
		return prv.String(), pub.String(), fmt.Errorf("unable to write public key %s", err)
	}
	return prv.String(), pub.String(), nil
}

func TestEncode(t *testing.T) {
	private, public, err := generateKeys()
	if err != nil {
		t.Error(err)
	}
	ja := New(jwt.SigningMethodRS512, private, public)
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
