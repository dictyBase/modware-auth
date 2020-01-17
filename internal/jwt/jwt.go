package jwt

import (
	jwtauth "github.com/dgrijalva/jwt-go"
)

type JWTAuth struct {
	signKey   interface{}
	verifyKey interface{}
	signer    jwtauth.SigningMethod
	parser    *jwtauth.Parser
}

// New creates a JWTAuth authenticator instance that provides middleware handlers
// and encoding/decoding functions for JWT signing.
func New(alg string, signKey interface{}, verifyKey interface{}) *JWTAuth {
	return &JWTAuth{
		signKey:   signKey,
		verifyKey: verifyKey,
		signer:    jwtauth.GetSigningMethod(alg),
		parser:    &jwtauth.Parser{},
	}
}

// Verify verifies if a JWT string is currently valid.
func Verify(ja *JWTAuth, tokenString string) (*jwtauth.Token, error) {
	tkn := &jwtauth.Token{}

	return tkn, nil
}

// Encode encodes the claims of a JWT and returns both a jwt struct and token string.
func (ja *JWTAuth) Encode(claims jwtauth.Claims) (t *jwtauth.Token, tokenString, err error) {
	return
}

// Decode decodes a JWT string and returns it as a jwt struct.
func (ja *JWTAuth) Decode(tokenString string) (t *jwtauth.Token, err error) {
	return
}
