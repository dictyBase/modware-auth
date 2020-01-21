package jwtauth

import (
	"crypto/rsa"

	jwt "github.com/dgrijalva/jwt-go"
)

// JWTAuth is a container for jwt authenticator manager
type JWTAuth struct {
	signKey   *rsa.PrivateKey
	verifyKey *rsa.PublicKey
	parser    *jwt.Parser
	signer    jwt.SigningMethod
}

// NewJwtAuth creates a JWTAuth authenticator instance
func NewJwtAuth(alg jwt.SigningMethod, signKey *rsa.PrivateKey, verifyKey *rsa.PublicKey) *JWTAuth {
	return &JWTAuth{
		signKey:   signKey,
		verifyKey: verifyKey,
		signer:    alg,
		parser:    &jwt.Parser{},
	}
}

// Verify a JWT string and returns a token object
func (ja *JWTAuth) Verify(tokenString string) (*jwt.Token, error) {
	token, err := ja.decode(tokenString)
	if err != nil {
		verr, ok := err.(*jwt.ValidationError)
		switch ok {
		case isValidationExpired(verr):
			return token, ErrExpired
		case isValidationIssuedAt(verr):
			return token, ErrIATInvalid
		case isValidationNotValidYet(verr):
			return token, ErrNBFInvalid
		case isInvalidSignature(verr):
			return token, ErrInvalidSignature
		default:
			return token, err
		}
	}
	if token == nil || !token.Valid {
		return token, ErrUnauthorized
	}
	if token.Method != ja.signer {
		return token, ErrAlgoInvalid
	}
	return token, nil
}

// Encode generate the signed jwt
func (ja *JWTAuth) Encode(claims jwt.Claims) (string, error) {
	tkn := jwt.New(ja.signer)
	tkn.Claims = claims
	return tkn.SignedString(ja.signKey)
}

func (ja *JWTAuth) decode(tokenString string) (*jwt.Token, error) {
	tkn, err := ja.parser.Parse(tokenString, ja.keyFunc)
	if err != nil {
		return nil, err
	}
	return tkn, nil
}

func (ja *JWTAuth) keyFunc(t *jwt.Token) (interface{}, error) {
	if ja.verifyKey != nil {
		return ja.verifyKey, nil
	} else {
		return ja.signKey, nil
	}
}
