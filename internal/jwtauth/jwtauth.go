package jwtauth

import (
	jwt "github.com/dgrijalva/jwt-go"
)

type JWTAuth struct {
	signKey   interface{}
	verifyKey interface{}
	signer    jwt.SigningMethod
	parser    *jwt.Parser
}

// New creates a JWTAuth authenticator instance that provides middleware handlers
// and encoding/decoding functions for JWT signing.
func New(alg string, signKey interface{}, verifyKey interface{}) *JWTAuth {
	return &JWTAuth{
		signKey:   signKey,
		verifyKey: verifyKey,
		signer:    jwt.GetSigningMethod(alg),
		parser:    &jwt.Parser{},
	}
}

// Verify checks if a JWT string is currently valid.
func Verify(ja *JWTAuth, tokenString string) (*jwt.Token, error) {
	token, err := ja.Decode(tokenString)
	if err != nil {
		verr, ok := err.(*jwt.ValidationError)
		switch ok {
		case isValidationExpired(verr):
			return token, ErrExpired
		case isValidationIssuedAt(verr):
			return token, ErrIATInvalid
		case isValidationNotValidYet(verr):
			return token, ErrNBFInvalid
		default:
			return token, err
		}
	}

	if token == nil || !token.Valid {
		return token, ErrUnauthorized
	}

	// Verify signing algorithm
	if token.Method != ja.signer {
		return token, ErrAlgoInvalid
	}

	// Valid!
	return token, nil
}

func (ja *JWTAuth) Encode(claims jwt.Claims) (*jwt.Token, string, error) {
	tkn := jwt.New(ja.signer)
	tkn.Claims = claims
	tokenString, err := tkn.SignedString(ja.signKey)
	tkn.Raw = tokenString
	return tkn, tokenString, err
}

func (ja *JWTAuth) Decode(tokenString string) (*jwt.Token, error) {
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
