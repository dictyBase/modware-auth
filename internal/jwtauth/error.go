package jwtauth

import (
	"errors"

	"github.com/golang-jwt/jwt"
)

var (
	ErrUnauthorized     = errors.New("jwtauth: token is unauthorized")
	ErrExpired          = errors.New("jwtauth: token is expired")
	ErrNBFInvalid       = errors.New("jwtauth: token nbf validation failed")
	ErrIATInvalid       = errors.New("jwtauth: token iat validation failed")
	ErrNoTokenFound     = errors.New("jwtauth: no token found")
	ErrAlgoInvalid      = errors.New("jwtauth: algorithm mismatch")
	ErrInvalidSignature = errors.New("jwtauth: invalid signature")
)

func isValidationNotValidYet(err *jwt.ValidationError) bool {
	return err.Errors == jwt.ValidationErrorNotValidYet
}

func isValidationIssuedAt(err *jwt.ValidationError) bool {
	return err.Errors == jwt.ValidationErrorIssuedAt
}

func isValidationExpired(err *jwt.ValidationError) bool {
	return err.Errors == jwt.ValidationErrorExpired
}

func isInvalidSignature(err *jwt.ValidationError) bool {
	return err.Errors == jwt.ValidationErrorSignatureInvalid
}
