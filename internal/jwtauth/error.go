package jwtauth

import (
	"errors"

	jwt "github.com/dgrijalva/jwt-go"
)

var (
	ErrUnauthorized = errors.New("jwtauth: token is unauthorized")
	ErrExpired      = errors.New("jwtauth: token is expired")
	ErrNBFInvalid   = errors.New("jwtauth: token nbf validation failed")
	ErrIATInvalid   = errors.New("jwtauth: token iat validation failed")
	ErrNoTokenFound = errors.New("jwtauth: no token found")
	ErrAlgoInvalid  = errors.New("jwtauth: algorithm mismatch")
)

func isValidationNotValidYet(err *jwt.ValidationError) bool {
	if err.Errors == jwt.ValidationErrorNotValidYet {
		return true
	}
	return false
}

func isValidationIssuedAt(err *jwt.ValidationError) bool {
	if err.Errors == jwt.ValidationErrorIssuedAt {
		return true
	}
	return false
}

func isValidationExpired(err *jwt.ValidationError) bool {
	if err.Errors == jwt.ValidationErrorExpired {
		return true
	}
	return false
}
