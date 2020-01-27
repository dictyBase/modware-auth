package service

import (
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/rs/xid"
)

type RefreshTokenClaims struct {
	// identity is used as an identifier for a user's identity data
	// (it is an ID for orcid, an email for others)
	identity string
	// provider is the login provider
	provider string
	// Standard JWT claims
	jwt.StandardClaims
}

func generateStandardClaims(expirationMinutes time.Duration) jwt.StandardClaims {
	return jwt.StandardClaims{
		Issuer:    "dictyBase",
		Subject:   "dictyBase login token",
		ExpiresAt: time.Now().Add(time.Minute * expirationMinutes).Unix(),
		IssuedAt:  time.Now().Unix(),
		NotBefore: time.Now().Unix(),
		Id:        xid.New().String(),
		Audience:  "user",
	}
}

func generateRefreshTokenClaims(identity string, provider string) RefreshTokenClaims {
	return RefreshTokenClaims{
		identity,
		provider,
		generateStandardClaims(refreshTokenExpirationTimeInMins),
	}
}
