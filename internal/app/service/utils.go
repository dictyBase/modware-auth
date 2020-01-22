package service

import (
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/rs/xid"
)

type RefreshTokenClaims struct {
	email string
	jwt.StandardClaims
}

func generateStandardClaims(expirationHours time.Duration) jwt.StandardClaims {
	return jwt.StandardClaims{
		Issuer:    "dictyBase",
		Subject:   "dictyBase login token",
		ExpiresAt: time.Now().Add(time.Hour * expirationHours).Unix(),
		IssuedAt:  time.Now().Unix(),
		NotBefore: time.Now().Unix(),
		Id:        xid.New().String(),
		Audience:  "user",
	}
}

func generateRefreshTokenClaims(email string) RefreshTokenClaims {
	return RefreshTokenClaims{
		email,
		generateStandardClaims(refreshTokenExpirationTimeInHours),
	}
}
