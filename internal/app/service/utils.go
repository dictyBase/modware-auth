package service

import (
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/rs/xid"
)

type RefreshTokenClaims struct {
	email string `json:"email"`
	jwt.StandardClaims
}

func generateJWTClaims() jwt.StandardClaims {
	return jwt.StandardClaims{
		Issuer:    "dictyBase",
		Subject:   "dictyBase login token",
		ExpiresAt: time.Now().Add(time.Hour * jwtExpirationTimeInHours).Unix(),
		IssuedAt:  time.Now().Unix(),
		NotBefore: time.Now().Unix(),
		Id:        xid.New().String(),
		Audience:  "user",
	}
}

func generateRefreshTokenClaims(email string) RefreshTokenClaims {
	return RefreshTokenClaims{
		email,
		jwt.StandardClaims{
			Issuer:    "dictyBase",
			Subject:   "dictyBase login token",
			ExpiresAt: time.Now().Add(time.Hour * refreshTokenExpirationTimeInHours).Unix(),
			IssuedAt:  time.Now().Unix(),
			NotBefore: time.Now().Unix(),
			Id:        xid.New().String(),
			Audience:  "user",
		},
	}
}
