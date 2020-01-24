package service

import (
	"context"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/dictyBase/aphgrpc"
	"github.com/dictyBase/go-genproto/dictybaseapis/auth"
	"github.com/dictyBase/modware-auth/internal/jwtauth"
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

type GenerateTokens struct {
	ctx      context.Context
	identity string
	provider string
	j        jwtauth.JWTAuth
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

func generateBothTokens(gt *GenerateTokens) (*auth.Token, error) {
	tkn := &auth.Token{}
	// generate new claims
	jwtClaims := generateStandardClaims(jwtExpirationTimeInMins)
	refTknClaims := generateRefreshTokenClaims(gt.identity, gt.provider)
	// generate new JWT and refresh token to send back
	tknStr, err := gt.j.Encode(jwtClaims)
	if err != nil {
		return tkn, aphgrpc.HandleError(gt.ctx, err)
	}
	tkn.Token = tknStr
	refTknStr, err := gt.j.Encode(refTknClaims)
	if err != nil {
		return tkn, aphgrpc.HandleError(gt.ctx, err)
	}
	tkn.RefreshToken = refTknStr
	return tkn, nil
}
