package service

import (
	"context"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/dictyBase/aphgrpc"
	"github.com/dictyBase/go-genproto/dictybaseapis/auth"
	"github.com/dictyBase/go-genproto/dictybaseapis/pubsub"
	"github.com/dictyBase/modware-auth/internal/jwtauth"
	"github.com/dictyBase/modware-auth/internal/oauth"
	"github.com/dictyBase/modware-auth/internal/user"
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

type ProviderLogin struct {
	ctx             context.Context
	provider        string
	login           *auth.NewLogin
	providerSecrets oauth.ProviderSecrets
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

func generateBothTokens(ctx context.Context, identity string, provider string, j jwtauth.JWTAuth) (*auth.Token, error) {
	tkn := &auth.Token{}
	// generate new claims
	jwtClaims := generateStandardClaims(jwtExpirationTimeInMins)
	refTknClaims := generateRefreshTokenClaims(identity, provider)
	// generate new JWT and refresh token to send back
	tknStr, err := j.Encode(jwtClaims)
	if err != nil {
		return tkn, aphgrpc.HandleError(ctx, err)
	}
	tkn.Token = tknStr
	refTknStr, err := j.Encode(refTknClaims)
	if err != nil {
		return tkn, aphgrpc.HandleError(ctx, err)
	}
	tkn.RefreshToken = refTknStr
	return tkn, nil
}

func getProviderLogin(p *ProviderLogin) (*user.NormalizedUser, error) {
	u := &user.NormalizedUser{}
	provider := p.provider
	switch {
	case provider == "orcid":
		o, err := oauth.OrcidLogin(p.ctx, p.login, p.providerSecrets.Orcid)
		if err != nil {
			return u, aphgrpc.HandleError(p.ctx, err)
		}
		return o, nil
	case provider == "google":
		g, err := oauth.GoogleLogin(p.ctx, p.login, p.providerSecrets.Google)
		if err != nil {
			return u, aphgrpc.HandleError(p.ctx, err)
		}
		return g, nil
	case provider == "linkedin":
		li, err := oauth.LinkedInLogin(p.ctx, p.login, p.providerSecrets.LinkedIn)
		if err != nil {
			return u, aphgrpc.HandleError(p.ctx, err)
		}
		return li, nil
	default:
		return u, nil
	}
}

func getIdentity(ctx context.Context, provider string, id string, auth *AuthService) (*pubsub.IdentityReply, error) {
	i := &pubsub.IdentityReply{}
	// look up identity based on id
	idnReq := &pubsub.IdentityReq{Provider: provider, Identifier: id}
	// check if the identity is present
	idnReply, err := auth.request.IdentityRequestWithContext(
		ctx,
		auth.Topics["identityGet"],
		idnReq,
	)
	if err != nil {
		return i, handleIdentityErr(ctx, idnReply, err)
	}
	return idnReply, nil
}

func getUser(ctx context.Context, uid int64, auth *AuthService) (*pubsub.UserReply, error) {
	u := &pubsub.UserReply{}
	// check for user id
	uReply, err := auth.request.UserRequestWithContext(
		ctx,
		auth.Topics["userExists"],
		&pubsub.IdRequest{Id: uid},
	)
	if err != nil {
		return u, handleUserErr(ctx, uReply, err)
	}
	// fetch the user
	duReply, err := auth.request.UserRequestWithContext(
		ctx,
		auth.Topics["userGet"],
		&pubsub.IdRequest{Id: uid},
	)
	if err != nil {
		return u, handleUserErr(ctx, duReply, err)
	}
	return duReply, nil
}

func handleUserErr(ctx context.Context, reply *pubsub.UserReply, err error) error {
	if err != nil {
		return aphgrpc.HandleMessagingReplyError(ctx, err)
	}
	if reply.Status != nil {
		if !reply.Exist {
			return aphgrpc.HandleAuthenticationError(ctx, err)
		}
		return aphgrpc.HandleMessagingReplyError(ctx, err)
	}
	return nil
}

func handleIdentityErr(ctx context.Context, reply *pubsub.IdentityReply, err error) error {
	if err != nil {
		return aphgrpc.HandleMessagingReplyError(ctx, err)
	}
	if reply.Status != nil {
		if !reply.Exist {
			return aphgrpc.HandleAuthenticationError(ctx, err)
		}
		return aphgrpc.HandleMessagingReplyError(ctx, err)
	}
	return nil
}
