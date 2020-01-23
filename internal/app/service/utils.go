package service

import (
	"context"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/dictyBase/aphgrpc"
	"github.com/dictyBase/apihelpers/apherror"
	"github.com/dictyBase/go-genproto/dictybaseapis/auth"
	"github.com/dictyBase/go-genproto/dictybaseapis/pubsub"
	"github.com/dictyBase/modware-auth/internal/jwtauth"
	"github.com/dictyBase/modware-auth/internal/oauth"
	"github.com/dictyBase/modware-auth/internal/user"
	"github.com/rs/xid"
	"google.golang.org/grpc/status"
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

func generateBothTokens(ctx context.Context, email string, j jwtauth.JWTAuth) (*auth.Token, error) {
	tkn := &auth.Token{}
	// generate new claims
	jwtClaims := generateStandardClaims(jwtExpirationTimeInHours)
	refTknClaims := generateRefreshTokenClaims(email)
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

func getProviderLogin(ctx context.Context, provider string, l *auth.NewLogin, providerSecrets oauth.ProviderSecrets) (*user.NormalizedUser, error) {
	u := &user.NormalizedUser{}
	switch {
	case provider == "orcid":
		o, err := oauth.OrcidLogin(l, providerSecrets.Orcid)
		if err != nil {
			return u, aphgrpc.HandleError(ctx, err)
		}
		return o, nil
	case provider == "google":
		g, err := oauth.GoogleLogin(l, providerSecrets.Google)
		if err != nil {
			return u, aphgrpc.HandleError(ctx, err)
		}
		return g, nil
	case provider == "linkedin":
		li, err := oauth.LinkedInLogin(l, providerSecrets.LinkedIn)
		if err != nil {
			return u, aphgrpc.HandleError(ctx, err)
		}
		return li, nil
	default:
		return u, nil
	}
}

func handleUserErr(reply *pubsub.UserReply, id int64, err error) error {
	if err != nil {
		return apherror.ErrMessagingReply.New("error in getting user reply %s", err.Error())
	}
	if reply.Status != nil {
		if !reply.Exist {
			return apherror.ErrAuthentication.New(
				"cannot authenticate user id %s with error %s",
				id,
				status.ErrorProto(reply.Status).Error(),
			)
		}
		return apherror.ErrMessagingReply.New(status.ErrorProto(reply.Status).Error())
	}
	return nil
}

func handleIdentityErr(reply *pubsub.IdentityReply, id string, err error) error {
	if err != nil {
		return apherror.ErrMessagingReply.New("error in getting identifier reply %s", err.Error())
	}
	if reply.Status != nil {
		if !reply.Exist {
			return apherror.ErrAuthentication.New(
				"cannot authenticate identifier %s with error %s",
				id,
				status.ErrorProto(reply.Status).Error(),
			)
		}
		return apherror.ErrMessagingReply.New(status.ErrorProto(reply.Status).Error())
	}
	return nil
}
