package service

import (
	"context"
	"fmt"
	"time"

	"github.com/dictyBase/modware-auth/internal/jwtauth"

	"github.com/go-playground/validator/v10"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/dictyBase/aphgrpc"
	"github.com/dictyBase/go-genproto/dictybaseapis/auth"
	"github.com/dictyBase/modware-auth/internal/message"
	"github.com/dictyBase/modware-auth/internal/repository"
	"github.com/golang/protobuf/ptypes/empty"
)

const (
	jwtExpirationTimeInHours          = 360 // 15 days
	refreshTokenExpirationTimeInHours = 720 // 30 days
)

// AuthService is the container for managing auth service definitions
type AuthService struct {
	*aphgrpc.Service
	repo      repository.AuthRepository
	publisher message.Publisher
	jwtAuth   jwtauth.JWTAuth
}

// ServiceParams are the attributes that are required for creating a new AuthService
type ServiceParams struct {
	Repository repository.AuthRepository `validate:"required"`
	Publisher  message.Publisher         `validate:"required"`
	JWTAuth    jwtauth.JWTAuth           `validate:"required"`
	Options    []aphgrpc.Option          `validate:"required"`
}

func defaultOptions() *aphgrpc.ServiceOptions {
	return &aphgrpc.ServiceOptions{Resource: "auth"}
}

// NewAuthService is the constructor for creating a new instance of AuthService
func NewAuthService(srvP *ServiceParams) (*AuthService, error) {
	if err := validator.New().Struct(srvP); err != nil {
		return &AuthService{}, err
	}
	so := defaultOptions()
	for _, optfn := range srvP.Options {
		optfn(so)
	}
	srv := &aphgrpc.Service{}
	aphgrpc.AssignFieldsToStructs(so, srv)
	return &AuthService{
		Service: srv,
		repo:    srvP.Repository,
		jwtAuth: srvP.JWTAuth,
	}, nil
}

func (s *AuthService) Login(ctx context.Context, l *auth.NewLogin) (*auth.Auth, error) {
	a := &auth.Auth{}
	if err := l.Validate(); err != nil {
		return a, aphgrpc.HandleInvalidParamError(ctx, err)
	}

	// 1. generate jwt and refresh token (which is also jwt)
	// 2. send user login data through middleware (need to expand on this)
	// 3. return json payload with tokens, user and identity data

	return a, nil
}

func (s *AuthService) Relogin(ctx context.Context, l *auth.NewRelogin) (*auth.Auth, error) {
	a := &auth.Auth{}
	if err := l.Validate(); err != nil {
		return a, aphgrpc.HandleInvalidParamError(ctx, err)
	}

	// 1. look up refresh token
	// 2. verify refresh token is valid
	// 3. fetch user/identity data based on key (user email)
	// 4. generate new jwt
	// 5. return json payload

	return a, nil
}

func (s *AuthService) GetRefreshToken(ctx context.Context, t *auth.NewToken) (*auth.Token, error) {
	tkn := &auth.Token{}
	if err := t.Validate(); err != nil {
		return tkn, aphgrpc.HandleInvalidParamError(ctx, err)
	}
	// if jwt exists, verify it is valid
	if t.Token != "" {
		_, err := s.jwtAuth.Verify(t.Token)
		if err != nil {
			return tkn, aphgrpc.HandleError(ctx, err)
		}
	}
	// verify refresh token
	r, err := s.jwtAuth.Verify(t.RefreshToken)
	if err != nil {
		return tkn, aphgrpc.HandleError(ctx, err)
	}
	// get the claims from decoded refresh token
	c := r.Claims.(jwt.MapClaims)
	email := fmt.Sprintf("%v", c["email"])
	// verify existence of refresh token in repository
	h, err := s.repo.HasToken(email)
	if err != nil {
		return tkn, aphgrpc.HandleNotFoundError(ctx, err)
	}
	if !h {
		return tkn, nil
	}
	// generate new claims
	jwtClaims := generateStandardClaims(jwtExpirationTimeInHours)
	refTknClaims := generateRefreshTokenClaims(email)
	// generate new JWT and refresh token to send back
	tknStr, err := s.jwtAuth.Encode(jwtClaims)
	if err != nil {
		return tkn, aphgrpc.HandleError(ctx, err)
	}
	tkn.Token = tknStr
	refTknStr, err := s.jwtAuth.Encode(refTknClaims)
	if err != nil {
		return tkn, aphgrpc.HandleError(ctx, err)
	}
	tkn.RefreshToken = refTknStr
	// store refresh token in repository
	if err := s.repo.SetToken(email, refTknStr, time.Hour*refreshTokenExpirationTimeInHours); err != nil {
		return tkn, aphgrpc.HandleInsertError(ctx, err)
	}
	if err := s.publisher.PublishTokens(s.Topics["tokenCreate"], tkn); err != nil {
		return tkn, aphgrpc.HandleError(ctx, err)
	}
	return tkn, nil
}

func (s *AuthService) Logout(ctx context.Context, t *auth.NewRefreshToken) (*empty.Empty, error) {
	e := &empty.Empty{}
	if err := t.Validate(); err != nil {
		return e, aphgrpc.HandleInvalidParamError(ctx, err)
	}
	if err := s.repo.DeleteToken(t.RefreshToken); err != nil {
		return e, aphgrpc.HandleDeleteError(ctx, err)
	}
	return e, nil
}
