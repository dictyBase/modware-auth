package service

import (
	"context"
	"crypto/rsa"
	"time"

	"github.com/dictyBase/modware-auth/internal/jwtauth"

	"github.com/go-playground/validator/v10"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/dictyBase/aphgrpc"
	"github.com/dictyBase/go-genproto/dictybaseapis/auth"
	"github.com/dictyBase/modware-auth/internal/message"
	"github.com/dictyBase/modware-auth/internal/repository"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/rs/xid"
)

// AuthService is the container for managing auth service definitions
type AuthService struct {
	*aphgrpc.Service
	repo       repository.AuthRepository
	publisher  message.Publisher
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
}

// ServiceParams are the attributes that are required for creating a new AuthService
type ServiceParams struct {
	Repository repository.AuthRepository `validate:"required"`
	Publisher  message.Publisher         `validate:"required"`
	PublicKey  *rsa.PublicKey            `validate:"required"`
	PrivateKey *rsa.PrivateKey           `validate:"required"`
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
		Service:    srv,
		repo:       srvP.Repository,
		publisher:  srvP.Publisher,
		publicKey:  srvP.PublicKey,
		privateKey: srvP.PrivateKey,
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
	// need to add:
	// if jwt exists, validate this
	// decode token with Verify method
	// if valid jwt, generate new jwt
	// then validate refresh token

	// should we look up by email instead? // email-JWT (key-value)
	h, err := s.repo.HasToken(t.RefreshToken)
	if err != nil {
		return tkn, aphgrpc.HandleNotFoundError(ctx, err)
	}
	if !h {
		return tkn, nil
	}

	claims := jwt.StandardClaims{
		Issuer:    "dictyBase",
		Subject:   "dictyBase login token",
		ExpiresAt: time.Now().Add(time.Hour * 360).Unix(),
		IssuedAt:  time.Now().Unix(),
		NotBefore: time.Now().Unix(),
		Id:        xid.New().String(),
		Audience:  "user",
	}

	// user's refresh token is valid
	// so generate new JWT and refresh token to send back
	newTkn := jwtauth.NewJwtAuth(jwt.SigningMethodRS512, s.privateKey, s.publicKey)
	tknStr, err := newTkn.Encode(claims)
	if err != nil {
		return tkn, aphgrpc.HandleError(ctx, err)
	}
	tkn.Token = tknStr

	newRefTkn := jwtauth.NewJwtAuth(jwt.SigningMethodRS512, s.privateKey, s.publicKey)
	refStr, err := newRefTkn.Encode(claims)
	if err != nil {
		return tkn, aphgrpc.HandleError(ctx, err)
	}
	tkn.RefreshToken = refStr

	// put refresh token in repository
	// need to get user's email for this
	if err := s.repo.SetToken(refStr, "email", time.Hour*24*30); err != nil {
		return tkn, aphgrpc.HandleInsertError(ctx, err)
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
