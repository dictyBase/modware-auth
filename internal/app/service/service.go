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
	"github.com/dictyBase/go-genproto/dictybaseapis/pubsub"
	"github.com/dictyBase/modware-auth/internal/message"
	"github.com/dictyBase/modware-auth/internal/oauth"
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
	repo            repository.AuthRepository
	publisher       message.Publisher
	request         message.Request
	jwtAuth         jwtauth.JWTAuth
	providerSecrets oauth.ProviderSecrets
}

// ServiceParams are the attributes that are required for creating a new AuthService
type ServiceParams struct {
	Repository      repository.AuthRepository `validate:"required"`
	Publisher       message.Publisher         `validate:"required"`
	Request         message.Request           `validate:"required"`
	JWTAuth         jwtauth.JWTAuth           `validate:"required"`
	ProviderSecrets oauth.ProviderSecrets     `validate:"required"`
	Options         []aphgrpc.Option          `validate:"required"`
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
		Service:         srv,
		repo:            srvP.Repository,
		publisher:       srvP.Publisher,
		request:         srvP.Request,
		jwtAuth:         srvP.JWTAuth,
		providerSecrets: srvP.ProviderSecrets,
	}, nil
}

func (s *AuthService) Login(ctx context.Context, l *auth.NewLogin) (*auth.Auth, error) {
	a := &auth.Auth{}
	if err := l.Validate(); err != nil {
		return a, aphgrpc.HandleInvalidParamError(ctx, err)
	}
	provider := l.Provider
	// log in to provider and get user data
	u, err := getProviderLogin(ctx, provider, l, s.providerSecrets)
	if err != nil {
		return a, aphgrpc.HandleError(ctx, err)
	}
	// look up identity based on id
	idnReq := &pubsub.IdentityReq{Provider: provider, Identifier: u.Email}
	if provider == "orcid" {
		idnReq.Identifier = u.ID
	}
	// check if the identity is present
	idnReply, err := s.request.IdentityRequestWithContext(
		ctx,
		s.Topics["identityGet"],
		idnReq,
	)
	if err != nil {
		return a, handleIdentityErr(idnReply, idnReq.Identifier, err)
	}
	// now check for user id
	uid := idnReply.Identity.Data.Attributes.UserId
	uReply, err := s.request.UserRequestWithContext(
		ctx,
		s.Topics["userExists"],
		&pubsub.IdRequest{Id: uid},
	)
	if err != nil {
		return a, handleUserErr(uReply, uid, err)
	}
	// fetch the user
	duReply, err := s.request.UserRequestWithContext(
		ctx,
		s.Topics["userGet"],
		&pubsub.IdRequest{Id: uid},
	)
	if err != nil {
		return a, handleUserErr(duReply, uid, err)
	}
	email := duReply.User.Data.Attributes.Email
	// generate tokens
	tkns, err := generateBothTokens(ctx, email, s.jwtAuth)
	if err != nil {
		return a, aphgrpc.HandleError(ctx, err)
	}
	// store refresh token in repository
	if err := s.repo.SetToken(email, tkns.RefreshToken, time.Hour*refreshTokenExpirationTimeInHours); err != nil {
		return a, aphgrpc.HandleInsertError(ctx, err)
	}
	if err := s.publisher.PublishTokens(s.Topics["tokenCreate"], tkns); err != nil {
		return a, aphgrpc.HandleError(ctx, err)
	}
	// return full Auth struct
	a = &auth.Auth{
		Token: tkns.Token,
		RefreshToken: tkns.RefreshToken,
		User: duReply.User,
		Identity: idnReply.Identity,
	}
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
	tkns := &auth.Token{}
	if err := t.Validate(); err != nil {
		return tkns, aphgrpc.HandleInvalidParamError(ctx, err)
	}
	// if jwt exists, verify it is valid
	if t.Token != "" {
		_, err := s.jwtAuth.Verify(t.Token)
		if err != nil {
			return tkns, aphgrpc.HandleError(ctx, err)
		}
	}
	// verify refresh token
	r, err := s.jwtAuth.Verify(t.RefreshToken)
	if err != nil {
		return tkns, aphgrpc.HandleError(ctx, err)
	}
	// get the claims from decoded refresh token
	c := r.Claims.(jwt.MapClaims)
	email := fmt.Sprintf("%v", c["email"])
	// verify existence of refresh token in repository
	h, err := s.repo.HasToken(email)
	if err != nil {
		return tkns, aphgrpc.HandleNotFoundError(ctx, err)
	}
	if !h {
		return tkns, nil
	}
	// generate tokens
	tkns, err = generateBothTokens(ctx, email, s.jwtAuth)
	if err != nil {
		return tkns, aphgrpc.HandleError(ctx, err)
	}
	// store refresh token in repository
	if err := s.repo.SetToken(email, tkns.RefreshToken, time.Hour*refreshTokenExpirationTimeInHours); err != nil {
		return tkns, aphgrpc.HandleInsertError(ctx, err)
	}
	if err := s.publisher.PublishTokens(s.Topics["tokenCreate"], tkns); err != nil {
		return tkns, aphgrpc.HandleError(ctx, err)
	}
	return tkns, nil
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
