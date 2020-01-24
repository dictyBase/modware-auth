package service

import (
	"context"
	"fmt"
	"time"

	"github.com/go-playground/validator/v10"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/dictyBase/aphgrpc"
	"github.com/dictyBase/go-genproto/dictybaseapis/api/jsonapi"
	"github.com/dictyBase/go-genproto/dictybaseapis/auth"
	"github.com/dictyBase/go-genproto/dictybaseapis/identity"
	"github.com/dictyBase/go-genproto/dictybaseapis/user"

	"github.com/dictyBase/modware-auth/internal/jwtauth"
	"github.com/dictyBase/modware-auth/internal/message"
	"github.com/dictyBase/modware-auth/internal/oauth"
	"github.com/dictyBase/modware-auth/internal/repository"
	"github.com/golang/protobuf/ptypes/empty"
)

const (
	jwtExpirationTimeInMins          = 15       // 15 mins
	refreshTokenExpirationTimeInMins = 60 * 720 // 30 days
)

// AuthService is the container for managing auth service definitions
type AuthService struct {
	*aphgrpc.Service
	repo            repository.AuthRepository
	publisher       message.Publisher
	identity        identity.IdentityServiceClient
	user            user.UserServiceClient
	jwtAuth         jwtauth.JWTAuth
	providerSecrets oauth.ProviderSecrets
}

// ServiceParams are the attributes that are required for creating a new AuthService
type ServiceParams struct {
	Repository      repository.AuthRepository      `validate:"required"`
	Publisher       message.Publisher              `validate:"required"`
	User            user.UserServiceClient         `validate:"required"`
	Identity        identity.IdentityServiceClient `validate:"required"`
	JWTAuth         jwtauth.JWTAuth                `validate:"required"`
	ProviderSecrets oauth.ProviderSecrets          `validate:"required"`
	Options         []aphgrpc.Option               `validate:"required"`
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
		user:            srvP.User,
		identity:        srvP.Identity,
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
	u, err := getProviderLogin(&ProviderLogin{
		ctx: ctx, provider: provider, login: l, providerSecrets: s.providerSecrets,
	})
	if err != nil {
		return a, aphgrpc.HandleError(ctx, err)
	}
	id := u.Email
	if provider == "orcid" {
		id = u.ID
	}
	// get identity data
	idn, err := s.identity.GetIdentityFromProvider(ctx, &identity.IdentityProviderReq{
		Identifier: id,
		Provider:   provider,
	})
	if err != nil {
		return a, aphgrpc.HandleNotFoundError(ctx, err)
	}
	// get user data
	uid := idn.Data.Attributes.UserId
	ud, err := s.user.GetUser(ctx, &jsonapi.GetRequest{Id: uid})
	if err != nil {
		return a, aphgrpc.HandleNotFoundError(ctx, err)
	}
	// generate tokens
	tkns, err := generateBothTokens(&GenerateTokens{
		ctx: ctx, identity: id, provider: provider, j: s.jwtAuth,
	})
	if err != nil {
		return a, aphgrpc.HandleError(ctx, err)
	}
	// store refresh token in repository
	if err := s.repo.SetToken(id, tkns.RefreshToken, time.Minute*refreshTokenExpirationTimeInMins); err != nil {
		return a, aphgrpc.HandleInsertError(ctx, err)
	}
	if err := s.publisher.PublishTokens(s.Topics["tokenCreate"], tkns); err != nil {
		return a, aphgrpc.HandleError(ctx, err)
	}
	// return full Auth struct
	a = &auth.Auth{
		Token:        tkns.Token,
		RefreshToken: tkns.RefreshToken,
		User:         ud,
		Identity:     idn,
	}
	return a, nil
}

func (s *AuthService) Relogin(ctx context.Context, l *auth.NewRelogin) (*auth.Auth, error) {
	a := &auth.Auth{}
	if err := l.Validate(); err != nil {
		return a, aphgrpc.HandleInvalidParamError(ctx, err)
	}
	// verify refresh token
	r, err := s.jwtAuth.Verify(l.RefreshToken)
	if err != nil {
		return a, aphgrpc.HandleError(ctx, err)
	}
	// get the claims from decoded refresh token
	c := r.Claims.(jwt.MapClaims)
	identityStr := fmt.Sprintf("%v", c["identity"])
	provider := fmt.Sprintf("%v", c["provider"])
	// verify existence of refresh token in repository
	h, err := s.repo.HasToken(identityStr)
	if err != nil {
		return a, aphgrpc.HandleNotFoundError(ctx, err)
	}
	if !h {
		return a, nil
	}
	// get identity data
	idn, err := s.identity.GetIdentityFromProvider(ctx, &identity.IdentityProviderReq{
		Identifier: identityStr,
		Provider:   provider,
	})
	if err != nil {
		return a, aphgrpc.HandleNotFoundError(ctx, err)
	}
	// get user data
	uid := idn.Data.Attributes.UserId
	ud, err := s.user.GetUser(ctx, &jsonapi.GetRequest{Id: uid})
	if err != nil {
		return a, aphgrpc.HandleNotFoundError(ctx, err)
	}
	// generate tokens
	tkns, err := generateBothTokens(&GenerateTokens{
		ctx: ctx, identity: identityStr, provider: provider, j: s.jwtAuth,
	})
	if err != nil {
		return a, aphgrpc.HandleError(ctx, err)
	}
	// store refresh token in repository
	if err := s.repo.SetToken(identityStr, tkns.RefreshToken, time.Minute*refreshTokenExpirationTimeInMins); err != nil {
		return a, aphgrpc.HandleInsertError(ctx, err)
	}
	if err := s.publisher.PublishTokens(s.Topics["tokenCreate"], tkns); err != nil {
		return a, aphgrpc.HandleError(ctx, err)
	}
	// return full Auth struct
	a = &auth.Auth{
		Token:        tkns.Token,
		RefreshToken: tkns.RefreshToken,
		User:         ud,
		Identity:     idn,
	}
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
	identity := fmt.Sprintf("%v", c["identity"])
	provider := fmt.Sprintf("%v", c["provider"])
	// verify existence of refresh token in repository
	h, err := s.repo.HasToken(identity)
	if err != nil {
		return tkns, aphgrpc.HandleNotFoundError(ctx, err)
	}
	if !h {
		return tkns, nil
	}
	// generate tokens
	tkns, err = generateBothTokens(&GenerateTokens{
		ctx: ctx, identity: identity, provider: provider, j: s.jwtAuth,
	})
	if err != nil {
		return tkns, aphgrpc.HandleError(ctx, err)
	}
	// store refresh token in repository
	if err := s.repo.SetToken(identity, tkns.RefreshToken, time.Minute*refreshTokenExpirationTimeInMins); err != nil {
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
