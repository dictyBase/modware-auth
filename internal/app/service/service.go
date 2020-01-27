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

type tokenParams struct {
	ctx      context.Context
	identity string
	provider string
}

type userData struct {
	user     *user.User
	identity *identity.Identity
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
	d, err := s.getUserAndIdentity(&tokenParams{
		ctx: ctx, identity: id, provider: provider,
	})
	if err != nil {
		return a, aphgrpc.HandleNotFoundError(ctx, err)
	}
	tkns, err := s.generateAndStoreTokens(&tokenParams{
		ctx: ctx, identity: id, provider: provider,
	})
	if err != nil {
		return a, aphgrpc.HandleError(ctx, err)
	}
	// return full Auth struct
	a = &auth.Auth{
		Token:        tkns.Token,
		RefreshToken: tkns.RefreshToken,
		User:         d.user,
		Identity:     d.identity,
	}
	return a, nil
}

func (s *AuthService) Relogin(ctx context.Context, l *auth.NewRelogin) (*auth.Auth, error) {
	a := &auth.Auth{}
	if err := l.Validate(); err != nil {
		return a, aphgrpc.HandleInvalidParamError(ctx, err)
	}
	refreshToken := l.RefreshToken
	v, err := s.validateRefreshToken(ctx, refreshToken)
	if err != nil {
		return a, aphgrpc.HandleError(ctx, err)
	}
	d, err := s.getUserAndIdentity(&tokenParams{
		ctx: ctx, identity: v.identity, provider: v.provider,
	})
	if err != nil {
		return a, aphgrpc.HandleNotFoundError(ctx, err)
	}
	tkns, err := s.generateAndStoreTokens(&tokenParams{
		ctx: ctx, identity: v.identity, provider: v.provider,
	})
	if err != nil {
		return a, aphgrpc.HandleError(ctx, err)
	}
	// return full Auth struct
	a = &auth.Auth{
		Token:        tkns.Token,
		RefreshToken: tkns.RefreshToken,
		User:         d.user,
		Identity:     d.identity,
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
			return tkns, aphgrpc.HandleAuthenticationError(ctx, err)
		}
	}
	refreshToken := t.RefreshToken
	v, err := s.validateRefreshToken(ctx, refreshToken)
	if err != nil {
		return tkns, aphgrpc.HandleError(ctx, err)
	}
	tkns, err = s.generateAndStoreTokens(&tokenParams{
		ctx: ctx, identity: v.identity, provider: v.provider,
	})
	if err != nil {
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
		return e, aphgrpc.HandleNotFoundError(ctx, err)
	}
	return e, nil
}

func (s *AuthService) getUserAndIdentity(gt *tokenParams) (*userData, error) {
	d := &userData{}
	// get identity data
	idn, err := s.identity.GetIdentityFromProvider(gt.ctx, &identity.IdentityProviderReq{
		Identifier: gt.identity,
		Provider:   gt.provider,
	})
	if err != nil {
		return d, aphgrpc.HandleNotFoundError(gt.ctx, err)
	}
	// get user data
	uid := idn.Data.Attributes.UserId
	ud, err := s.user.GetUser(gt.ctx, &jsonapi.GetRequest{Id: uid})
	if err != nil {
		return d, aphgrpc.HandleNotFoundError(gt.ctx, err)
	}
	d.identity = idn
	d.user = ud
	return d, nil
}

func (s *AuthService) generateAndStoreTokens(gt *tokenParams) (*auth.Token, error) {
	// generate tokens
	tkns, err := s.generateBothTokens(gt)
	if err != nil {
		return tkns, aphgrpc.HandleError(gt.ctx, err)
	}
	// store refresh token in repository
	if err := s.repo.SetToken(gt.identity, tkns.RefreshToken, time.Minute*refreshTokenExpirationTimeInMins); err != nil {
		return tkns, aphgrpc.HandleInsertError(gt.ctx, err)
	}
	if err := s.publisher.PublishTokens(s.Topics["tokenCreate"], tkns); err != nil {
		return tkns, aphgrpc.HandleInsertError(gt.ctx, err)
	}
	return tkns, nil
}

func (s *AuthService) generateBothTokens(gt *tokenParams) (*auth.Token, error) {
	tkns := &auth.Token{}
	// generate new claims
	jwtClaims := generateStandardClaims(jwtExpirationTimeInMins)
	refTknClaims := generateRefreshTokenClaims(gt.identity, gt.provider)
	// generate new JWT and refresh token to send back
	tknStr, err := s.jwtAuth.Encode(jwtClaims)
	if err != nil {
		return tkns, aphgrpc.HandleError(gt.ctx, err)
	}
	tkns.Token = tknStr
	refTknStr, err := s.jwtAuth.Encode(refTknClaims)
	if err != nil {
		return tkns, aphgrpc.HandleError(gt.ctx, err)
	}
	tkns.RefreshToken = refTknStr
	return tkns, nil
}

func (s *AuthService) validateRefreshToken(ctx context.Context, rt string) (*tokenParams, error) {
	t := &tokenParams{}
	// verify refresh token
	r, err := s.jwtAuth.Verify(rt)
	if err != nil {
		return t, aphgrpc.HandleAuthenticationError(ctx, err)
	}
	// get the claims from decoded refresh token
	c := r.Claims.(jwt.MapClaims)
	identityStr := fmt.Sprintf("%v", c["identity"])
	provider := fmt.Sprintf("%v", c["provider"])
	// verify existence of refresh token in repository
	h, err := s.repo.HasToken(identityStr)
	if err != nil {
		return t, aphgrpc.HandleGetError(ctx, err)
	}
	if !h {
		return t, aphgrpc.HandleNotFoundError(ctx, err)
	}
	t = &tokenParams{
		ctx:      ctx,
		identity: identityStr,
		provider: provider,
	}
	return t, nil
}
