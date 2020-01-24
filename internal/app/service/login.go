package service

import (
	"context"

	"github.com/dictyBase/aphgrpc"
	"github.com/dictyBase/go-genproto/dictybaseapis/auth"
	"github.com/dictyBase/modware-auth/internal/oauth"
	"github.com/dictyBase/modware-auth/internal/user"
)

type ProviderLogin struct {
	ctx             context.Context
	provider        string
	login           *auth.NewLogin
	providerSecrets oauth.ProviderSecrets
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
