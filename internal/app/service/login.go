package service

import (
	"context"

	"github.com/dictyBase/go-genproto/dictybaseapis/auth"
	"github.com/dictyBase/modware-auth/internal/oauth"
	"github.com/dictyBase/modware-auth/internal/user"
)

type ProviderLogin struct {
	provider        string
	login           *auth.NewLogin
	providerSecrets oauth.ProviderSecrets
}

func getProviderLogin(ctx context.Context, p *ProviderLogin) (*user.NormalizedUser, error) {
	u := &user.NormalizedUser{}
	provider := p.provider
	switch {
	case provider == "orcid":
		o, err := oauth.OrcidLogin(ctx, &oauth.Login{
			NewLogin: p.login, ClientSecret: p.providerSecrets.Orcid,
		})
		if err != nil {
			return u, err
		}
		return o, nil
	case provider == "google":
		g, err := oauth.GoogleLogin(ctx, &oauth.Login{
			NewLogin: p.login, ClientSecret: p.providerSecrets.Google,
		})
		if err != nil {
			return u, err
		}
		return g, nil
	case provider == "linkedin":
		li, err := oauth.LinkedInLogin(ctx, &oauth.Login{
			NewLogin: p.login, ClientSecret: p.providerSecrets.LinkedIn,
		})
		if err != nil {
			return u, err
		}
		return li, nil
	default:
		return u, nil
	}
}
