package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/dictyBase/aphgrpc"

	"github.com/dictyBase/go-genproto/dictybaseapis/auth"
	"github.com/dictyBase/modware-auth/internal/user"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/linkedin"
)

var OrcidEndpoint = oauth2.Endpoint{
	AuthURL:  "https://orcid.org/oauth/authorize",
	TokenURL: "https://orcid.org/oauth/token",
}

type ProviderSecrets struct {
	Google   string `json:"google"`
	LinkedIn string `json:"linkedin"`
	Orcid    string `json:"orcid"`
}

type Login struct {
	Ctx          context.Context
	NewLogin     *auth.NewLogin
	ClientSecret string
}

func OrcidLogin(l *Login) (*user.NormalizedUser, error) {
	nu := &user.NormalizedUser{}
	postBody := fmt.Sprintf(
		"client_id=%s&client_secret=%s&grant_type=%s&redirect_uri=%s&code=%s",
		l.NewLogin.ClientId,
		l.ClientSecret,
		"authorization_code",
		l.NewLogin.RedirectUrl,
		l.NewLogin.Code,
	)
	body := strings.NewReader(postBody)
	req, err := http.NewRequest("POST", OrcidEndpoint.TokenURL, body)
	if err != nil {
		return nu, aphgrpc.HandleJSONEncodingError(l.Ctx, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nu, aphgrpc.HandleOauthExchangeError(l.Ctx, err)
	}
	defer resp.Body.Close()
	var orcid user.OrcidUser
	if err := json.NewDecoder(resp.Body).Decode(&orcid); err != nil {
		return nu, aphgrpc.HandleJSONEncodingError(l.Ctx, err)
	}
	nu = &user.NormalizedUser{
		Name:     orcid.Name,
		ID:       orcid.Orcid,
		Provider: "orcid",
	}
	return nu, nil
}

func GoogleLogin(l *Login) (*user.NormalizedUser, error) {
	nu := &user.NormalizedUser{}
	oc := &oauth2.Config{
		ClientID:     l.NewLogin.ClientId,
		ClientSecret: l.ClientSecret,
		Endpoint:     google.Endpoint,
		RedirectURL:  l.NewLogin.RedirectUrl,
		Scopes:       strings.Split(l.NewLogin.Scopes, " "),
	}
	token, err := oc.Exchange(l.Ctx, l.NewLogin.Code)
	if err != nil {
		return nu, aphgrpc.HandleOauthExchangeError(l.Ctx, err)
	}
	oauthClient := oc.Client(l.Ctx, token)
	resp, err := oauthClient.Get(user.Google)
	if err != nil {
		return nu, aphgrpc.HandleUserRetrievalError(l.Ctx, err)
	}
	defer resp.Body.Close()
	var google user.GoogleUser
	if err := json.NewDecoder(resp.Body).Decode(&google); err != nil {
		return nu, aphgrpc.HandleJSONEncodingError(l.Ctx, err)
	}
	nu = &user.NormalizedUser{
		Name:     google.Name,
		Email:    google.Email,
		ID:       google.ID,
		Provider: "google",
	}
	return nu, nil
}

func LinkedInLogin(l *Login) (*user.NormalizedUser, error) {
	nu := &user.NormalizedUser{}
	oc := &oauth2.Config{
		ClientID:     l.NewLogin.ClientId,
		ClientSecret: l.ClientSecret,
		Endpoint:     linkedin.Endpoint,
		RedirectURL:  l.NewLogin.RedirectUrl,
		Scopes:       strings.Split(l.NewLogin.Scopes, " "),
	}
	token, err := oc.Exchange(context.Background(), l.NewLogin.Code)
	if err != nil {
		return nu, aphgrpc.HandleOauthExchangeError(l.Ctx, err)
	}
	oauthClient := oc.Client(context.Background(), token)
	resp, err := oauthClient.Get(user.LinkedIn)
	if err != nil {
		return nu, aphgrpc.HandleUserRetrievalError(l.Ctx, err)
	}
	defer resp.Body.Close()
	var linkedin user.LinkedInUser
	if err := json.NewDecoder(resp.Body).Decode(&linkedin); err != nil {
		return nu, aphgrpc.HandleJSONEncodingError(l.Ctx, err)
	}
	nu = &user.NormalizedUser{
		Name:     fmt.Sprintf("%s %s", linkedin.FirstName, linkedin.LastName),
		Email:    linkedin.EmailAddress,
		ID:       linkedin.ID,
		Provider: "linkedin",
	}
	return nu, nil
}
