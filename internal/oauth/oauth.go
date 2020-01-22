package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/dictyBase/apihelpers/apherror"
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

func GetOrcidUser(ctx context.Context, nl *auth.NewLogin, clientSecret string) (*user.NormalizedUser, error) {
	nu := &user.NormalizedUser{}
	postBody := fmt.Sprintf(
		"client_id=%s&client_secret=%s&grant_type=%s&redirect_uri=%s&code=%s",
		nl.ClientId,
		clientSecret,
		"authorization_code",
		nl.RedirectUrl,
		nl.Code,
	)
	body := strings.NewReader(postBody)
	req, err := http.NewRequest("POST", OrcidEndpoint.TokenURL, body)
	if err != nil {
		return nu, apherror.ErrJSONEncoding.New(err.Error())
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nu, apherror.ErrOauthExchange.New(err.Error())
	}
	defer resp.Body.Close()
	var orcid user.OrcidUser
	if err := json.NewDecoder(resp.Body).Decode(&orcid); err != nil {
		return nu, apherror.ErrJSONEncoding.New(err.Error())
	}
	nu = &user.NormalizedUser{
		Name:     orcid.Name,
		Id:       orcid.Orcid,
		Provider: "orcid",
	}
	return nu, nil
}

func GetGoogleUser(ctx context.Context, nl *auth.NewLogin, clientSecret string) (*user.NormalizedUser, error) {
	nu := &user.NormalizedUser{}
	oc := &oauth2.Config{
		ClientID:     nl.ClientId,
		ClientSecret: clientSecret,
		Endpoint:     google.Endpoint,
		RedirectURL:  nl.RedirectUrl,
		Scopes:       strings.Split(nl.Scopes, " "),
	}
	token, err := oc.Exchange(oauth2.NoContext, nl.Code)
	if err != nil {
		return nu, apherror.ErrOauthExchange.New(err.Error())
	}
	oauthClient := oc.Client(oauth2.NoContext, token)
	resp, err := oauthClient.Get(user.Google)
	if err != nil {
		return nu, apherror.ErrUserRetrieval.New(err.Error())
	}
	var google user.GoogleUser
	if err := json.NewDecoder(resp.Body).Decode(&google); err != nil {
		return nu, apherror.ErrJSONEncoding.New(err.Error())
	}
	nu = &user.NormalizedUser{
		Name:     google.Name,
		Email:    google.Email,
		Id:       google.Id,
		Provider: "google",
	}
	return nu, nil
}

func GetLinkedInUser(ctx context.Context, nl *auth.NewLogin, clientSecret string) (*user.NormalizedUser, error) {
	nu := &user.NormalizedUser{}
	oc := &oauth2.Config{
		ClientID:     nl.ClientId,
		ClientSecret: clientSecret,
		Endpoint:     linkedin.Endpoint,
		RedirectURL:  nl.RedirectUrl,
		Scopes:       strings.Split(nl.Scopes, " "),
	}
	token, err := oc.Exchange(oauth2.NoContext, nl.Code)
	if err != nil {
		return nu, apherror.ErrOauthExchange.New(err.Error())
	}
	oauthClient := oc.Client(oauth2.NoContext, token)
	resp, err := oauthClient.Get(user.LinkedIn)
	if err != nil {
		return nu, apherror.ErrUserRetrieval.New(err.Error())
	}
	var linkedin user.LinkedInUser
	if err := json.NewDecoder(resp.Body).Decode(&linkedin); err != nil {
		return nu, apherror.ErrJSONEncoding.New(err.Error())
	}
	nu = &user.NormalizedUser{
		Name:     fmt.Sprintf("%s %s", linkedin.FirstName, linkedin.LastName),
		Email:    linkedin.EmailAddress,
		Id:       linkedin.Id,
		Provider: "linkedin",
	}
	return nu, nil
}
