// package user provides url constants and structures
// for handling user information
// from various oauth providers
package user

var (
	Google   = "https://www.googleapis.com/userinfo/v2/me"
	LinkedIn = "https://api.linkedin.com/v1/people/~:(first-name,last-name,email-address)?format=json"
	Orcid    = "https://pub.orcid.org/v2.1"
)

type GoogleUser struct {
	FamilyName    string `json:"family_name"`
	Name          string `json:"name"`
	Gender        string `json:"gender"`
	Email         string `json:"email"`
	GivenName     string `json:"given_name"`
	Id            string `json:"id"`
	VerifiedEmail bool   `json:"verified_email"`
	Picture       string `json:"picture"`
}

type LinkedInUser struct {
	FirstName                  string `json:"firstName"`
	Headline                   string `json:"headline"`
	Id                         string `json:"id"`
	LastName                   string `json:"lastName"`
	SiteStandardProfileRequest struct {
		URL string `json:"url"`
	} `json:"siteStandardProfileRequest"`
	EmailAddress string `json:"emailAddress"`
}

type OrcidUser struct {
	Name         string `json:"name"`
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Orcid        string `json:"orcid"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
}

type NormalizedUser struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Id       string `json:"id"`
	Provider string `json:"provider"`
}
