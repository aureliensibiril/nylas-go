package nylas

import (
	"context"
	"net/url"
	"strconv"
	"strings"
)

// ResponseType enum
type ResponseType int

const (
	Code ResponseType = iota
	Token
)

func (rt ResponseType) String() string {
	return [...]string{"code", "token"}[rt]
}

// Provider enum
type Provider int

const (
	None Provider = iota
	ICloud
	Gmail
	Office365
	Exchange
	IMAP
)

func (p Provider) String() string {
	return [...]string{"", "icloud", "gmail", "office365", "exchange", "imap"}[p]
}

// AuthorizeRequest used to start the process of connecting an account to Nylas.
// See: https://developer.nylas.com/docs/api/v2/#get-/oauth/authorize
type HostedAuthorizeRequest struct {
	ClientID        string
	RedirectURI     string
	LoginHint       string
	State           string
	Scopes          []string
	Provider        Provider
	ResponseType    ResponseType
	RedirectOnError *bool
}

// HostedAuthentificationURL returns the URL to redirect the user to in order to connect their account to Nylas.
// See: https://developer.nylas.com/docs/api/v2/#get-/oauth/authorize
func (c *Client) HostedAuthentificationURL(ctx context.Context, authReq HostedAuthorizeRequest) string {

	if len(authReq.Scopes) == 0 {
		authReq.Scopes = []string{"email", "calendar", "contacts"}
	}

	values := url.Values{}
	values.Add("redirect_uri", authReq.RedirectURI)
	values.Add("client_id", c.clientID)
	values.Add("response_type", Code.String())
	values.Add("login_hint", authReq.LoginHint)
	values.Add("state", authReq.State)

	if len(authReq.Scopes) > 0 {
		values.Add("scopes", strings.Join(authReq.Scopes, ","))
	}

	if authReq.Provider != None {
		values.Add("provider", authReq.Provider.String())
	}

	if authReq.RedirectOnError != nil {
		values.Add("redirect_on_error", strconv.FormatBool(*authReq.RedirectOnError))
	}

	return c.baseURL + "/oauth/authorize" + "?" + values.Encode()
}
