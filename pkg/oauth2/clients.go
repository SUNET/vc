package oauth2

import (
	"errors"
	"net/url"
	"reflect"
	"slices"
)

// ClientType constants for OAuth2 client types per RFC 6749 Section 2.1
const (
	ClientTypePublic       = "public"
	ClientTypeConfidential = "confidential"
)

// Client holds the configuration for a single OAuth2 client
type Client struct {
	// Type is the client type per RFC 6749 Section 2.1 ("public" or "confidential").
	// Defaults to "public" since registered clients are wallets (native/web apps)
	// that cannot securely store credentials and rely on PKCE instead.
	Type string `json:"type" yaml:"type" validate:"required,oneof=public confidential" default:"public"`
	// RedirectURI is the allowed redirect URI for the client
	RedirectURI string `json:"redirect_uri" yaml:"redirect_uri" validate:"required" doc_example:"\"https://example.com/callback\""`
	// Scopes is the list of OAuth2 scopes allowed for the client
	Scopes []string `json:"scopes" yaml:"scopes" validate:"required"`
}

// Clients maps client IDs to their OAuth2 client configuration
type Clients map[string]*Client

// Get returns the Client for the given clientID, or an error if not found.
func (c *Clients) Get(clientID string) (*Client, error) {
	client, ok := (*c)[clientID]
	if !ok {
		return nil, errors.New("client not found in config")
	}
	return client, nil
}

// Allow validates the client request and returns the Client configuration if allowed.
// The caller can inspect the returned Client (e.g. Type) to enforce additional constraints.
func (c *Clients) Allow(clientID, redirectURI, scope string) (*Client, error) {
	client, ok := (*c)[clientID]
	if !ok {
		return nil, errors.New("client not found in config")
	}

	urlFromWallet, err := url.Parse(redirectURI)
	if err != nil {
		return nil, err
	}
	urlFromConfig, err := url.Parse(client.RedirectURI)
	if err != nil {
		return nil, err
	}

	if !reflect.DeepEqual(urlFromWallet, urlFromConfig) {
		return nil, errors.New("redirect_url do not match")
	}

	if !slices.Contains(client.Scopes, scope) {
		return nil, errors.New("requested scope is not allowed for this client")
	}

	return client, nil
}
