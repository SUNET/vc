package oauth2

import (
	"encoding/json"
	"errors"
	"net/url"
	"path"
	"reflect"
	"slices"
	"strings"
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
	// RedirectURIs is the list of allowed redirect URIs for the client.
	// Accepts either a single string or an array of strings in YAML/JSON.
	RedirectURIs RedirectURIs `json:"redirect_uri" yaml:"redirect_uri" validate:"required,min=1,dive,required" doc_example:"\"https://example.com/callback\""`
	// Scopes is the list of OAuth2 scopes allowed for the client
	Scopes []string `json:"scopes" yaml:"scopes" validate:"required"`
	// JWKSURI is the URL to the client's JWKS for verifying client_assertion signatures (RFC 7523).
	// Required for confidential clients using private_key_jwt authentication.
	JWKSURI string `json:"jwks_uri,omitempty" yaml:"jwks_uri,omitempty" validate:"required_if=Type confidential,omitempty,httpsurl"`
}

// RedirectURIs holds one or more allowed redirect URIs.
// It unmarshals from either a single string or an array of strings.
type RedirectURIs []string

func (r *RedirectURIs) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var single string
	if err := unmarshal(&single); err == nil {
		*r = RedirectURIs{single}
		return nil
	}
	var list []string
	if err := unmarshal(&list); err != nil {
		return err
	}
	*r = list
	return nil
}

func (r *RedirectURIs) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*r = RedirectURIs{single}
		return nil
	}
	var list []string
	if err := json.Unmarshal(data, &list); err != nil {
		return err
	}
	*r = list
	return nil
}

// Contains returns true if the given URI matches any of the allowed redirect URIs.
// If an allowed URI ends with "/*", it matches any URI with the same scheme, host,
// and a path that starts with the prefix before the wildcard.
func (r RedirectURIs) Contains(uri string) bool {
	parsed, err := url.Parse(uri)
	if err != nil {
		return false
	}
	// Reject URIs with fragments per RFC 6749 §3.1.2
	if parsed.Fragment != "" {
		return false
	}
	for _, allowed := range r {
		if strings.HasSuffix(allowed, "/*") {
			prefix := strings.TrimSuffix(allowed, "*")
			prefixParsed, err := url.Parse(prefix)
			if err != nil {
				continue
			}
			// Clean paths to prevent traversal via dot-segments (e.g. /a/../evil)
			cleanedPath := path.Clean(parsed.Path)
			cleanedPrefix := path.Clean(prefixParsed.Path)
			if parsed.Scheme == prefixParsed.Scheme &&
				parsed.Host == prefixParsed.Host &&
				(cleanedPath == cleanedPrefix ||
					strings.HasPrefix(cleanedPath, cleanedPrefix+"/") ||
					cleanedPrefix == "/") {
				return true
			}
			continue
		}
		allowedParsed, err := url.Parse(allowed)
		if err != nil {
			continue
		}
		if reflect.DeepEqual(parsed, allowedParsed) {
			return true
		}
	}
	return false
}

// FirstConcreteURI returns the first non-wildcard redirect URI suitable for
// use as a cancel/error redirect target. If no concrete URI exists, it derives
// one from the first wildcard entry by trimming the trailing "*".
func (r RedirectURIs) FirstConcreteURI() string {
	for _, uri := range r {
		if !strings.HasSuffix(uri, "/*") {
			return uri
		}
	}
	// Fallback: derive a concrete URI from the first wildcard pattern
	if len(r) > 0 && strings.HasSuffix(r[0], "/*") {
		return strings.TrimSuffix(r[0], "*")
	}
	return ""
}

// Clients maps client IDs to their OAuth2 client configuration
type Clients map[string]*Client

// Get returns the Client for the given clientID, or an error if not found.
func (c *Clients) Get(clientID string) (*Client, error) {
	client, ok := (*c)[clientID]
	if !ok || client == nil {
		return nil, errors.New("client not found in config")
	}
	return client, nil
}

// Allow validates the client request and returns the Client configuration if allowed.
// The caller can inspect the returned Client (e.g. Type) to enforce additional constraints.
func (c *Clients) Allow(clientID, redirectURI, scope string) (*Client, error) {
	client, ok := (*c)[clientID]
	if !ok || client == nil {
		return nil, errors.New("client not found in config")
	}

	if len(client.RedirectURIs) == 0 {
		return nil, errors.New("no redirect_uri configured for client")
	}
	if !client.RedirectURIs.Contains(redirectURI) {
		return nil, errors.New("redirect_uri does not match any allowed URI")
	}

	if !slices.Contains(client.Scopes, scope) {
		return nil, errors.New("requested scope is not allowed for this client")
	}

	return client, nil
}
