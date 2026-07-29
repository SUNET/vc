package oauth2

import (
	"context"
	"encoding/json"
	"time"

	"github.com/SUNET/vc/pkg/jose"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/pki"

	"github.com/golang-jwt/jwt/v5"
)

// ClientMetadata represents OAuth 2.0 client metadata
// Extended for OpenID4VP with vp_formats_supported per
// https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-verifier-metadata-client-me
type ClientMetadata struct {
	// ClientID REQUIRED. OAuth 2.0 client identifier string.
	ClientID string `json:"client_id" validate:"required"`

	// ClientName OPTIONAL. Human-readable string name of the client to be presented to the end-user during authorization.
	ClientName string `json:"client_name,omitempty"`

	// ClientURI OPTIONAL. URL string of a web page providing information about the client.
	ClientURI string `json:"client_uri,omitempty"`

	// LogoURI OPTIONAL. URL string that references a logo for the client.
	LogoURI string `json:"logo_uri,omitempty"`

	// RedirectURIs REQUIRED. Array of redirection URI strings for use in redirect-based flows.
	RedirectURIs []string `json:"redirect_uris,omitempty"`

	// ResponseTypes OPTIONAL. JSON array containing a list of the OAuth 2.0 response_type values that the client will restrict itself to using.
	ResponseTypes []string `json:"response_types,omitempty"`

	// GrantTypes OPTIONAL. JSON array containing a list of the OAuth 2.0 grant types that the client will restrict itself to using.
	GrantTypes []string `json:"grant_types,omitempty"`

	// Scope OPTIONAL. String containing a space-separated list of scope values that the client can use when requesting access tokens.
	Scope string `json:"scope,omitempty"`

	// Contacts OPTIONAL. Array of strings representing ways to contact people responsible for this client, typically email addresses.
	Contacts []string `json:"contacts,omitempty"`

	// JWKSURI OPTIONAL. URL string referencing the client's JSON Web Key (JWK) Set document.
	JWKSURI string `json:"jwks_uri,omitempty"`

	// VPFormatsSupported OPTIONAL. Object defining the formats and algorithms the client (verifier) supports.
	// Per OpenID4VP spec section on Verifier Metadata.
	VPFormatsSupported *openid4vp.VPFormatsSupported `json:"vp_formats_supported,omitempty"`

	// SignedMetadata OPTIONAL. A JWT containing the client metadata values as claims.
	SignedMetadata string `json:"signed_metadata,omitempty"`
}

// Marshal converts ClientMetadata to JWT claims
func (c *ClientMetadata) MarshalJWTClaims() (jwt.MapClaims, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	claims := jwt.MapClaims{}
	err = json.Unmarshal(data, &claims)
	if err != nil {
		return nil, err
	}
	claims["iat"] = time.Now().Unix()
	return claims, nil
}

// Sign creates a signed JWT of the client metadata using pki.Signer.
// The pki.Signer interface supports both software keys and HSM.
func (c *ClientMetadata) Sign(ctx context.Context, signer pki.Signer, chain []string) (string, error) {
	claims, err := c.MarshalJWTClaims()
	if err != nil {
		return "", err
	}

	header := jwt.MapClaims{
		"typ": "JWT",
	}

	// Add x5c header if chain provided
	if len(chain) > 0 {
		header["x5c"] = chain
	}

	return jose.MakeJWT(ctx, header, claims, signer)
}
