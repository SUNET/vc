package apiv1

import (
	"context"
	"fmt"
	"net/url"
	"strconv"

	"github.com/SUNET/vc/internal/registry/db"
	"github.com/SUNET/vc/pkg/jose"
	"github.com/SUNET/vc/pkg/tokenstatuslist"
)

// TokenStatusListsRequest represents the request for fetching a Status List Token.
// Per draft-ietf-oauth-status-list Section 8.1
type TokenStatusListsRequest struct {
	// ID is the section identifier for the status list (from URI path)
	ID int64 `json:"id" uri:"id" validate:"gte=0"`

	// Time is an optional query parameter for historical resolution (Section 8.4)
	// Format: Unix timestamp (seconds since epoch). Zero means not provided.
	Time *int64 `json:"time" form:"time"`

	// Accept is the Accept header from the HTTP request for content negotiation.
	// Supported values: "application/statuslist+jwt" (default), "application/statuslist+cwt"
	Accept string `json:"-" header:"Accept"`
}

// TokenStatusListsResponse represents the response containing a Status List Token.
// Content-Type should be: application/statuslist+jwt or application/statuslist+cwt
type TokenStatusListsResponse struct {
	// Token is the signed Status List Token (JWT string or CWT bytes)
	Token []byte `json:"token"`

	// ContentType is the media type for the response
	ContentType string `json:"content_type"`
}

// StatusLists handles requests for Status List Tokens per draft-ietf-oauth-status-list Section 8.1.
// The endpoint returns a cached signed JWT or CWT containing the compressed status list.
//
// Query Parameters:
//   - time: Optional. Unix timestamp for historical resolution (Section 8.4).
//     If provided and historical resolution is not supported, returns an error.
//
// Content Negotiation (via Accept header):
//   - application/statuslist+jwt (default)
//   - application/statuslist+cwt
//
// Response:
//   - Content-Type: application/statuslist+jwt or application/statuslist+cwt
//   - Body: The signed Status List Token
func (c *Client) TokenStatusLists(ctx context.Context, req *TokenStatusListsRequest) (*TokenStatusListsResponse, error) {
	c.log.Debug("status_lists", "request", req)

	// Check for time parameter (historical resolution - Section 8.4)
	if req.Time != nil {
		// Historical resolution is not currently supported
		// Per Section 8.4, we should return an error if we can't provide historical data
		c.log.Info("historical resolution requested but not supported", "time", *req.Time)
		return nil, tokenstatuslist.ErrHistoricalResolutionNotSupported
	}

	// Determine response format based on Accept header (content negotiation)
	// Default to JWT if no Accept header or unrecognized value
	var token []byte
	var contentType string

	switch req.Accept {
	case tokenstatuslist.MediaTypeCWT:
		// CWT format requested - get from cache
		cwtBytes := c.tokenStatusListIssuer.GetCachedCWT(ctx, req.ID)
		if cwtBytes == nil {
			c.log.Info("CWT not found in cache", "section", req.ID)
			return nil, tokenstatuslist.ErrSectionNotFound
		}
		token = cwtBytes
		contentType = tokenstatuslist.MediaTypeCWT
	default:
		// JWT format (default) - get from cache
		jwtStr := c.tokenStatusListIssuer.GetCachedJWT(ctx, req.ID)
		if jwtStr == "" {
			c.log.Info("JWT not found in cache", "section", req.ID)
			return nil, tokenstatuslist.ErrSectionNotFound
		}
		token = []byte(jwtStr)
		contentType = tokenstatuslist.MediaTypeJWT
	}

	reply := &TokenStatusListsResponse{
		Token:       token,
		ContentType: contentType,
	}

	return reply, nil
}

// TokenStatusListJWKSRequest is the request for a status list's signing key set.
type TokenStatusListJWKSRequest struct {
	// ID is the section identifier for the status list (from URI path)
	ID int64 `json:"id" uri:"id" validate:"gte=0"`
}

// TokenStatusListJWKS returns the public signing keys of a Status List Token as
// a JWK Set, served from under the list URI itself.
//
// The Token Status List draft defines no key discovery of its own: a verifier
// is left to resolve the signer from the token (an "x5c" chain or an embedded
// "jwk") and then decide whether to trust it. Deciding that is a trust
// registry's job, and a registry that binds names to keys needs somewhere to
// read this signer's keys from. The name it has is the list URI - the token's
// "sub", and the subject every status-list trust query carries - so the keys
// are published relative to that URI rather than to the registry's origin.
//
// The path is {list URI}/.well-known/jwks.json, which is the JWKS location
// metadata discovery falls back to when no metadata document names a jwks_uri
// (RFC 8615 reserves the .well-known space for exactly this). Nothing is
// served at the origin's own .well-known: a status list signer is not the
// registry's issuing identity, and publishing it there would say it was.
//
// Returns ErrSectionNotFound for a section this registry does not serve a
// token for, so a list URI's keys exist exactly when the list does.
func (c *Client) TokenStatusListJWKS(ctx context.Context, req *TokenStatusListJWKSRequest) (*jose.JWKS, error) {
	c.log.Debug("status_list_jwks", "request", req)

	if c.tokenStatusListIssuer.GetCachedJWT(ctx, req.ID) == "" {
		c.log.Info("JWKS requested for unknown section", "section", req.ID)
		return nil, tokenstatuslist.ErrSectionNotFound
	}

	jwks, err := c.tokenStatusListIssuer.SigningKeySet(ctx)
	if err != nil {
		c.log.Error(err, "failed to build status list signing key set")
		return nil, err
	}

	return jwks, nil
}

// TokenStatusListAggregationResponse represents the Status List Aggregation response per Section 9.3.
// This provides a list of Status List Token URIs for pre-fetching and caching.
// Content-Type: application/json
type TokenStatusListAggregationResponse struct {
	// StatusLists is a JSON array of URIs linking to Status List Tokens
	StatusLists []string `json:"status_lists"`
}

// TokenStatusListAggregation handles requests for Status List Aggregation per Section 9.3.
// This endpoint returns a JSON array of URIs linking to all available Status List Tokens.
// Relying Parties can use this to pre-fetch and cache Status List Tokens.
//
// Response (JSON):
//   - status_lists: Array of URIs to Status List Tokens
//
// Per Section 9.3:
// "The Status List Aggregation URI provides a list of Status List Token URIs.
// This aggregation in JSON and the media type return MUST be application/json."
func (c *Client) TokenStatusListAggregation(ctx context.Context) (*TokenStatusListAggregationResponse, error) {
	c.log.Debug("status_list_aggregation")

	// Get all sections from the metadata
	sections, err := c.tokenStatusListIssuer.GetAllSections(ctx)
	if err != nil {
		c.log.Error(err, "failed to get all sections")
		return nil, err
	}

	// Build the list of Status List Token URIs
	statusLists := make([]string, 0, len(sections))

	for _, section := range sections {
		uri, err := url.JoinPath(c.cfg.Registry.PublicURL, "/statuslists", strconv.FormatInt(section, 10))
		if err != nil {
			c.log.Error(err, "failed to construct status list URI")
			return nil, fmt.Errorf("failed to construct status list URI: %w", err)
		}
		statusLists = append(statusLists, uri)
	}

	reply := &TokenStatusListAggregationResponse{
		StatusLists: statusLists,
	}

	c.log.Debug("status_list_aggregation", "reply", reply)

	return reply, nil
}

// SaveCredentialSubjectRequest is the request to save credential subject info
type SaveCredentialSubjectRequest struct {
	Identifier string `json:"identifier" validate:"required"`
	Section    int64  `json:"section" validate:"gte=0"`
	Index      int64  `json:"index" validate:"gte=0"`
}

// SaveCredentialSubject saves credential subject info linked to a Token Status List entry
func (c *Client) SaveCredentialSubject(ctx context.Context, req *SaveCredentialSubjectRequest) error {
	if c.credentialSubjects == nil {
		c.log.Debug("credential subjects store not configured, skipping save")
		return nil
	}

	doc := &db.CredentialSubjectDoc{
		Identifier: req.Identifier,
		Section:    req.Section,
		Index:      req.Index,
	}

	if err := c.credentialSubjects.Add(ctx, doc); err != nil {
		c.log.Error(err, "failed to save credential subject", "section", req.Section, "index", req.Index)
		return err
	}

	c.log.Debug("saved credential subject", "identifier", req.Identifier, "section", req.Section, "index", req.Index)
	return nil
}
