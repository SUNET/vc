package apiv1

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"vc/internal/registry/db"
	"vc/pkg/tokenstatuslist"
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
		cwtBytes := c.tokenStatusListIssuer.GetCachedCWT(req.ID)
		if cwtBytes == nil {
			c.log.Info("CWT not found in cache", "section", req.ID)
			return nil, tokenstatuslist.ErrSectionNotFound
		}
		token = cwtBytes
		contentType = tokenstatuslist.MediaTypeCWT
	default:
		// JWT format (default) - get from cache
		jwtStr := c.tokenStatusListIssuer.GetCachedJWT(req.ID)
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
	FirstName   string `json:"first_name" validate:"required"`
	LastName    string `json:"last_name" validate:"required"`
	DateOfBirth string `json:"date_of_birth" validate:"required"`
	Section     int64  `json:"section" validate:"gte=0"`
	Index       int64  `json:"index" validate:"gte=0"`
}

// SaveCredentialSubject saves credential subject info linked to a Token Status List entry
func (c *Client) SaveCredentialSubject(ctx context.Context, req *SaveCredentialSubjectRequest) error {
	if c.credentialSubjects == nil {
		c.log.Debug("credential subjects store not configured, skipping save")
		return nil
	}

	doc := &db.CredentialSubjectDoc{
		FirstName:   req.FirstName,
		LastName:    req.LastName,
		DateOfBirth: req.DateOfBirth,
		Section:     req.Section,
		Index:       req.Index,
	}

	if err := c.credentialSubjects.Add(ctx, doc); err != nil {
		c.log.Error(err, "failed to save credential subject", "section", req.Section, "index", req.Index)
		return err
	}

	c.log.Debug("saved credential subject", "first_name", req.FirstName, "last_name", req.LastName, "section", req.Section, "index", req.Index)
	return nil
}
