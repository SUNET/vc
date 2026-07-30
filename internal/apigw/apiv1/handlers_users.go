package apiv1

import (
	"context"
	"fmt"
	"net/url"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/sdjwtvc"
	"github.com/SUNET/vc/pkg/vcclient"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// UserAuthenticSourceLookup resolves which authentic sources are available for a session,
// or sets the selected authentic source on the authorization context.
func (c *Client) UserAuthenticSourceLookup(ctx context.Context, req *vcclient.UserAuthenticSourceLookupRequest) (*vcclient.UserAuthenticSourceLookupReply, error) {
	c.log.Debug("UserAuthenticSource called")

	if req.AuthenticSource == "" && req.SessionID != "" {
		c.log.Debug("userAuthenticSourceLookup called without authentic source, looking up by session ID", "session_id", req.SessionID)
		authorizationContext, err := c.cacheService.AuthContext.Get(ctx, &cache.AuthorizationContext{
			SessionID: req.SessionID,
		})
		if err != nil {
			c.log.Error(err, "failed to get authorization context for authentic source lookup")
			return nil, err
		}

		docs, ok := c.cacheService.Document.Get(ctx, authorizationContext.SessionID)
		if !ok {
			c.log.Error(nil, "no documents found in cache for session", "session_id", req.SessionID)
			return nil, fmt.Errorf("no documents found for session %s", req.SessionID)
		}

		authenticSources := []string{}

		for _, doc := range docs {
			authenticSources = append(authenticSources, doc.Meta.AuthenticSource)
		}

		reply := &vcclient.UserAuthenticSourceLookupReply{
			AuthenticSources: authenticSources,
		}

		return reply, nil

	} else if req.AuthenticSource != "" {
		c.log.Debug("userAuthenticSourceLookup called with authentic source", "authentic_source", req.AuthenticSource)
		if err := c.cacheService.AuthContext.SetAuthenticSource(ctx, &cache.AuthorizationContext{SessionID: req.SessionID}, req.AuthenticSource); err != nil {
			c.log.Error(err, "failed to set authentic source")
			return nil, fmt.Errorf("failed to set authentic source %s: %w", req.AuthenticSource, err)
		}
	}

	return nil, nil
}

// UserLookup resolves the authenticated user's displayable claims for the credential preview (SVG template).
// It retrieves data differently depending on the auth provider: from the verifier session cache for OpenID4VP,
// or from the VCI session cache for SAML/OIDC.
// After collecting the claims it marks the authorization context as consented and returns the wallet redirect URL.
func (c *Client) UserLookup(ctx context.Context, req *vcclient.UserLookupRequest) (*vcclient.UserLookupReply, error) {
	c.log.Debug("UserLookup called")

	authorizationContext, err := c.cacheService.AuthContext.Get(ctx, &cache.AuthorizationContext{
		RequestURI: req.RequestURI,
	})
	if err != nil {
		c.log.Error(err, "failed to get authorization for user", "request_uri", req.RequestURI)
		return nil, err
	}

	c.log.Debug("UserLookup", "auth", authorizationContext)

	redirectResult, err := buildAuthorizationRedirectURL(authorizationContext.WalletURI, authorizationContext.Code, authorizationContext.State, c.cfg.APIGW.PublicURL)
	if err != nil {
		c.log.Error(err, "failed to build redirect URL", "redirect_uri", authorizationContext.WalletURI)
		return nil, err
	}

	var svgTemplateClaims map[string]sdjwtvc.SVGValue
	var presentationClaims map[string]any
	var doc *model.CompleteDocument

	switch req.AuthProvider {
	case model.AuthProviderOpenID4VP:
		authorizationContext, err := c.cacheService.AuthContext.Get(ctx, &cache.AuthorizationContext{VerifierResponseCode: req.ResponseCode})
		if err != nil {
			c.log.Error(err, "failed to get authorization context")
			return nil, err
		}

		docs, ok := c.cacheService.Document.Get(ctx, authorizationContext.SessionID)
		if !ok || len(docs) == 0 {
			c.log.Error(nil, "no documents found in cache for session")
			return nil, fmt.Errorf("no documents found for session %s", authorizationContext.SessionID)
		}

		c.log.Debug("userLookup - retrieved docs from cache", "session_id", authorizationContext.SessionID, "num_docs", len(docs))

		doc, err = firstDocument(docs)
		if err != nil {
			c.log.Error(err, "no usable document in cache")
			return nil, err
		}
		c.log.Debug("userLookup", "authenticSource", doc.Meta.AuthenticSource, "docs", docs)

	case model.AuthProviderSAML, model.AuthProviderOIDC:
		// For SAML/OIDC, documents are stored in the VCI session cache by the
		// ACS/callback handlers, keyed by the authorization context's session ID.
		// No verifier response_code lookup is needed — we use the session ID directly.
		docs, ok := c.cacheService.Document.Get(ctx, authorizationContext.SessionID)
		if !ok || len(docs) == 0 {
			c.log.Error(nil, "no documents found in cache for SAML/OIDC session",
				"session_id", authorizationContext.SessionID)
			return nil, fmt.Errorf("no documents found for session %s", authorizationContext.SessionID)
		}

		c.log.Debug("userLookup - retrieved SAML/OIDC docs from cache",
			"session_id", authorizationContext.SessionID, "num_docs", len(docs))

		var err error
		doc, err = firstDocument(docs)
		if err != nil {
			c.log.Error(err, "no usable document in cache for SAML/OIDC session")
			return nil, err
		}

	default:
		return nil, fmt.Errorf("unsupported auth method for user lookup: %s", req.AuthProvider)
	}

	// Normalize bson.D/bson.A values to map[string]any/[]any so that
	// Presentation() and SVGValues() can traverse nested documents.
	for k, v := range doc.DocumentData {
		doc.DocumentData[k] = normalizeBSONValue(v)
	}

	// req.VCTM is nil for mso_mdoc scopes (GetVCTMFromScope only returns a
	// VCTM for sd-jwt-based credentials) - use the MDDL schema's own
	// Presentation instead. mso_mdoc has no SVG-template concept, so
	// svgTemplateClaims stays empty in that case.
	switch {
	case req.VCTM != nil:
		presentationClaims = req.VCTM.Presentation(doc.DocumentData)
		svgTemplateClaims = req.VCTM.SVGValues(doc.DocumentData)
	case req.MDDL != nil:
		presentationClaims = req.MDDL.Presentation(doc.DocumentData)
	}

	if svgTemplateClaims == nil {
		svgTemplateClaims = map[string]sdjwtvc.SVGValue{}
	}
	if presentationClaims == nil {
		presentationClaims = map[string]any{}
	}

	c.log.Debug("lookupUser", "svgTemplateClaimCount", len(svgTemplateClaims), "presentationClaimCount", len(presentationClaims))

	if err := c.cacheService.AuthContext.Consent(ctx, &cache.AuthorizationContext{RequestURI: req.RequestURI}); err != nil {
		c.log.Error(err, "failed to consent for user")
		return nil, fmt.Errorf("failed to consent: %w", err)
	}

	reply := &vcclient.UserLookupReply{
		SVGTemplateClaims:  svgTemplateClaims,
		PresentationClaims: presentationClaims,
		RedirectURL:        redirectResult,
	}

	return reply, nil
}

// firstDocument returns the single document from the cache map.
// Returns an error if the map is empty or any entry is nil/incomplete.
func firstDocument(docs map[string]*model.CompleteDocument) (*model.CompleteDocument, error) {
	for key, doc := range docs {
		if doc == nil || doc.Meta == nil || doc.DocumentData == nil {
			return nil, fmt.Errorf("cached document for key %q is nil or has no data", key)
		}
		return doc, nil
	}
	return nil, fmt.Errorf("no documents in cache")
}

// normalizeBSONValue recursively converts bson.D values to map[string]any
// so that downstream code (e.g. walkPath in VCTM.Presentation) can traverse
// nested documents with plain Go type assertions.
// The MongoDB driver v2 decodes nested BSON documents inside any-typed fields
// as bson.D rather than map[string]any.
func normalizeBSONValue(v any) any {
	switch val := v.(type) {
	case bson.D:
		m := make(map[string]any, len(val))
		for _, e := range val {
			m[e.Key] = normalizeBSONValue(e.Value)
		}
		return m
	case map[string]any:
		for k, elem := range val {
			val[k] = normalizeBSONValue(elem)
		}
		return val
	case []any:
		for i, elem := range val {
			val[i] = normalizeBSONValue(elem)
		}
		return val
	case bson.A:
		m := make([]any, len(val))
		for i, elem := range val {
			m[i] = normalizeBSONValue(elem)
		}
		return m
	default:
		return v
	}
}

// buildAuthorizationRedirectURL constructs the authorization response redirect URL
// by preserving existing query parameters and appending code, state, and iss.
func buildAuthorizationRedirectURL(walletURI, code, state, issuer string) (string, error) {
	redirectURL, err := url.Parse(walletURI)
	if err != nil {
		return "", fmt.Errorf("failed to parse redirect URI %s: %w", walletURI, err)
	}

	q, parseErr := url.ParseQuery(redirectURL.RawQuery)
	if parseErr != nil {
		return "", fmt.Errorf("malformed query in redirect URI: %w", parseErr)
	}
	q.Set("code", code)
	q.Set("state", state)
	q.Set("iss", issuer)
	redirectURL.RawQuery = q.Encode()
	return redirectURL.String(), nil
}
