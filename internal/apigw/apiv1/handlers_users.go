package apiv1

import (
	"context"
	"fmt"
	"net/url"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/sdjwtvc"
	"github.com/SUNET/vc/pkg/vcclient"
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
	}

	c.log.Debug("UserLookup", "auth", authorizationContext)

	redirectURL, err := url.Parse(authorizationContext.WalletURI)
	if err != nil {
		c.log.Error(err, "failed to parse redirect URI", "redirect_uri", authorizationContext.WalletURI)
		return nil, fmt.Errorf("failed to parse redirect URI %s: %w", authorizationContext.WalletURI, err)
	}

	redirectURL.RawQuery = url.Values{"code": {authorizationContext.Code}, "state": {authorizationContext.State}}.Encode()

	svgTemplateClaims := map[string]vcclient.SVGClaim{}

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

		doc, err := firstDocument(docs)
		if err != nil {
			c.log.Error(err, "no usable document in cache")
			return nil, err
		}
		c.log.Debug("userLookup", "authenticSource", doc.Meta.AuthenticSource, "docs", docs)

		jsonPaths, err := req.VCTM.ClaimJSONPath()
		if err != nil {
			c.log.Error(err, "failed to get JSON paths from VCTM claims")
			return nil, err
		}

		c.log.Debug("userLookup", "doc", doc, "jsonPath", jsonPaths)

		claimValues, err := sdjwtvc.ExtractClaimsByJSONPath(doc.DocumentData, jsonPaths.Displayable)
		if err != nil {
			c.log.Error(err, "failed to extract claim values from document data", "json_paths", jsonPaths.Displayable, "document_data", doc.DocumentData)
			return nil, fmt.Errorf("failed to extract claim values from document data: %w", err)
		}

		c.log.Debug("extracted claim values", "extracted_count", len(claimValues), "requested_count", len(jsonPaths.Displayable), "claims", claimValues)

		for _, claim := range req.VCTM.Claims {
			if claim.SVGID != "" {
				value, ok := claimValues[claim.SVGID].(string)
				if !ok {
					continue
				}
				svgTemplateClaims[claim.SVGID] = vcclient.SVGClaim{
					Label: claim.Display[0].Label,
					Value: value,
				}
			} else if len(claim.Display) > 0 {
				// No svg_id — fall back to extracting claim value from document data by path
				key := claim.JSONPath()
				if value := findValueByName(doc.DocumentData, claim.Path); value != nil {
					svgTemplateClaims[key] = vcclient.SVGClaim{
						Label: claim.Display[0].Label,
						Value: value,
					}
				}
			}
		}

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

		doc, err := firstDocument(docs)
		if err != nil {
			c.log.Error(err, "no usable document in cache for SAML/OIDC session")
			return nil, err
		}

		jsonPaths, err := req.VCTM.ClaimJSONPath()
		if err != nil {
			c.log.Error(err, "failed to get JSON paths from VCTM claims")
			return nil, err
		}

		claimValues, err := sdjwtvc.ExtractClaimsByJSONPath(doc.DocumentData, jsonPaths.Displayable)
		if err != nil {
			c.log.Error(err, "failed to extract claim values from document data",
				"json_paths", jsonPaths.Displayable, "document_data", doc.DocumentData)
			return nil, fmt.Errorf("failed to extract claim values from document data: %w", err)
		}

		if len(claimValues) == 0 && len(jsonPaths.Displayable) > 0 {
			// Log diagnostic info when JSONPath extraction finds nothing.
			// This typically means the attribute_mappings don't produce the
			// claim keys expected by the VCTM (check svg_id / path alignment).
			docKeys := make([]string, 0, len(doc.DocumentData))
			for k := range doc.DocumentData {
				docKeys = append(docKeys, k)
			}
			c.log.Warn("no claims extracted: document data keys do not match VCTM JSONPaths",
				"document_data_keys", docKeys,
				"json_paths", jsonPaths.Displayable)
		} else {
			c.log.Debug("extracted claim values",
				"extracted_count", len(claimValues),
				"requested_count", len(jsonPaths.Displayable),
				"claims", claimValues)
		}

		for _, claim := range req.VCTM.Claims {
			if claim.SVGID != "" {
				value, ok := claimValues[claim.SVGID].(string)
				if !ok {
					// JSONPath extraction missed this claim — try direct lookup as fallback.
					// SVG-template claims must be strings to be substitutable.
					if s, ok := findValueByName(doc.DocumentData, claim.Path).(string); ok && s != "" {
						svgTemplateClaims[claim.SVGID] = vcclient.SVGClaim{
							Label: claim.Display[0].Label,
							Value: s,
						}
					}
					continue
				}
				svgTemplateClaims[claim.SVGID] = vcclient.SVGClaim{
					Label: claim.Display[0].Label,
					Value: value,
				}
			} else if len(claim.Display) > 0 {
				// No svg_id — fall back to extracting claim value from document data by path
				key := claim.JSONPath()
				if value := findValueByName(doc.DocumentData, claim.Path); value != nil {
					svgTemplateClaims[key] = vcclient.SVGClaim{
						Label: claim.Display[0].Label,
						Value: value,
					}
				}
			}
		}

	default:
		return nil, fmt.Errorf("unsupported auth method for user lookup: %s", req.AuthProvider)
	}

	c.log.Debug("lookupUser", "svgTemplateClaims", svgTemplateClaims)

	if err := c.cacheService.AuthContext.Consent(ctx, &cache.AuthorizationContext{RequestURI: req.RequestURI}); err != nil {
		c.log.Error(err, "failed to consent for user")
		return nil, fmt.Errorf("failed to consent: %w", err)
	}

	reply := &vcclient.UserLookupReply{
		SVGTemplateClaims: svgTemplateClaims,
		RedirectURL:       redirectURL.String(),
	}

	c.log.Debug("userlookup", "reply", reply)

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

// findValueByName searches the document data for a claim value matching
// the VCTM claim path. It first tries an exact JSONPath-style lookup,
// then falls back to searching recursively by the leaf key name.
// Returns the raw value (string, map, slice, ...) so that the consent UI
// can render nested structures as a tree. Returns nil if not found.
func findValueByName(data map[string]any, path []*string) any {
	if len(path) == 0 {
		return nil
	}

	// Walk the path through nested maps
	var current any = data
	for _, p := range path {
		if p == nil {
			break
		}
		m, ok := current.(map[string]any)
		if !ok {
			break
		}
		current, ok = m[*p]
		if !ok {
			// Exact path failed — try recursive search by leaf key name
			leafKey := *path[len(path)-1]
			return findValueRecursive(data, leafKey)
		}
	}

	return current
}

// findValueRecursive searches a nested map for the first value matching key.
// Returns nil if not found.
func findValueRecursive(data map[string]any, key string) any {
	if v, ok := data[key]; ok {
		return v
	}
	for _, v := range data {
		if nested, ok := v.(map[string]any); ok {
			if result := findValueRecursive(nested, key); result != nil {
				return result
			}
		}
	}
	return nil
}
