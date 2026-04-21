package apiv1

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/sdjwtvc"
	"github.com/SUNET/vc/pkg/vcclient"

	"golang.org/x/crypto/bcrypt"
)

func (c *Client) AddPIDUser(ctx context.Context, req *vcclient.AddPIDRequest) error {
	// store user and password in the database before document is saved - to check constraints that the user not already exists
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	err = c.usersStore.Save(ctx, &model.OAuthUsers{
		Username:        req.Username,
		Password:        string(passwordHash),
		Identity:        req.Identity,
		AuthenticSource: req.Meta.AuthenticSource,
	})
	if err != nil {
		c.log.Error(err, "failed to save user")
		return err
	}

	return nil
}

func (c *Client) LoginPIDUser(ctx context.Context, req *vcclient.LoginPIDUserRequest) error {
	username := strings.ToLower(req.Username)

	c.log.Debug("LoginPIDUser called", "username", username)
	user, err := c.usersStore.GetUser(ctx, username)
	if err != nil {
		return fmt.Errorf("username %s not found", username)
	}

	if err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		return fmt.Errorf("password mismatch for username %s", username)
	}

	update := &cache.AuthorizationContext{
		Identity:        user.Identity,
		AuthenticSource: user.AuthenticSource,
	}
	// Update the authorization with the user identity
	if err := c.cacheService.AuthContext.AddIdentity(ctx, &cache.AuthorizationContext{RequestURI: req.RequestURI}, update); err != nil {
		c.log.Error(err, "failed to add identity to authorization context")
		return err
	}

	return nil

}

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

func (c *Client) UserLookup(ctx context.Context, req *vcclient.UserLookupRequest) (*vcclient.UserLookupReply, error) {
	c.log.Debug("UserLookup called")

	authorizationContext, err := c.cacheService.AuthContext.Get(ctx, &cache.AuthorizationContext{
		RequestURI: req.RequestURI,
	})
	if err != nil {
		c.log.Error(err, "failed to get authorization for user", "request_uri", req.RequestURI)
	}

	c.log.Debug("LoginPIDUser", "auth", authorizationContext)

	redirectURL, err := url.Parse(authorizationContext.WalletURI)
	if err != nil {
		c.log.Error(err, "failed to parse redirect URI", "redirect_uri", authorizationContext.WalletURI)
		return nil, fmt.Errorf("failed to parse redirect URI %s: %w", authorizationContext.WalletURI, err)
	}

	redirectURL.RawQuery = url.Values{"code": {authorizationContext.Code}, "state": {authorizationContext.State}}.Encode()

	svgTemplateClaims := map[string]vcclient.SVGClaim{}

	switch req.AuthMethod {
	case model.AuthMethodBasic:
		user, err := c.usersStore.GetUser(ctx, strings.ToLower(req.Username))
		if err != nil {
			c.log.Error(err, "failed to get user", "username", strings.ToLower(req.Username))
			return nil, fmt.Errorf("user %s not found: %w", strings.ToLower(req.Username), err)
		}

		svgTemplateClaims = map[string]vcclient.SVGClaim{
			"given_name": {
				Label: "Given name",
				Value: user.Identity.GivenName,
			},
			"family_name": {
				Label: "Family name",
				Value: user.Identity.FamilyName,
			},
			"birth_date": {
				Label: "Birth date",
				Value: user.Identity.BirthDate,
			},
			"expiry_date": {
				Label: "Expiry date",
				Value: user.Identity.ExpiryDate,
			},
		}

	case model.AuthMethodOpenID4VP:
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
				if value := findValueByName(doc.DocumentData, claim.Path); value != "" {
					svgTemplateClaims[key] = vcclient.SVGClaim{
						Label: claim.Display[0].Label,
						Value: value,
					}
				}
			}
		}

	case model.AuthMethodSAML, model.AuthMethodOIDC:
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
			// This typically means the credential_mappings don't produce the
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
					// JSONPath extraction missed this claim — try direct lookup as fallback
					if value := findValueByName(doc.DocumentData, claim.Path); value != "" {
						svgTemplateClaims[claim.SVGID] = vcclient.SVGClaim{
							Label: claim.Display[0].Label,
							Value: value,
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
				if value := findValueByName(doc.DocumentData, claim.Path); value != "" {
					svgTemplateClaims[key] = vcclient.SVGClaim{
						Label: claim.Display[0].Label,
						Value: value,
					}
				}
			}
		}

	default:
		return nil, fmt.Errorf("unsupported auth method for user lookup: %s", req.AuthMethod)
	}

	c.log.Debug("lookupUser", "svgTemplateClaims", svgTemplateClaims)

	if err := c.cacheService.AuthContext.Consent(ctx, &cache.AuthorizationContext{RequestURI: req.RequestURI}); err != nil {
		c.log.Error(err, "failed to consent for user", "username", req.Username)
		return nil, fmt.Errorf("failed to consent for user %s: %w", req.Username, err)
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
func findValueByName(data map[string]any, path []*string) string {
	if len(path) == 0 {
		return ""
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

	if s, ok := current.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", current)
}

// findValueRecursive searches a nested map for the first string value matching key.
func findValueRecursive(data map[string]any, key string) string {
	if v, ok := data[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
		return fmt.Sprintf("%v", v)
	}
	for _, v := range data {
		if nested, ok := v.(map[string]any); ok {
			if result := findValueRecursive(nested, key); result != "" {
				return result
			}
		}
	}
	return ""
}
