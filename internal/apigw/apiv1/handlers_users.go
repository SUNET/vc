package apiv1

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"vc/pkg/cache"
	"vc/pkg/model"
	"vc/pkg/sdjwtvc"
	"vc/pkg/vcclient"

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

	case model.AuthMethodPID:
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

		// TODO(masv): fix this monstrosity
		authenticSource := ""
		for key, doc := range docs {
			c.log.Debug("userLookup - examining doc", "key", key, "authentic_source", doc.Meta.AuthenticSource, "doc_nil", doc == nil)
			authenticSource = doc.Meta.AuthenticSource
			break
		}
		c.log.Debug("userLookup", "authenticSource", authenticSource, "docs", docs)

		doc, ok := docs[authenticSource]
		if !ok {
			c.log.Error(nil, "no document found for authentic source", "authenticSource", authenticSource, "available_keys", func() []string {
				keys := make([]string, 0, len(docs))
				for k := range docs {
					keys = append(keys, k)
				}
				return keys
			}())
			return nil, fmt.Errorf("no document found for authentic source %s", authenticSource)
		}
		c.log.Debug("userLookup", "doc", doc)

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
			value, ok := claimValues[claim.SVGID].(string)
			if !ok {
				continue
			}

			if claim.SVGID != "" {
				svgTemplateClaims[claim.SVGID] = vcclient.SVGClaim{
					Label: claim.Display[0].Label,
					Value: value,
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

		// Extract the first document (same approach as pid_auth)
		authenticSource := ""
		for key, doc := range docs {
			c.log.Debug("userLookup - examining doc", "key", key,
				"authentic_source", doc.Meta.AuthenticSource, "doc_nil", doc == nil)
			authenticSource = doc.Meta.AuthenticSource
			break
		}

		doc, ok := docs[authenticSource]
		if !ok {
			return nil, fmt.Errorf("no document found for authentic source %s", authenticSource)
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

		c.log.Debug("extracted claim values",
			"extracted_count", len(claimValues),
			"requested_count", len(jsonPaths.Displayable),
			"claims", claimValues)

		for _, claim := range req.VCTM.Claims {
			value, ok := claimValues[claim.SVGID].(string)
			if !ok {
				continue
			}

			if claim.SVGID != "" {
				svgTemplateClaims[claim.SVGID] = vcclient.SVGClaim{
					Label: claim.Display[0].Label,
					Value: value,
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
