package httpserver

import (
	"context"
	"net/http"

	"github.com/SUNET/vc/internal/apigw/apiv1"
	"github.com/SUNET/vc/pkg/httphelpers"
	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/codes"
)

const adminSessionKey = "admin_authenticated"

func (s *Service) endpointAdminUI(ctx context.Context, c *gin.Context) (any, error) {
	c.HTML(http.StatusOK, "admin.html", nil)
	return nil, nil
}

// endpointAdminLogin redirects the browser to the OIDC provider's authorization endpoint.
// When no OIDC is configured, it creates a full-access session immediately.
func (s *Service) endpointAdminLogin(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointAdminLogin")
	defer span.End()

	reply, err := s.apiv1.AdminLoginURL(ctx)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// No OIDC configured — grant full access without authentication
	if reply.AuthURL == "" {
		session := sessions.Default(c)
		session.Set(adminSessionKey, true)
		session.Set("admin_subject", "anonymous")
		if err := session.Save(); err != nil {
			span.SetStatus(codes.Error, err.Error())
			return nil, err
		}
		c.Redirect(http.StatusFound, "/ui")
		return nil, nil
	}

	session := sessions.Default(c)
	session.Set("oidc_state", reply.State)
	if err := session.Save(); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	c.Redirect(http.StatusFound, reply.AuthURL)
	return nil, nil
}

// endpointAdminCallback handles the OIDC callback, delegates token exchange
// to apiv1, and creates an admin session.
func (s *Service) endpointAdminCallback(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointAdminCallback")
	defer span.End()

	session := sessions.Default(c)
	savedState, ok := session.Get("oidc_state").(string)
	if !ok || savedState == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing or invalid session state"})
		return nil, nil
	}

	request := &apiv1.AdminCallbackRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	if savedState != request.State {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid state parameter"})
		return nil, nil
	}
	session.Delete("oidc_state")
	if err := session.Save(); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	reply, err := s.apiv1.AdminCallback(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "admin_oidc_callback_failed")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication failed"})
		return nil, nil
	}

	session.Set(adminSessionKey, true)
	session.Set("admin_subject", reply.Subject)

	// Store the raw ID token server-side in the cache instead of the cookie
	// session to avoid exceeding the ~4 KB cookie size limit and to reduce
	// exposure of sensitive token material to the client.
	if reply.RawIDToken != "" {
		tokenRef := uuid.NewString()
		s.cacheService.AdminIDToken.Set(ctx, tokenRef, reply.RawIDToken)
		session.Set("admin_id_token_ref", tokenRef)
	}

	if err := session.Save(); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	c.Redirect(http.StatusFound, "/ui")
	return nil, nil
}

func (s *Service) endpointAdminStatus(ctx context.Context, c *gin.Context) (any, error) {
	session := sessions.Default(c)
	if auth := session.Get(adminSessionKey); auth == true {
		subject, _ := session.Get("admin_subject").(string)

		var allScopes []string
		scopeTemplates := map[string]any{}
		if s.cfg.Common != nil {
			for scope, cm := range s.cfg.Common.CredentialMetadata {
				allScopes = append(allScopes, scope)
				if cm != nil && cm.VCTM != nil {
					scopeTemplates[scope] = buildClaimTemplate(cm.VCTM.Claims)
				}
			}
		}

		// Resolve allowed resources from SPOCP rules.
		allowedSources := httphelpers.AllowedAuthenticSources(s.spocpEngine, subject)
		pairs := httphelpers.ResolveAllowedResources(s.spocpEngine, subject)

		// When allowedSources is nil (wildcard rule = unrestricted),
		// fetch all authentic sources from the database for the UI dropdown.
		if allowedSources == nil {
			if dbSources, err := s.apiv1.ListAuthenticSources(ctx); err == nil && len(dbSources) > 0 {
				allowedSources = dbSources
			}
		}

		// Filter scopes to only those the user is allowed to access.
		scopes := filterAllowedScopes(allScopes, pairs)

		return gin.H{
			"authenticated":             true,
			"subject":                   subject,
			"scopes":                    scopes,
			"scope_templates":           scopeTemplates,
			"allowed_authentic_sources": allowedSources,
			"has_identity_mapping":      hasIdentityMappingScope(pairs),
		}, nil
	}
	return gin.H{"authenticated": false}, nil
}

// filterAllowedScopes returns only configured scopes that the user's SPOCP rules permit.
// If pairs is empty (no resource constraints) or any pair has Scope "*", all scopes are returned.
func filterAllowedScopes(allScopes []string, pairs []httphelpers.ResourcePair) []string {
	if len(pairs) == 0 {
		return allScopes
	}
	allowed := map[string]bool{}
	for _, p := range pairs {
		if p.Scope == "*" {
			return allScopes
		}
		allowed[p.Scope] = true
	}
	var result []string
	for _, s := range allScopes {
		if allowed[s] {
			result = append(result, s)
		}
	}
	return result
}

// hasIdentityMappingScope returns true when the SPOCP pairs grant the
// synthetic "identity_mapping" scope (or a wildcard that covers it).
func hasIdentityMappingScope(pairs []httphelpers.ResourcePair) bool {
	if len(pairs) == 0 {
		return true // no resource constraints — unrestricted
	}
	for _, p := range pairs {
		if p.Scope == "*" || p.Scope == "identity_mapping" {
			return true
		}
	}
	return false
}

// buildClaimTemplate creates a nested map from VCTM claims with empty string values
func buildClaimTemplate(claims []sdjwtvc.Claim) map[string]any {
	result := map[string]any{}
	for _, claim := range claims {
		if len(claim.Path) == 0 {
			continue
		}
		current := result
		for i, p := range claim.Path {
			if p == nil {
				continue
			}
			if i == len(claim.Path)-1 {
				// Leaf — only set placeholder if not already a nested map
				if _, ok := current[*p].(map[string]any); !ok {
					current[*p] = ""
				}
			} else {
				// Intermediate — ensure nested map exists
				if existing, ok := current[*p]; !ok {
					current[*p] = map[string]any{}
				} else if _, ok := existing.(map[string]any); !ok {
					// Overwrite leaf placeholder with nested map
					current[*p] = map[string]any{}
				}
				if nested, ok := current[*p].(map[string]any); ok {
					current = nested
				}
			}
		}
	}
	return result
}

func (s *Service) endpointAdminLogout(ctx context.Context, c *gin.Context) (any, error) {
	session := sessions.Default(c)

	// Retrieve the raw ID token from the server-side cache using the opaque
	// reference stored in the cookie session.
	var idToken string
	if ref, ok := session.Get("admin_id_token_ref").(string); ok && ref != "" {
		if v, found := s.cacheService.AdminIDToken.Get(ctx, ref); found {
			idToken = v
		}
		s.cacheService.AdminIDToken.Delete(ctx, ref)
	}

	session.Clear()
	_ = session.Save()

	logoutURL := s.apiv1.AdminLogoutURL(idToken)
	return gin.H{"ok": true, "logout_url": logoutURL}, nil
}
