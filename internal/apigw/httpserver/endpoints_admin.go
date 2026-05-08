package httpserver

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/SUNET/vc/internal/apigw/apiv1"
	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
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
	session.Set("admin_id_token", reply.RawIDToken)

	// Derive unique authentic sources for search filtering
	sourceSet := map[string]struct{}{}
	for _, r := range reply.AllowedResources {
		sourceSet[r.AuthenticSource] = struct{}{}
	}
	allowedSources := make([]string, 0, len(sourceSet))
	for s := range sourceSet {
		allowedSources = append(allowedSources, s)
	}
	session.Set("admin_allowed_authentic_sources", allowedSources)

	// Store full resource+scope pairs as JSON for the status API
	type pair struct {
		AuthenticSource string `json:"authentic_source"`
		Scope           string `json:"scope"`
	}
	pairs := make([]pair, len(reply.AllowedResources))
	for i, r := range reply.AllowedResources {
		pairs[i] = pair{AuthenticSource: r.AuthenticSource, Scope: r.Scope}
	}
	pairsJSON, _ := json.Marshal(pairs)
	session.Set("admin_allowed_resources_json", string(pairsJSON))

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

		// Parse allowed resource+scope pairs from session
		var allowedResources []map[string]string
		if raw, ok := session.Get("admin_allowed_resources_json").(string); ok && raw != "" {
			_ = json.Unmarshal([]byte(raw), &allowedResources)
		}

		var scopes []string
		scopeTemplates := map[string]any{}
		if s.cfg.Common != nil {
			for scope, cm := range s.cfg.Common.CredentialMetadata {
				scopes = append(scopes, scope)
				if cm != nil && cm.VCTM != nil {
					scopeTemplates[scope] = buildClaimTemplate(cm.VCTM.Claims)
				}
			}
		}
		return gin.H{"authenticated": true, "subject": subject, "allowed_resources": allowedResources, "scopes": scopes, "scope_templates": scopeTemplates}, nil
	}
	return gin.H{"authenticated": false}, nil
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
	var idToken string
	if v, ok := session.Get("admin_id_token").(string); ok {
		idToken = v
	}
	session.Clear()
	_ = session.Save()

	logoutURL := s.apiv1.AdminLogoutURL(idToken)
	return gin.H{"ok": true, "logout_url": logoutURL}, nil
}
