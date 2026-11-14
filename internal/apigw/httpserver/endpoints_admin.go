package httpserver

import (
	"context"
	"net/http"

	"github.com/SUNET/vc/internal/apigw/apiv1"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/resourcereach"
	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/codes"
)

const adminSessionKey = "admin_authenticated"

// anonymousAdminSubject is the admin_subject /ui/login grants when no OIDC
// is configured.
const anonymousAdminSubject = "anonymous"

// spocpService is the service name in the SPOCP rules of this service.
const spocpService = "apigw"

func (s *Service) endpointAdminUI(ctx context.Context, c *gin.Context) (any, error) {
	c.HTML(http.StatusOK, "admin.html", nil)
	return nil, nil
}

// endpointAdminLogin redirects the browser to the OIDC provider's authorization endpoint.
// When no OIDC is configured, grants anonymous access (the UI must be explicitly enabled via config).
func (s *Service) endpointAdminLogin(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointAdminLogin")
	defer span.End()

	reply, err := s.apiv1.AdminLoginURL(ctx)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// No OIDC configured — grant anonymous admin access.
	if reply.AuthURL == "" {
		session := sessions.Default(c)
		session.Set(adminSessionKey, true)
		session.Set("admin_subject", anonymousAdminSubject)
		// CSRFProtection rejects any state-changing request from a session
		// that has no csrf_token; without this the anonymous admin UI can
		// GET but never POST/PUT/DELETE.
		session.Set("csrf_token", uuid.NewString())
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

	// Generate CSRF token for the session.
	session.Set("csrf_token", uuid.NewString())

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

		// This page serves every route, so it shows the union over all of them.
		reach, err := resourcereach.ResolveOnAnyRoute(s.spocpEngine, spocpService, subject)
		if err != nil {
			return nil, err
		}

		// A source form other than an atom is known through the stored sources.
		var storedSources []string
		if !reach.Nothing() {
			storedSources, err = s.apiv1.ListAuthenticSources(ctx)
			if err != nil {
				s.log.Error(err, "admin status: list authentic sources")
			}
		}
		allowedSources := reach.SourcesAmong(storedSources)

		// Filter scopes to only those the user is allowed to access.
		scopes := filterAllowedScopes(allScopes, reach)

		// Determine if running without authentication (anonymous mode).
		authEnabled := s.cfg.APIGW != nil && (s.cfg.APIGW.APIServer.APIAuth.OIDC.Enable || s.cfg.APIGW.APIServer.APIAuth.JWKS.Enable)

		// Scopes eligible for the datastore pre-authorized offer UI action.
		preauthScopes := []string{}
		if s.cfg.APIGW != nil {
			for scope, cred := range s.cfg.APIGW.DataSources.Datastore.Scopes {
				// Mirrors requirePreAuthScope: a scope qualifies either by
				// being a preauth twin or by carrying allow_preauth_offer.
				// Listing only the twins would hide the Offer action for
				// exactly the scopes this flag exists to serve, and
				// admin.js refuses them locally before any request is
				// made - so migrating away from a twin would have removed
				// the UI workflow even though the handler accepts it.
				if cred.AuthProvider == model.AuthProviderPreAuth || cred.AllowPreAuthOffer {
					preauthScopes = append(preauthScopes, scope)
				}
			}
		}

		return gin.H{
			"authenticated":             true,
			"subject":                   subject,
			"scopes":                    scopes,
			"scope_templates":           scopeTemplates,
			"allowed_authentic_sources": allowedSources,
			"has_identity_mapping":      reach.ReachesScope(resourcereach.IdentityMappingScope),
			"csrf_token":                session.Get("csrf_token"),
			"unrestricted":              !authEnabled,
			"preauth_scopes":            preauthScopes,
		}, nil
	}
	return gin.H{"authenticated": false}, nil
}

// filterAllowedScopes returns the configured scopes that reach accepts.
func filterAllowedScopes(allScopes []string, reach resourcereach.Reach) []string {
	scopes := make([]string, 0, len(allScopes))
	for _, scope := range allScopes {
		if reach.ReachesScope(scope) {
			scopes = append(scopes, scope)
		}
	}
	return scopes
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

	logoutURL := s.apiv1.AdminLogoutURL(c.Request.Context(), idToken)
	return gin.H{"ok": true, "logout_url": logoutURL}, nil
}
