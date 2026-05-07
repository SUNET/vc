package httpserver

import (
	"context"
	"net/http"

	"github.com/SUNET/vc/internal/apigw/apiv1"

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
func (s *Service) endpointAdminLogin(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointAdminLogin")
	defer span.End()

	reply, err := s.apiv1.AdminLoginURL(ctx)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
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
	_, span := s.tracer.Start(ctx, "httpserver:endpointAdminCallback")
	defer span.End()

	session := sessions.Default(c)
	savedState, _ := session.Get("oidc_state").(string)
	if savedState == "" || savedState != c.Query("state") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid state parameter"})
		return nil, nil
	}
	session.Delete("oidc_state")

	if errCode := c.Query("error"); errCode != "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": errCode, "error_description": c.Query("error_description")})
		return nil, nil
	}

	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing authorization code"})
		return nil, nil
	}

	reply, err := s.apiv1.AdminCallback(ctx, &apiv1.AdminCallbackRequest{Code: code})
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "admin_oidc_callback_failed")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication failed"})
		return nil, nil
	}

	session.Set(adminSessionKey, true)
	session.Set("admin_subject", reply.Subject)
	session.Set("admin_id_token", reply.RawIDToken)
	session.Set("admin_org_ids", reply.OrgIDs)
	session.Set("admin_given_name", reply.GivenName)
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
		givenName, _ := session.Get("admin_given_name").(string)
		var orgIDs []string
		if v, ok := session.Get("admin_org_ids").([]string); ok {
			orgIDs = v
		}
		return gin.H{"authenticated": true, "subject": subject, "given_name": givenName, "org_ids": orgIDs}, nil
	}
	return gin.H{"authenticated": false}, nil
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
