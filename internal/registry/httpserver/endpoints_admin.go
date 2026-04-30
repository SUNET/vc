package httpserver

import (
	"context"
	"crypto/subtle"
	"net/http"

	"github.com/SUNET/vc/internal/registry/apiv1"

	"github.com/gin-gonic/gin"
)

const (
	sessionName     = "registry_admin_session"
	sessionAuthKey  = "authenticated"
	sessionUsername = "username"
)

// HTMLResponse wraps an HTML string for rendering
type HTMLResponse string

// adminLoginRequest is the request for admin login (httpserver-specific, not in apiv1)
type adminLoginRequest struct {
	Username string `form:"username" validate:"required"`
	Password string `form:"password" validate:"required"`
}

// adminAuthMiddleware checks if the user is authenticated
func (s *Service) adminAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		session, err := s.sessionStore.Get(c.Request, sessionName)
		if err != nil {
			c.Redirect(http.StatusFound, "/admin/login")
			c.Abort()
			return
		}

		auth, ok := session.Values[sessionAuthKey].(bool)
		if !ok || !auth {
			c.Redirect(http.StatusFound, "/admin/login")
			c.Abort()
			return
		}

		c.Next()
	}
}

// endpointAdminLoginPage renders the login page
func (s *Service) endpointAdminLoginPage(ctx context.Context, c *gin.Context) (any, error) {
	// Check if already logged in
	session, _ := s.sessionStore.Get(c.Request, sessionName)
	if auth, ok := session.Values[sessionAuthKey].(bool); ok && auth {
		c.Redirect(http.StatusFound, "/admin/dashboard")
		return nil, nil
	}

	errorMsg := c.Query("error")
	c.Header("Content-Type", "text/html")
	return HTMLResponse(loginPageHTML(errorMsg)), nil
}

// endpointAdminLogin handles the login form submission
func (s *Service) endpointAdminLogin(ctx context.Context, c *gin.Context) (any, error) {
	var req adminLoginRequest
	if err := s.httpHelpers.Binding.Request(ctx, c, &req); err != nil {
		c.Redirect(http.StatusFound, "/admin/login?error=Invalid+request")
		return nil, nil
	}

	// Constant-time comparison to prevent timing attacks
	expectedUsername := s.cfg.Registry.AdminGUI.Username
	expectedPassword := s.cfg.Registry.AdminGUI.Password

	usernameMatch := subtle.ConstantTimeCompare([]byte(req.Username), []byte(expectedUsername)) == 1
	passwordMatch := subtle.ConstantTimeCompare([]byte(req.Password), []byte(expectedPassword)) == 1

	if !usernameMatch || !passwordMatch {
		s.log.Info("Admin login failed", "username", req.Username)
		c.Redirect(http.StatusFound, "/admin/login?error=Invalid+credentials")
		return nil, nil
	}

	session, _ := s.sessionStore.Get(c.Request, sessionName)
	session.Values[sessionAuthKey] = true
	session.Values[sessionUsername] = req.Username
	if err := session.Save(c.Request, c.Writer); err != nil {
		s.log.Error(err, "Failed to save session")
		c.Redirect(http.StatusFound, "/admin/login?error=Session+error")
		return nil, nil
	}

	s.log.Info("Admin login successful", "username", req.Username)
	c.Redirect(http.StatusFound, "/admin/dashboard")
	return nil, nil
}

// endpointAdminLogout handles logout
func (s *Service) endpointAdminLogout(ctx context.Context, c *gin.Context) (any, error) {
	session, _ := s.sessionStore.Get(c.Request, sessionName)
	session.Values[sessionAuthKey] = false
	session.Options.MaxAge = -1 // Delete the session
	_ = session.Save(c.Request, c.Writer)

	c.Redirect(http.StatusFound, "/admin/login")
	return nil, nil
}

// endpointAdminDashboard renders the main dashboard
func (s *Service) endpointAdminDashboard(ctx context.Context, c *gin.Context) (any, error) {
	session, _ := s.sessionStore.Get(c.Request, sessionName)
	username := session.Values[sessionUsername].(string)

	c.Header("Content-Type", "text/html")
	return HTMLResponse(dashboardPageHTML(username)), nil
}

// endpointAdminSearchPage renders the search page
func (s *Service) endpointAdminSearchPage(ctx context.Context, c *gin.Context) (any, error) {
	c.Header("Content-Type", "text/html")
	return HTMLResponse(searchPageHTML("", nil, "", nil)), nil
}

// endpointAdminSearch handles person search
func (s *Service) endpointAdminSearch(ctx context.Context, c *gin.Context) (any, error) {
	request := &apiv1.SearchPersonRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		c.Header("Content-Type", "text/html")
		return HTMLResponse(searchPageHTML("Invalid request parameters", nil, "", nil)), nil
	}

	reply, err := s.apiv1.SearchPerson(ctx, request)
	if err != nil {
		s.log.Error(err, "Search failed")
		c.Header("Content-Type", "text/html")
		return HTMLResponse(searchPageHTML("Search failed: "+err.Error(), nil, "", request)), nil
	}

	c.Header("Content-Type", "text/html")
	return HTMLResponse(searchPageHTML("", reply, "", request)), nil
}

// endpointAdminUpdateStatus handles status updates
func (s *Service) endpointAdminUpdateStatus(ctx context.Context, c *gin.Context) (any, error) {
	request := &apiv1.UpdateStatusRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		c.Header("Content-Type", "text/html")
		return HTMLResponse(searchPageHTML("Invalid request parameters", nil, "", nil)), nil
	}

	if err := s.apiv1.UpdateStatus(ctx, request); err != nil {
		s.log.Error(err, "Status update failed", "section", request.Section, "index", request.Index, "status", request.Status)
		c.Header("Content-Type", "text/html")
		// Preserve search params on error
		searchParams := &apiv1.SearchPersonRequest{
			FirstName:   request.SearchFirstName,
			LastName:    request.SearchLastName,
			DateOfBirth: request.SearchDateOfBirth,
		}
		return HTMLResponse(searchPageHTML("Failed to update status: "+err.Error(), nil, "", searchParams)), nil
	}

	s.log.Info("Status updated via admin GUI", "section", request.Section, "index", request.Index, "status", request.Status)

	// Re-run the search to show updated results
	searchParams := &apiv1.SearchPersonRequest{
		FirstName:   request.SearchFirstName,
		LastName:    request.SearchLastName,
		DateOfBirth: request.SearchDateOfBirth,
	}

	reply, err := s.apiv1.SearchPerson(ctx, searchParams)
	if err != nil {
		s.log.Error(err, "Failed to re-run search after status update")
		c.Header("Content-Type", "text/html")
		return HTMLResponse(searchPageHTML("Status updated, but failed to refresh search results", nil, "", searchParams)), nil
	}

	c.Header("Content-Type", "text/html")
	return HTMLResponse(searchPageHTML("", reply, "Status updated successfully", searchParams)), nil
}
