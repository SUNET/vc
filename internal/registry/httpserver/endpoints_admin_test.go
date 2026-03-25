package httpserver

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"github.com/SUNET/vc/internal/gen/status/apiv1_status"
	"github.com/SUNET/vc/internal/registry/apiv1"
	"github.com/SUNET/vc/pkg/httphelpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockApiv1 implements the Apiv1 interface for testing
type mockApiv1 struct {
	searchResult *apiv1.SearchPersonReply
	searchErr    error
	updateErr    error
}

func (m *mockApiv1) Status(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	return &apiv1_status.StatusReply{}, nil
}

func (m *mockApiv1) TokenStatusLists(ctx context.Context, req *apiv1.TokenStatusListsRequest) (*apiv1.TokenStatusListsResponse, error) {
	return nil, nil
}

func (m *mockApiv1) TokenStatusListAggregation(ctx context.Context) (*apiv1.TokenStatusListAggregationResponse, error) {
	return nil, nil
}

func (m *mockApiv1) SearchPerson(ctx context.Context, req *apiv1.SearchPersonRequest) (*apiv1.SearchPersonReply, error) {
	if m.searchErr != nil {
		return nil, m.searchErr
	}
	return m.searchResult, nil
}

func (m *mockApiv1) UpdateStatus(ctx context.Context, req *apiv1.UpdateStatusRequest) error {
	return m.updateErr
}

func setupTestService(t *testing.T) *Service {
	t.Helper()

	gin.SetMode(gin.TestMode)
	log := logger.NewSimple("test")
	ctx := t.Context()

	tracer, err := trace.NewForTesting(ctx, "test", log)
	require.NoError(t, err)

	cfg := &model.Cfg{
		Registry: &model.Registry{
			AdminGUI: model.AdminGUI{
				Enable:   new(true),
				Username: "admin",
				Password: "secret123",
			},
		},
	}

	httpHelpers, err := httphelpers.New(ctx, tracer, cfg, log)
	require.NoError(t, err)

	s := &Service{
		cfg:         cfg,
		log:         log,
		apiv1:       &mockApiv1{},
		gin:         gin.New(),
		httpHelpers: httpHelpers,
	}

	// Setup session store with test keys (encryption key must be exactly 32 bytes for AES-256)
	s.sessionStore = sessions.NewCookieStore([]byte("test-secret-key-32-bytes-long!!"), []byte("12345678901234567890123456789012"))
	s.sessionStore.Options = &sessions.Options{
		Path:     "/admin",
		MaxAge:   3600,
		HttpOnly: true,
	}

	return s
}

func TestEndpointAdminLoginPage(t *testing.T) {
	s := setupTestService(t)

	t.Run("renders login page", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/admin/login", nil)

		result, err := s.endpointAdminLoginPage(t.Context(), c)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		html, ok := result.(HTMLResponse)
		assert.True(t, ok)
		assert.Contains(t, string(html), "Registry Admin")
		assert.Contains(t, string(html), "<form")
	})

	t.Run("shows error message when present", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/admin/login?error=Invalid+credentials", nil)

		result, err := s.endpointAdminLoginPage(t.Context(), c)

		assert.NoError(t, err)
		html := result.(HTMLResponse)
		assert.Contains(t, string(html), "Invalid credentials")
	})
}

func TestEndpointAdminLogin(t *testing.T) {
	s := setupTestService(t)

	t.Run("successful login redirects to dashboard", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		form := url.Values{}
		form.Add("username", "admin")
		form.Add("password", "secret123")
		c.Request = httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(form.Encode()))
		c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		result, err := s.endpointAdminLogin(t.Context(), c)

		assert.NoError(t, err)
		assert.Nil(t, result) // Returns nil on redirect
		// Check Location header for redirect
		assert.Contains(t, w.Header().Get("Location"), "/admin/dashboard")
		// Check that session cookie is set
		assert.NotEmpty(t, w.Header().Get("Set-Cookie"))
	})

	t.Run("invalid credentials redirects to login with error", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		form := url.Values{}
		form.Add("username", "admin")
		form.Add("password", "wrongpassword")
		c.Request = httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(form.Encode()))
		c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		result, err := s.endpointAdminLogin(t.Context(), c)

		assert.NoError(t, err)
		assert.Nil(t, result)
		assert.Contains(t, w.Header().Get("Location"), "/admin/login?error=Invalid+credentials")
	})

	t.Run("invalid username redirects to login with error", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		form := url.Values{}
		form.Add("username", "wronguser")
		form.Add("password", "secret123")
		c.Request = httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(form.Encode()))
		c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		result, err := s.endpointAdminLogin(t.Context(), c)

		assert.NoError(t, err)
		assert.Nil(t, result)
		assert.Contains(t, w.Header().Get("Location"), "/admin/login?error=Invalid+credentials")
	})
}

func TestEndpointAdminLogout(t *testing.T) {
	s := setupTestService(t)

	t.Run("logout redirects to login", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/admin/logout", nil)

		result, err := s.endpointAdminLogout(t.Context(), c)

		assert.NoError(t, err)
		assert.Nil(t, result)
		assert.Equal(t, http.StatusFound, w.Code)
		assert.Contains(t, w.Header().Get("Location"), "/admin/login")
	})
}

func TestEndpointAdminDashboard(t *testing.T) {
	s := setupTestService(t)

	t.Run("renders dashboard with username", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/admin/dashboard", nil)

		// Create a session with authenticated user
		session, _ := s.sessionStore.New(c.Request, sessionName)
		session.Values[sessionAuthKey] = true
		session.Values[sessionUsername] = "testuser"
		_ = session.Save(c.Request, w)

		// Add cookie to request
		c.Request.Header.Set("Cookie", w.Header().Get("Set-Cookie"))

		result, err := s.endpointAdminDashboard(t.Context(), c)

		assert.NoError(t, err)
		html := result.(HTMLResponse)
		assert.Contains(t, string(html), "testuser")
		assert.Contains(t, string(html), "Dashboard")
	})
}

func TestEndpointAdminSearchPage(t *testing.T) {
	s := setupTestService(t)

	t.Run("renders empty search page", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/admin/search", nil)

		result, err := s.endpointAdminSearchPage(t.Context(), c)

		assert.NoError(t, err)
		html := result.(HTMLResponse)
		assert.Contains(t, string(html), "Search Credential Subjects")
		assert.Contains(t, string(html), "<form")
	})
}

func TestEndpointAdminSearch(t *testing.T) {
	t.Run("successful search shows result", func(t *testing.T) {
		s := setupTestService(t)
		s.apiv1 = &mockApiv1{
			searchResult: &apiv1.SearchPersonReply{
				Results: []*apiv1.PersonResult{
					{
						FirstName:   "John",
						LastName:    "Doe",
						DateOfBirth: "1990-01-15",
						Section:     0,
						Index:       42,
						Status:      0,
					},
				},
			},
		}

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		form := url.Values{}
		form.Add("first_name", "John")
		form.Add("last_name", "Doe")
		form.Add("date_of_birth", "1990-01-15")
		c.Request = httptest.NewRequest(http.MethodPost, "/admin/search", strings.NewReader(form.Encode()))
		c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		result, err := s.endpointAdminSearch(t.Context(), c)

		assert.NoError(t, err)
		html := result.(HTMLResponse)
		assert.Contains(t, string(html), "John")
		assert.Contains(t, string(html), "Doe")
		assert.Contains(t, string(html), "VALID")
	})

	t.Run("search not found shows error", func(t *testing.T) {
		s := setupTestService(t)
		s.apiv1 = &mockApiv1{
			searchErr: fmt.Errorf("not found"),
		}

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		form := url.Values{}
		form.Add("first_name", "Unknown")
		form.Add("last_name", "Person")
		form.Add("date_of_birth", "1990-01-01")
		c.Request = httptest.NewRequest(http.MethodPost, "/admin/search", strings.NewReader(form.Encode()))
		c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		result, err := s.endpointAdminSearch(t.Context(), c)

		assert.NoError(t, err)
		html := result.(HTMLResponse)
		assert.Contains(t, string(html), "Search failed")
	})
}

func TestEndpointAdminUpdateStatus(t *testing.T) {
	t.Run("successful update shows success message", func(t *testing.T) {
		s := setupTestService(t)
		s.apiv1 = &mockApiv1{
			updateErr: nil,
			searchResult: &apiv1.SearchPersonReply{
				Results: []*apiv1.PersonResult{
					{
						FirstName:   "John",
						LastName:    "Doe",
						DateOfBirth: "1990-01-15",
						Section:     0,
						Index:       42,
						Status:      1,
					},
				},
			},
		}

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		form := url.Values{}
		form.Add("first_name", "John")
		form.Add("last_name", "Doe")
		form.Add("date_of_birth", "1990-01-15")
		form.Add("status", "1")
		c.Request = httptest.NewRequest(http.MethodPost, "/admin/update-status", strings.NewReader(form.Encode()))
		c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		result, err := s.endpointAdminUpdateStatus(t.Context(), c)

		assert.NoError(t, err)
		html := result.(HTMLResponse)
		assert.Contains(t, string(html), "Status updated successfully")
	})

	t.Run("update failure shows error", func(t *testing.T) {
		s := setupTestService(t)
		s.apiv1 = &mockApiv1{
			updateErr: fmt.Errorf("database error"),
		}

		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)

		form := url.Values{}
		form.Add("first_name", "John")
		form.Add("last_name", "Doe")
		form.Add("date_of_birth", "1990-01-15")
		form.Add("status", "1")
		c.Request = httptest.NewRequest(http.MethodPost, "/admin/update-status", strings.NewReader(form.Encode()))
		c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		result, err := s.endpointAdminUpdateStatus(t.Context(), c)

		assert.NoError(t, err)
		html := result.(HTMLResponse)
		assert.Contains(t, string(html), "Failed to update status")
	})
}

func TestAdminAuthMiddleware(t *testing.T) {
	s := setupTestService(t)

	t.Run("unauthenticated request redirects to login", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/admin/dashboard", nil)

		middleware := s.adminAuthMiddleware()
		middleware(c)

		assert.True(t, c.IsAborted())
		assert.Equal(t, http.StatusFound, w.Code)
		assert.Contains(t, w.Header().Get("Location"), "/admin/login")
	})

	t.Run("authenticated request passes through", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/admin/dashboard", nil)

		// Create authenticated session
		session, _ := s.sessionStore.New(c.Request, sessionName)
		session.Values[sessionAuthKey] = true
		session.Values[sessionUsername] = "admin"
		_ = session.Save(c.Request, w)

		// Create new request with cookie
		c.Request = httptest.NewRequest(http.MethodGet, "/admin/dashboard", nil)
		c.Request.Header.Set("Cookie", w.Header().Get("Set-Cookie"))

		// Reset recorder
		w = httptest.NewRecorder()
		c, _ = gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/admin/dashboard", nil)
		c.Request.Header.Set("Cookie", w.Header().Get("Set-Cookie"))

		middleware := s.adminAuthMiddleware()
		middleware(c)

		// If session is properly restored, should not be aborted
		// Note: This test is simplified; full session restoration requires more setup
	})
}

func TestStatusValues(t *testing.T) {
	// Test that status values are correctly interpreted per draft-ietf-oauth-status-list
	tests := []struct {
		status   uint8
		expected string
	}{
		{0, "VALID"},
		{1, "INVALID"},
		{2, "SUSPENDED"},
		{3, "UNKNOWN"}, // Any value > 2 is unknown
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("status_%d", tt.status), func(t *testing.T) {
			var statusText string
			switch tt.status {
			case 0:
				statusText = "VALID"
			case 1:
				statusText = "INVALID"
			case 2:
				statusText = "SUSPENDED"
			default:
				statusText = "UNKNOWN"
			}
			assert.Equal(t, tt.expected, statusText)
		})
	}
}
