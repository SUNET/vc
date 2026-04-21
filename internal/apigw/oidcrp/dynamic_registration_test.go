package oidcrp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
)

func TestBuildRegistrationRequest(t *testing.T) {
	s := &Service{
		cfg: &model.OIDCRP{
			RedirectURI: "https://example.com/callback",
			ClientName:  "Test Client",
			ClientURI:   "https://example.com",
			LogoURI:     "https://example.com/logo.png",
			Contacts:    []string{"admin@example.com"},
			TosURI:      "https://example.com/tos",
			PolicyURI:   "https://example.com/policy",
			Scopes:      []string{"openid", "profile", "email"},
		},
	}

	req := s.buildRegistrationRequest()

	if req.RedirectURIs[0] != "https://example.com/callback" {
		t.Errorf("Expected redirect_uri https://example.com/callback, got %s", req.RedirectURIs[0])
	}

	if req.ClientName != "Test Client" {
		t.Errorf("Expected client_name 'Test Client', got %s", req.ClientName)
	}

	if req.ClientURI != "https://example.com" {
		t.Errorf("Expected client_uri https://example.com, got %s", req.ClientURI)
	}

	if req.LogoURI != "https://example.com/logo.png" {
		t.Errorf("Expected logo_uri https://example.com/logo.png, got %s", req.LogoURI)
	}

	if req.Scope != "openid profile email" {
		t.Errorf("Expected scope 'openid profile email', got %s", req.Scope)
	}

	if req.ResponseTypes[0] != "code" {
		t.Errorf("Expected response_type 'code', got %s", req.ResponseTypes[0])
	}

	if req.GrantTypes[0] != "authorization_code" {
		t.Errorf("Expected grant_type 'authorization_code', got %s", req.GrantTypes[0])
	}

	if req.TokenEndpointAuthMethod != "client_secret_basic" {
		t.Errorf("Expected token_endpoint_auth_method 'client_secret_basic', got %s", req.TokenEndpointAuthMethod)
	}
}

func TestBuildRegistrationRequest_MinimalConfig(t *testing.T) {
	s := &Service{
		cfg: &model.OIDCRP{
			RedirectURI: "https://example.com/callback",
			Scopes:      []string{"openid"},
		},
	}

	req := s.buildRegistrationRequest()

	if len(req.RedirectURIs) != 1 {
		t.Errorf("Expected 1 redirect_uri, got %d", len(req.RedirectURIs))
	}

	if req.Scope != "openid" {
		t.Errorf("Expected scope 'openid', got %s", req.Scope)
	}

	// Optional fields should be empty
	if req.ClientName != "" {
		t.Errorf("Expected empty client_name, got %s", req.ClientName)
	}

	if req.ClientURI != "" {
		t.Errorf("Expected empty client_uri, got %s", req.ClientURI)
	}
}

func TestRegister_Success(t *testing.T) {
	// Mock OIDC provider registration endpoint
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST request, got %s", r.Method)
		}

		// Check Content-Type
		contentType := r.Header.Get("Content-Type")
		if contentType != "application/json" {
			t.Errorf("Expected Content-Type application/json, got %s", contentType)
		}

		// Decode request body
		var regReq RegistrationRequest
		if err := json.NewDecoder(r.Body).Decode(&regReq); err != nil {
			t.Fatalf("Failed to decode request: %v", err)
		}

		// Validate request
		if len(regReq.RedirectURIs) == 0 {
			t.Error("Expected at least one redirect_uri")
		}

		// Send successful response
		resp := RegistrationResponse{
			ClientID:                "test-client-id",
			ClientSecret:            "test-client-secret",
			RegistrationAccessToken: "test-access-token",
			RegistrationClientURI:   r.URL.String() + "/clients/test-client-id",
			ClientSecretExpiresAt:   0,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(resp)
	}))
	defer mockServer.Close()

	// Create service
	log := logger.NewSimple("test")
	s := &Service{
		cfg: &model.OIDCRP{
			RedirectURI: "https://example.com/callback",
			ClientName:  "Test Client",
			Scopes:      []string{"openid", "profile"},
		},
		httpClient: &http.Client{},
		log:        log.New("oidcrp"),
	}
	req := s.buildRegistrationRequest()

	// Perform registration
	ctx := t.Context()
	resp, err := s.dynamicClientRegistration(ctx, mockServer.URL, req, "")

	if err != nil {
		t.Fatalf("Registration failed: %v", err)
	}

	if resp.ClientID != "test-client-id" {
		t.Errorf("Expected client_id 'test-client-id', got %s", resp.ClientID)
	}

	if resp.ClientSecret != "test-client-secret" {
		t.Errorf("Expected client_secret 'test-client-secret', got %s", resp.ClientSecret)
	}

	if resp.RegistrationAccessToken != "test-access-token" {
		t.Errorf("Expected registration_access_token 'test-access-token', got %s", resp.RegistrationAccessToken)
	}
}

func TestRegister_WithInitialAccessToken(t *testing.T) {
	expectedToken := "initial-access-token-123"

	// Mock server that validates initial access token
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check Authorization header
		authHeader := r.Header.Get("Authorization")
		expectedAuth := "Bearer " + expectedToken
		if authHeader != expectedAuth {
			t.Errorf("Expected Authorization '%s', got '%s'", expectedAuth, authHeader)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Send successful response
		resp := RegistrationResponse{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(resp)
	}))
	defer mockServer.Close()

	// Create service
	log := logger.NewSimple("test")
	s := &Service{
		cfg: &model.OIDCRP{
			RedirectURI: "https://example.com/callback",
			Scopes:      []string{"openid"},
		},
		httpClient: &http.Client{},
		log:        log.New("oidcrp"),
	}
	req := s.buildRegistrationRequest()

	// Perform registration with initial access token
	ctx := t.Context()
	resp, err := s.dynamicClientRegistration(ctx, mockServer.URL, req, expectedToken)

	if err != nil {
		t.Fatalf("Registration failed: %v", err)
	}

	if resp.ClientID != "test-client-id" {
		t.Errorf("Expected client_id 'test-client-id', got %s", resp.ClientID)
	}
}

func TestRegister_ServerError(t *testing.T) {
	// Mock server that returns error
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_request",
			"error_description": "redirect_uri is required",
		})
	}))
	defer mockServer.Close()

	// Create service
	log := logger.NewSimple("test")
	s := &Service{
		cfg:        &model.OIDCRP{},
		httpClient: &http.Client{},
		log:        log.New("oidcrp"),
	}

	// Build registration request (intentionally empty)
	req := &RegistrationRequest{}

	// Perform registration (should fail)
	ctx := t.Context()
	_, err := s.dynamicClientRegistration(ctx, mockServer.URL, req, "")

	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	// Check error message contains status code
	if err.Error() == "" {
		t.Error("Expected non-empty error message")
	}
}

func TestRegister_InvalidEndpoint(t *testing.T) {
	// Create service
	log := logger.NewSimple("test")
	s := &Service{
		cfg: &model.OIDCRP{
			RedirectURI: "https://example.com/callback",
			Scopes:      []string{"openid"},
		},
		httpClient: &http.Client{},
		log:        log.New("oidcrp"),
	}
	req := s.buildRegistrationRequest()

	// Perform registration with invalid endpoint
	ctx := t.Context()
	_, err := s.dynamicClientRegistration(ctx, "http://invalid-endpoint-that-does-not-exist.local", req, "")

	if err == nil {
		t.Fatal("Expected error for invalid endpoint, got nil")
	}
}
