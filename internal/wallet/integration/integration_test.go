//go:build integration

package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SUNET/vc/internal/wallet/apiv1"
	"github.com/SUNET/vc/internal/wallet/config"
	"github.com/SUNET/vc/internal/wallet/credential"
	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/openid4vp"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test environment
// ---------------------------------------------------------------------------

// testEnvironment holds mock servers and the wallet client for a single test run.
type testEnvironment struct {
	t       *testing.T
	wallet  *apiv1.Client
	cfg     *config.Config
	log     *slog.Logger
	cleanup func()

	// mock servers
	issuerServer   *httptest.Server
	oauth2Server   *httptest.Server
	nonceServer    *httptest.Server
	verifierServer *httptest.Server

	// state captured by mock servers
	mu                    sync.Mutex
	tokenRequestsReceived []map[string]string
	credRequestsReceived  []map[string]any
	notificationsReceived []openid4vci.NotificationRequest
	vpResponsesReceived   []vpResponseCapture
	issuedCNonce          string
	issuedAccessToken     string
	deferredTransactionID string
	deferredReady         bool
}

type vpResponseCapture struct {
	VPToken string
	State   string
}

// setupTestEnvironment creates mock issuer/oauth2/verifier servers and a configured wallet client.
func setupTestEnvironment(t *testing.T, opts ...envOption) *testEnvironment {
	t.Helper()

	env := &testEnvironment{
		t:                 t,
		issuedCNonce:      "test-c-nonce-12345",
		issuedAccessToken: "test-access-token-xyz",
		log:               slog.Default(),
	}

	for _, o := range opts {
		o(env)
	}

	env.setupIssuerServer()
	env.setupOAuth2Server()
	env.setupVerifierServer()

	env.cfg = &config.Config{
		Wallet: config.WalletIdentity{
			ClientID:     "test-wallet-client",
			KeyAlgorithm: "ES256",
		},
		APIServer: config.APIServer{Addr: ":0"},
		Scenarios: []config.Scenario{},
	}

	ctx := context.Background()
	var err error
	env.wallet, err = apiv1.New(ctx, env.cfg, env.log)
	require.NoError(t, err)

	env.cleanup = func() {
		env.issuerServer.Close()
		env.oauth2Server.Close()
		if env.verifierServer != nil {
			env.verifierServer.Close()
		}
	}

	return env
}

type envOption func(*testEnvironment)

// ---------------------------------------------------------------------------
// Mock Issuer Server  (credential-issuer metadata + credential + nonce + notification)
// ---------------------------------------------------------------------------

func (env *testEnvironment) setupIssuerServer() {
	mux := http.NewServeMux()

	// Credential issuer metadata
	mux.HandleFunc("GET /.well-known/openid-credential-issuer/", func(w http.ResponseWriter, r *http.Request) {
		meta := openid4vci.CredentialIssuerMetadataParameters{
			CredentialIssuer:           env.issuerServer.URL,
			AuthorizationServers:       []string{env.oauth2Server.URL},
			CredentialEndpoint:         env.issuerServer.URL + "/credential",
			DeferredCredentialEndpoint: env.issuerServer.URL + "/credential/deferred",
			NotificationEndpoint:       env.issuerServer.URL + "/notification",
			CredentialConfigurationsSupported: map[string]openid4vci.CredentialConfigurationsSupported{
				"test_credential": {
					Format: "vc+sd-jwt",
					Scope:  "test_scope",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(meta)
	})

	// Credential offer
	mux.HandleFunc("GET /credential-offer", func(w http.ResponseWriter, r *http.Request) {
		offer := openid4vci.CredentialOfferParameters{
			CredentialIssuer:           env.issuerServer.URL,
			CredentialConfigurationIDs: []string{"test_credential"},
			Grants: map[string]any{
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]any{
					"pre-authorized_code": "test-pre-auth-code-abc",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(offer)
	})

	// Nonce endpoint
	mux.HandleFunc("POST /nonce", func(w http.ResponseWriter, r *http.Request) {
		resp := openid4vci.NonceResponse{
			CNonce: env.issuedCNonce,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// Credential endpoint
	mux.HandleFunc("POST /credential", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		json.Unmarshal(body, &req)

		env.mu.Lock()
		env.credRequestsReceived = append(env.credRequestsReceived, req)
		env.mu.Unlock()

		// Verify authorization header
		auth := r.Header.Get("Authorization")
		if !strings.Contains(auth, env.issuedAccessToken) {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_token"})
			return
		}

		// If deferred mode, return transaction_id first
		if env.deferredTransactionID != "" && !env.deferredReady {
			resp := openid4vci.CredentialResponse{
				TransactionID: env.deferredTransactionID,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}

		// Issue a mock SD-JWT credential
		mockCredential := createMockSDJWT(env.t)
		resp := openid4vci.CredentialResponse{
			Credentials: []openid4vci.Credential{
				{Credential: mockCredential},
			},
			CNonce:         "new-c-nonce-after-issuance",
			NotificationID: "notif-id-001",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// Deferred credential endpoint
	mux.HandleFunc("POST /credential/deferred", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req openid4vci.DeferredCredentialRequest
		json.Unmarshal(body, &req)

		if !env.deferredReady {
			resp := openid4vci.CredentialResponse{
				TransactionID: env.deferredTransactionID,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}

		mockCredential := createMockSDJWT(env.t)
		resp := openid4vci.CredentialResponse{
			Credentials: []openid4vci.Credential{
				{Credential: mockCredential},
			},
			NotificationID: "notif-id-deferred-001",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// Notification endpoint
	mux.HandleFunc("POST /notification", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req openid4vci.NotificationRequest
		json.Unmarshal(body, &req)

		env.mu.Lock()
		env.notificationsReceived = append(env.notificationsReceived, req)
		env.mu.Unlock()

		w.WriteHeader(http.StatusNoContent)
	})

	env.issuerServer = httptest.NewServer(mux)
}

// ---------------------------------------------------------------------------
// Mock OAuth2 Authorization Server
// ---------------------------------------------------------------------------

func (env *testEnvironment) setupOAuth2Server() {
	mux := http.NewServeMux()

	// OAuth2 server metadata
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		meta := map[string]string{
			"issuer":                                env.oauth2Server.URL,
			"authorization_endpoint":                env.oauth2Server.URL + "/authorize",
			"token_endpoint":                        env.oauth2Server.URL + "/token",
			"pushed_authorization_request_endpoint": env.oauth2Server.URL + "/par",
			"nonce_endpoint":                        env.oauth2Server.URL + "/nonce",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(meta)
	})

	// Token endpoint
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		captured := map[string]string{
			"grant_type":          r.FormValue("grant_type"),
			"pre-authorized_code": r.FormValue("pre-authorized_code"),
			"code":                r.FormValue("code"),
			"client_id":           r.FormValue("client_id"),
			"redirect_uri":        r.FormValue("redirect_uri"),
		}

		env.mu.Lock()
		env.tokenRequestsReceived = append(env.tokenRequestsReceived, captured)
		env.mu.Unlock()

		resp := openid4vci.TokenResponse{
			AccessToken: env.issuedAccessToken,
			TokenType:   "Bearer",
			ExpiresIn:   3600,
			CNonce:      env.issuedCNonce,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// PAR endpoint
	mux.HandleFunc("POST /par", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		resp := openid4vci.ParResponse{
			RequestURI: "urn:ietf:params:oauth:request_uri:test-par-uri",
			ExpiresIn:  90,
		}
		w.WriteHeader(http.StatusCreated)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// Authorization endpoint — auto-redirects with a code
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		redirectURI := r.URL.Query().Get("redirect_uri")
		state := r.URL.Query().Get("state")
		if redirectURI == "" {
			redirectURI = "http://localhost:8080/callback"
		}
		location := fmt.Sprintf("%s?code=test-auth-code-456&state=%s", redirectURI, state)
		http.Redirect(w, r, location, http.StatusFound)
	})

	env.oauth2Server = httptest.NewServer(mux)
}

// ---------------------------------------------------------------------------
// Mock Verifier Server
// ---------------------------------------------------------------------------

func (env *testEnvironment) setupVerifierServer() {
	mux := http.NewServeMux()

	// Request object endpoint — returns a JSON request object
	mux.HandleFunc("GET /request-object", func(w http.ResponseWriter, r *http.Request) {
		ro := openid4vp.RequestObject{
			ClientID:     "verifier-client-id",
			ResponseType: "vp_token",
			ResponseMode: "direct_post",
			ResponseURI:  env.verifierServer.URL + "/direct_post",
			Nonce:        "verifier-nonce-789",
			State:        "verifier-state-xyz",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ro)
	})

	// Direct post endpoint — captures VP responses
	mux.HandleFunc("POST /direct_post", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		capture := vpResponseCapture{
			VPToken: r.FormValue("vp_token"),
			State:   r.FormValue("state"),
		}

		env.mu.Lock()
		env.vpResponsesReceived = append(env.vpResponsesReceived, capture)
		env.mu.Unlock()

		resp := openid4vp.DirectPostResponse{
			RedirectURI: "https://verifier.example.com/success",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	env.verifierServer = httptest.NewServer(mux)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// createMockSDJWT generates a minimal SD-JWT for testing (header.payload.sig~disclosure~)
func createMockSDJWT(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token := jwtv5.NewWithClaims(jwtv5.SigningMethodES256, jwtv5.MapClaims{
		"iss": "https://issuer.example.com",
		"iat": time.Now().Unix(),
		"vct": "urn:credential:test",
		"cnf": map[string]any{
			"jwk": map[string]any{
				"kty": "EC",
				"crv": "P-256",
				"x":   base64.RawURLEncoding.EncodeToString(key.PublicKey.X.Bytes()),
				"y":   base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.Bytes()),
			},
		},
	})
	signed, err := token.SignedString(key)
	require.NoError(t, err)

	// SD-JWT format: issuer-jwt~disclosure1~disclosure2~
	mockDisclosure := base64.RawURLEncoding.EncodeToString([]byte(`["salt","given_name","John"]`))
	return signed + "~" + mockDisclosure + "~"
}

// addScenario is a convenience to append a scenario to the wallet config
func (env *testEnvironment) addScenario(s config.Scenario) {
	env.cfg.Scenarios = append(env.cfg.Scenarios, s)
}

// ---------------------------------------------------------------------------
// Tests: VCI Pre-Authorized Code Flow
// ---------------------------------------------------------------------------

func TestVCI_PreAuthorizedCodeFlow(t *testing.T) {
	env := setupTestEnvironment(t)
	defer env.cleanup()

	env.addScenario(config.Scenario{
		Name: "vci-pre-auth",
		Type: "vci",
		VCI: &config.VCIScenario{
			IssuerURL:                 env.issuerServer.URL,
			PreAuthorizedCode:         "test-pre-auth-code-abc",
			CredentialConfigurationID: "test_credential",
			ProofType:                 "jwt",
			SendNotification:          true,
		},
	})

	result, err := env.wallet.RunScenario(context.Background(), "vci-pre-auth")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.True(t, result.Success, "scenario should succeed, got error: %s", result.Error)
	assert.Equal(t, "vci-pre-auth", result.ScenarioName)
	assert.Equal(t, "vci", result.Type)

	// Verify steps executed in order
	stepNames := extractStepNames(result)
	assert.Contains(t, stepNames, "fetch_issuer_metadata")
	assert.Contains(t, stepNames, "fetch_oauth2_metadata")
	assert.Contains(t, stepNames, "token_request_pre_auth")
	assert.Contains(t, stepNames, "credential_request")
	assert.Contains(t, stepNames, "notification")

	// Verify token request used pre-authorized code
	env.mu.Lock()
	require.GreaterOrEqual(t, len(env.tokenRequestsReceived), 1)
	tokenReq := env.tokenRequestsReceived[0]
	env.mu.Unlock()
	assert.Equal(t, "urn:ietf:params:oauth:grant-type:pre-authorized_code", tokenReq["grant_type"])
	assert.Equal(t, "test-pre-auth-code-abc", tokenReq["pre-authorized_code"])

	// Verify credential was stored
	creds := env.wallet.Store().List()
	require.Len(t, creds, 1)
	assert.Equal(t, "vc+sd-jwt", creds[0].Format)
	assert.Equal(t, env.issuerServer.URL, creds[0].IssuerURL)
	assert.Contains(t, creds[0].RawCredential, "~")

	// Verify notification was sent
	env.mu.Lock()
	require.Len(t, env.notificationsReceived, 1)
	assert.Equal(t, "notif-id-001", env.notificationsReceived[0].NotificationID)
	assert.Equal(t, "credential_accepted", env.notificationsReceived[0].Event)
	env.mu.Unlock()

	// Verify result is in the result store
	storedResult := env.wallet.Results().LastByName("vci-pre-auth")
	require.NotNil(t, storedResult)
	assert.True(t, storedResult.Success)
}

func TestVCI_PreAuthorizedCodeWithTXCode(t *testing.T) {
	env := setupTestEnvironment(t)
	defer env.cleanup()

	env.addScenario(config.Scenario{
		Name: "vci-pre-auth-txcode",
		Type: "vci",
		VCI: &config.VCIScenario{
			IssuerURL:                 env.issuerServer.URL,
			PreAuthorizedCode:         "test-pre-auth-code-abc",
			TXCode:                    "123456",
			CredentialConfigurationID: "test_credential",
			ProofType:                 "jwt",
		},
	})

	result, err := env.wallet.RunScenario(context.Background(), "vci-pre-auth-txcode")
	require.NoError(t, err)
	assert.True(t, result.Success, "got error: %s", result.Error)

	// Verify credential stored
	assert.Equal(t, 1, env.wallet.Store().Count())
}

func TestVCI_FromCredentialOfferURI(t *testing.T) {
	env := setupTestEnvironment(t)
	defer env.cleanup()

	env.addScenario(config.Scenario{
		Name: "vci-offer-uri",
		Type: "vci",
		VCI: &config.VCIScenario{
			CredentialOfferURI: env.issuerServer.URL + "/credential-offer",
			ProofType:          "jwt",
		},
	})

	result, err := env.wallet.RunScenario(context.Background(), "vci-offer-uri")
	require.NoError(t, err)
	assert.True(t, result.Success, "got error: %s", result.Error)

	stepNames := extractStepNames(result)
	assert.Contains(t, stepNames, "fetch_credential_offer")
	assert.Contains(t, stepNames, "token_request_pre_auth")

	// Should have stored a credential
	assert.Equal(t, 1, env.wallet.Store().Count())
}

func TestVCI_FromInlineCredentialOffer(t *testing.T) {
	env := setupTestEnvironment(t)
	defer env.cleanup()

	offer := openid4vci.CredentialOfferParameters{
		CredentialIssuer:           env.issuerServer.URL,
		CredentialConfigurationIDs: []string{"test_credential"},
		Grants: map[string]any{
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]any{
				"pre-authorized_code": "inline-pre-auth-code",
			},
		},
	}
	offerJSON, err := json.Marshal(offer)
	require.NoError(t, err)

	env.addScenario(config.Scenario{
		Name: "vci-inline-offer",
		Type: "vci",
		VCI: &config.VCIScenario{
			CredentialOffer:   string(offerJSON),
			PreAuthorizedCode: "inline-pre-auth-code",
			ProofType:         "jwt",
		},
	})

	result, err := env.wallet.RunScenario(context.Background(), "vci-inline-offer")
	require.NoError(t, err)
	assert.True(t, result.Success, "got error: %s", result.Error)

	stepNames := extractStepNames(result)
	assert.Contains(t, stepNames, "parse_credential_offer")
	assert.Equal(t, 1, env.wallet.Store().Count())
}

func TestVCI_AuthorizationCodeFlow(t *testing.T) {
	env := setupTestEnvironment(t)
	defer env.cleanup()

	env.addScenario(config.Scenario{
		Name: "vci-auth-code",
		Type: "vci",
		VCI: &config.VCIScenario{
			IssuerURL:                 env.issuerServer.URL,
			CredentialConfigurationID: "test_credential",
			Scope:                     "test_scope",
			RedirectURI:               "http://localhost:8080/callback",
			ProofType:                 "jwt",
		},
	})

	result, err := env.wallet.RunScenario(context.Background(), "vci-auth-code")
	require.NoError(t, err)
	assert.True(t, result.Success, "got error: %s", result.Error)

	stepNames := extractStepNames(result)
	assert.Contains(t, stepNames, "authorization")
	assert.Contains(t, stepNames, "token_request_auth_code")
	assert.Contains(t, stepNames, "credential_request")

	// Token request should use authorization_code grant
	env.mu.Lock()
	require.GreaterOrEqual(t, len(env.tokenRequestsReceived), 1)
	tokenReq := env.tokenRequestsReceived[0]
	env.mu.Unlock()
	assert.Equal(t, "authorization_code", tokenReq["grant_type"])
	assert.Equal(t, "test-auth-code-456", tokenReq["code"])

	assert.Equal(t, 1, env.wallet.Store().Count())
}

func TestVCI_WithoutProof(t *testing.T) {
	env := setupTestEnvironment(t)
	defer env.cleanup()

	env.addScenario(config.Scenario{
		Name: "vci-no-proof",
		Type: "vci",
		VCI: &config.VCIScenario{
			IssuerURL:                 env.issuerServer.URL,
			PreAuthorizedCode:         "test-pre-auth-code-abc",
			CredentialConfigurationID: "test_credential",
			ProofType:                 "none",
		},
	})

	result, err := env.wallet.RunScenario(context.Background(), "vci-no-proof")
	require.NoError(t, err)
	assert.True(t, result.Success, "got error: %s", result.Error)

	// Verify no proofs were sent in credential request
	env.mu.Lock()
	require.Len(t, env.credRequestsReceived, 1)
	credReq := env.credRequestsReceived[0]
	env.mu.Unlock()
	_, hasProofs := credReq["proofs"]
	assert.False(t, hasProofs, "credential request should not contain proofs when proof_type=none")
}

func TestVCI_DeferredIssuance(t *testing.T) {
	env := setupTestEnvironment(t)
	defer env.cleanup()

	env.deferredTransactionID = "deferred-tx-001"
	env.deferredReady = false

	// Make deferred credential available after a short delay
	go func() {
		time.Sleep(200 * time.Millisecond)
		env.mu.Lock()
		env.deferredReady = true
		env.mu.Unlock()
	}()

	env.addScenario(config.Scenario{
		Name: "vci-deferred",
		Type: "vci",
		VCI: &config.VCIScenario{
			IssuerURL:                 env.issuerServer.URL,
			PreAuthorizedCode:         "test-pre-auth-code-abc",
			CredentialConfigurationID: "test_credential",
			ProofType:                 "jwt",
			DeferredPolling:           true,
			DeferredPollInterval:      100 * time.Millisecond,
			DeferredPollMaxAttempts:   10,
		},
	})

	result, err := env.wallet.RunScenario(context.Background(), "vci-deferred")
	require.NoError(t, err)
	assert.True(t, result.Success, "got error: %s", result.Error)

	stepNames := extractStepNames(result)
	assert.Contains(t, stepNames, "deferred_credential")

	assert.Equal(t, 1, env.wallet.Store().Count())
}

// ---------------------------------------------------------------------------
// Tests: VCI Negative (Expected Errors)
// ---------------------------------------------------------------------------

func TestVCI_ExpectError_MatchesActual(t *testing.T) {
	env := setupTestEnvironment(t)
	defer env.cleanup()

	// Stand up a server that always returns 404 for issuer metadata
	badIssuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":"not_found"}`))
	}))
	defer badIssuer.Close()

	env.addScenario(config.Scenario{
		Name: "vci-expect-error",
		Type: "vci",
		VCI: &config.VCIScenario{
			IssuerURL:                 badIssuer.URL,
			CredentialConfigurationID: "test_credential",
			ProofType:                 "jwt",
			ExpectError:               "issuer metadata HTTP 404",
		},
	})

	result, err := env.wallet.RunScenario(context.Background(), "vci-expect-error")
	require.NoError(t, err) // RunScenario returns nil because executeScenario handles expected errors
	assert.True(t, result.Success, "expected error should be treated as success, got: %s", result.Error)
	assert.Contains(t, result.Error, "expected error matched")
}

func TestVCI_MissingIssuerURL(t *testing.T) {
	env := setupTestEnvironment(t)
	defer env.cleanup()

	env.addScenario(config.Scenario{
		Name: "vci-no-issuer",
		Type: "vci",
		VCI: &config.VCIScenario{
			ProofType: "jwt",
		},
	})

	result, err := env.wallet.RunScenario(context.Background(), "vci-no-issuer")
	require.NoError(t, err)
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "no issuer URL")
}

func TestVCI_MissingVCIConfig(t *testing.T) {
	env := setupTestEnvironment(t)
	defer env.cleanup()

	env.addScenario(config.Scenario{
		Name: "vci-missing-config",
		Type: "vci",
		// VCI is nil
	})

	result, err := env.wallet.RunScenario(context.Background(), "vci-missing-config")
	require.NoError(t, err)
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "no vci config")
}

// ---------------------------------------------------------------------------
// Tests: VP Direct Post Flow
// ---------------------------------------------------------------------------

func TestVP_DirectPostFromRequestURI(t *testing.T) {
	env := setupTestEnvironment(t)
	defer env.cleanup()

	// Pre-load a credential into the wallet store
	env.wallet.Store().Add(&credential.StoredCredential{
		RawCredential: createMockSDJWT(t),
		Format:        "vc+sd-jwt",
		VCT:           "urn:credential:test",
		IssuerURL:     "https://issuer.example.com",
		ScenarioName:  "setup",
	})

	env.addScenario(config.Scenario{
		Name: "vp-direct-post",
		Type: "vp",
		VP: &config.VPScenario{
			RequestURI:       env.verifierServer.URL + "/request-object",
			SkipConsentCheck: true,
		},
	})

	result, err := env.wallet.RunScenario(context.Background(), "vp-direct-post")
	require.NoError(t, err)
	assert.True(t, result.Success, "got error: %s", result.Error)

	stepNames := extractStepNames(result)
	assert.Contains(t, stepNames, "fetch_request_object")
	assert.Contains(t, stepNames, "select_credentials")
	assert.Contains(t, stepNames, "build_vp_token")
	assert.Contains(t, stepNames, "send_vp_response")

	// Verify the verifier received the VP response
	env.mu.Lock()
	require.Len(t, env.vpResponsesReceived, 1)
	vpResp := env.vpResponsesReceived[0]
	env.mu.Unlock()

	assert.Equal(t, "verifier-state-xyz", vpResp.State)
	assert.NotEmpty(t, vpResp.VPToken)
	// SD-JWT VP should contain key binding JWT
	assert.Contains(t, vpResp.VPToken, "~")
}

func TestVP_DirectPostFromAuthorizationRequestURI(t *testing.T) {
	env := setupTestEnvironment(t)
	defer env.cleanup()

	env.wallet.Store().Add(&credential.StoredCredential{
		RawCredential: createMockSDJWT(t),
		Format:        "vc+sd-jwt",
		VCT:           "urn:credential:test",
		IssuerURL:     "https://issuer.example.com",
		ScenarioName:  "setup",
	})

	// openid4vp:// scheme with request_uri parameter
	authRequestURI := fmt.Sprintf("openid4vp://?request_uri=%s&client_id=verifier-client-id",
		url.QueryEscape(env.verifierServer.URL+"/request-object"))

	env.addScenario(config.Scenario{
		Name: "vp-auth-request-uri",
		Type: "vp",
		VP: &config.VPScenario{
			AuthorizationRequestURI: authRequestURI,
			SkipConsentCheck:        true,
		},
	})

	result, err := env.wallet.RunScenario(context.Background(), "vp-auth-request-uri")
	require.NoError(t, err)
	assert.True(t, result.Success, "got error: %s", result.Error)

	env.mu.Lock()
	require.Len(t, env.vpResponsesReceived, 1)
	env.mu.Unlock()
}

func TestVP_WithCredentialFilter(t *testing.T) {
	env := setupTestEnvironment(t)
	defer env.cleanup()

	// Add two credentials — one matching, one not
	env.wallet.Store().Add(&credential.StoredCredential{
		RawCredential: createMockSDJWT(t),
		Format:        "vc+sd-jwt",
		VCT:           "urn:credential:test",
		IssuerURL:     "https://issuer.example.com",
		ScenarioName:  "setup",
	})
	env.wallet.Store().Add(&credential.StoredCredential{
		RawCredential: "some-other-jwt-credential",
		Format:        "jwt_vc_json",
		VCT:           "urn:credential:other",
		IssuerURL:     "https://issuer.example.com",
		ScenarioName:  "setup",
	})

	env.addScenario(config.Scenario{
		Name: "vp-filtered",
		Type: "vp",
		VP: &config.VPScenario{
			RequestURI:       env.verifierServer.URL + "/request-object",
			SkipConsentCheck: true,
			CredentialFilter: &config.CredentialFilter{
				Format: "vc+sd-jwt",
			},
		},
	})

	result, err := env.wallet.RunScenario(context.Background(), "vp-filtered")
	require.NoError(t, err)
	assert.True(t, result.Success, "got error: %s", result.Error)

	// The VP token should only contain the SD-JWT credential
	env.mu.Lock()
	require.Len(t, env.vpResponsesReceived, 1)
	vpResp := env.vpResponsesReceived[0]
	env.mu.Unlock()

	assert.Contains(t, vpResp.VPToken, "~", "VP token should be SD-JWT format")
	assert.NotContains(t, vpResp.VPToken, "some-other-jwt-credential")
}

func TestVP_WithExplicitCredentialIDs(t *testing.T) {
	env := setupTestEnvironment(t)
	defer env.cleanup()

	id := env.wallet.Store().Add(&credential.StoredCredential{
		RawCredential: createMockSDJWT(t),
		Format:        "vc+sd-jwt",
		VCT:           "urn:credential:test",
		IssuerURL:     "https://issuer.example.com",
		ScenarioName:  "setup",
	})

	env.addScenario(config.Scenario{
		Name: "vp-explicit-ids",
		Type: "vp",
		VP: &config.VPScenario{
			RequestURI:        env.verifierServer.URL + "/request-object",
			SkipConsentCheck:  true,
			SendCredentialIDs: []string{id},
		},
	})

	result, err := env.wallet.RunScenario(context.Background(), "vp-explicit-ids")
	require.NoError(t, err)
	assert.True(t, result.Success, "got error: %s", result.Error)

	env.mu.Lock()
	require.Len(t, env.vpResponsesReceived, 1)
	env.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Tests: VP Negative Testing
// ---------------------------------------------------------------------------

func TestVP_MalformedVPToken(t *testing.T) {
	env := setupTestEnvironment(t)
	defer env.cleanup()

	env.wallet.Store().Add(&credential.StoredCredential{
		RawCredential: createMockSDJWT(t),
		Format:        "vc+sd-jwt",
		VCT:           "urn:credential:test",
		IssuerURL:     "https://issuer.example.com",
		ScenarioName:  "setup",
	})

	env.addScenario(config.Scenario{
		Name: "vp-malformed",
		Type: "vp",
		VP: &config.VPScenario{
			RequestURI:       env.verifierServer.URL + "/request-object",
			SkipConsentCheck: true,
			MalformedVP:      true,
		},
	})

	result, err := env.wallet.RunScenario(context.Background(), "vp-malformed")
	require.NoError(t, err)
	assert.True(t, result.Success, "got error: %s", result.Error)

	// The VP token should be the malformed placeholder
	env.mu.Lock()
	require.Len(t, env.vpResponsesReceived, 1)
	assert.Equal(t, "this-is-not-a-valid-vp-token", env.vpResponsesReceived[0].VPToken)
	env.mu.Unlock()
}

func TestVP_WrongSignature(t *testing.T) {
	env := setupTestEnvironment(t)
	defer env.cleanup()

	env.wallet.Store().Add(&credential.StoredCredential{
		RawCredential: createMockSDJWT(t),
		Format:        "vc+sd-jwt",
		VCT:           "urn:credential:test",
		IssuerURL:     "https://issuer.example.com",
		ScenarioName:  "setup",
	})

	env.addScenario(config.Scenario{
		Name: "vp-wrong-sig",
		Type: "vp",
		VP: &config.VPScenario{
			RequestURI:       env.verifierServer.URL + "/request-object",
			SkipConsentCheck: true,
			WrongSignature:   true,
		},
	})

	result, err := env.wallet.RunScenario(context.Background(), "vp-wrong-sig")
	require.NoError(t, err)
	assert.True(t, result.Success, "got error: %s", result.Error)

	// VP token should have been sent (with corrupted signature)
	env.mu.Lock()
	require.Len(t, env.vpResponsesReceived, 1)
	vpToken := env.vpResponsesReceived[0].VPToken
	env.mu.Unlock()

	// Should still be SD-JWT format but with corrupted KB-JWT signature
	assert.Contains(t, vpToken, "~")
	assert.True(t, strings.HasSuffix(vpToken, "XXXX"), "KB-JWT signature should be corrupted")
}

func TestVP_NoCredentialsAvailable(t *testing.T) {
	env := setupTestEnvironment(t)
	defer env.cleanup()

	// Don't add any credentials to the store
	env.addScenario(config.Scenario{
		Name: "vp-no-creds",
		Type: "vp",
		VP: &config.VPScenario{
			RequestURI:       env.verifierServer.URL + "/request-object",
			SkipConsentCheck: true,
		},
	})

	result, err := env.wallet.RunScenario(context.Background(), "vp-no-creds")
	require.NoError(t, err)
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "no matching credentials")
}

func TestVP_MissingRequestURI(t *testing.T) {
	env := setupTestEnvironment(t)
	defer env.cleanup()

	env.addScenario(config.Scenario{
		Name: "vp-missing-uri",
		Type: "vp",
		VP: &config.VPScenario{
			SkipConsentCheck: true,
		},
	})

	result, err := env.wallet.RunScenario(context.Background(), "vp-missing-uri")
	require.NoError(t, err)
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "requires either authorization_request_uri or request_uri")
}

func TestVP_MissingVPConfig(t *testing.T) {
	env := setupTestEnvironment(t)
	defer env.cleanup()

	env.addScenario(config.Scenario{
		Name: "vp-missing-config",
		Type: "vp",
		// VP is nil
	})

	result, err := env.wallet.RunScenario(context.Background(), "vp-missing-config")
	require.NoError(t, err)
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "no vp config")
}

// ---------------------------------------------------------------------------
// Tests: End-to-End  VCI → VP
// ---------------------------------------------------------------------------

func TestEndToEnd_VCI_Then_VP(t *testing.T) {
	env := setupTestEnvironment(t)
	defer env.cleanup()

	// Step 1: Issue a credential via VCI
	env.addScenario(config.Scenario{
		Name: "e2e-vci",
		Type: "vci",
		VCI: &config.VCIScenario{
			IssuerURL:                 env.issuerServer.URL,
			PreAuthorizedCode:         "test-pre-auth-code-abc",
			CredentialConfigurationID: "test_credential",
			ProofType:                 "jwt",
		},
	})

	vciResult, err := env.wallet.RunScenario(context.Background(), "e2e-vci")
	require.NoError(t, err)
	require.True(t, vciResult.Success, "VCI should succeed: %s", vciResult.Error)

	// Verify credential was stored
	creds := env.wallet.Store().List()
	require.Len(t, creds, 1)
	credID := creds[0].ID

	// Step 2: Present the issued credential via VP
	env.addScenario(config.Scenario{
		Name: "e2e-vp",
		Type: "vp",
		VP: &config.VPScenario{
			RequestURI:        env.verifierServer.URL + "/request-object",
			SkipConsentCheck:  true,
			SendCredentialIDs: []string{credID},
		},
	})

	vpResult, err := env.wallet.RunScenario(context.Background(), "e2e-vp")
	require.NoError(t, err)
	require.True(t, vpResult.Success, "VP should succeed: %s", vpResult.Error)

	// Verify the verifier received the VP
	env.mu.Lock()
	require.Len(t, env.vpResponsesReceived, 1)
	vpResp := env.vpResponsesReceived[0]
	env.mu.Unlock()

	assert.NotEmpty(t, vpResp.VPToken)
	assert.Equal(t, "verifier-state-xyz", vpResp.State)

	// Verify both results are stored
	allResults := env.wallet.Results().List()
	assert.Len(t, allResults, 2)
}

// ---------------------------------------------------------------------------
// Tests: Credential Store
// ---------------------------------------------------------------------------

func TestCredentialStore_Operations(t *testing.T) {
	store := credential.NewStore()

	// Add
	id1 := store.Add(&credential.StoredCredential{
		RawCredential: "cred-1",
		Format:        "vc+sd-jwt",
		VCT:           "urn:credential:test",
		IssuerURL:     "https://issuer1.example.com",
		ScenarioName:  "test",
	})
	id2 := store.Add(&credential.StoredCredential{
		RawCredential: "cred-2",
		Format:        "jwt_vc_json",
		VCT:           "urn:credential:other",
		IssuerURL:     "https://issuer2.example.com",
		ScenarioName:  "test",
	})

	assert.NotEqual(t, id1, id2)
	assert.Equal(t, 2, store.Count())

	// Get
	cred, ok := store.Get(id1)
	require.True(t, ok)
	assert.Equal(t, "cred-1", cred.RawCredential)
	assert.Equal(t, "vc+sd-jwt", cred.Format)

	_, ok = store.Get("nonexistent")
	assert.False(t, ok)

	// List
	all := store.List()
	assert.Len(t, all, 2)

	// FindByVCT
	found := store.FindByVCT("urn:credential:test")
	require.Len(t, found, 1)
	assert.Equal(t, id1, found[0].ID)

	// FindByFormat
	found = store.FindByFormat("jwt_vc_json")
	require.Len(t, found, 1)
	assert.Equal(t, id2, found[0].ID)

	// Delete
	assert.True(t, store.Delete(id1))
	assert.Equal(t, 1, store.Count())
	assert.False(t, store.Delete(id1)) // already deleted

	_, ok = store.Get(id1)
	assert.False(t, ok)
}

// ---------------------------------------------------------------------------
// Tests: Result Store
// ---------------------------------------------------------------------------

func TestResultStore_Operations(t *testing.T) {
	rs := apiv1.NewResultStore()

	rs.Add(&apiv1.ScenarioResult{
		ScenarioName: "test-1",
		Success:      true,
	})
	rs.Add(&apiv1.ScenarioResult{
		ScenarioName: "test-2",
		Success:      false,
		Error:        "something failed",
	})
	rs.Add(&apiv1.ScenarioResult{
		ScenarioName: "test-1",
		Success:      true,
	})

	all := rs.List()
	assert.Len(t, all, 3)

	last := rs.LastByName("test-1")
	require.NotNil(t, last)
	assert.True(t, last.Success)

	last = rs.LastByName("test-2")
	require.NotNil(t, last)
	assert.False(t, last.Success)

	none := rs.LastByName("nonexistent")
	assert.Nil(t, none)
}

// ---------------------------------------------------------------------------
// Tests: Scenario Lookup
// ---------------------------------------------------------------------------

func TestScenarioNotFound(t *testing.T) {
	env := setupTestEnvironment(t)
	defer env.cleanup()

	_, err := env.wallet.RunScenario(context.Background(), "nonexistent-scenario")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestUnknownScenarioType(t *testing.T) {
	env := setupTestEnvironment(t)
	defer env.cleanup()

	env.addScenario(config.Scenario{
		Name: "bad-type",
		Type: "unknown",
	})

	result, err := env.wallet.RunScenario(context.Background(), "bad-type")
	require.NoError(t, err)
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "unknown scenario type")
}

// ---------------------------------------------------------------------------
// Tests: Config Loading
// ---------------------------------------------------------------------------

func TestConfigLoad_NonexistentFile(t *testing.T) {
	_, err := config.Load("/nonexistent/config.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading wallet config")
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

func extractStepNames(result *apiv1.ScenarioResult) []string {
	names := make([]string, len(result.Steps))
	for i, s := range result.Steps {
		names[i] = s.Name
	}
	return names
}
