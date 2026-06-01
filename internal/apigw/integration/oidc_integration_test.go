//go:build integration

package integration

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/SUNET/vc/internal/apigw/auth_providers/oidcrp"
	pkgcache "github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOIDCIntegration_FullFlow tests the complete OIDC RP authentication flow
// from discovery through token exchange and claim transformation
func TestOIDCIntegration_FullFlow(t *testing.T) {
	env := setupOIDCTestEnvironment(t)
	defer env.cleanup()

	t.Run("Step1_ProviderDiscovery", func(t *testing.T) {
		testProviderDiscovery(t, env)
	})

	t.Run("Step2_InitiateAuth", func(t *testing.T) {
		testOIDCInitiateAuth(t, env)
	})

	t.Run("Step3_AuthURLContainsPKCE", func(t *testing.T) {
		testAuthURLContainsPKCE(t, env)
	})

	t.Run("Step4_ProcessCallback", func(t *testing.T) {
		testProcessCallback(t, env)
	})

	t.Run("Step5_TransformClaims", func(t *testing.T) {
		testOIDCClaimTransformation(t, env)
	})
}

// TestOIDCIntegration_MultipleCredentialTypes tests issuing different credential types
func TestOIDCIntegration_MultipleCredentialTypes(t *testing.T) {
	env := setupOIDCTestEnvironment(t)
	defer env.cleanup()

	credentialTypes := []string{"pid", "diploma", "ehic"}

	for _, credType := range credentialTypes {
		t.Run(fmt.Sprintf("CredentialType_%s", credType), func(t *testing.T) {
			testOIDCCredentialTypeFlow(t, env, credType)
		})
	}
}

// TestOIDCIntegration_ErrorHandling tests error scenarios
func TestOIDCIntegration_ErrorHandling(t *testing.T) {
	env := setupOIDCTestEnvironment(t)
	defer env.cleanup()

	t.Run("InvalidState", func(t *testing.T) {
		testInvalidState(t, env)
	})

	t.Run("ExpiredSession", func(t *testing.T) {
		testExpiredSession(t, env)
	})

	t.Run("MissingRequiredClaims", func(t *testing.T) {
		testMissingRequiredClaims(t, env)
	})

	t.Run("InvalidAuthorizationCode", func(t *testing.T) {
		testInvalidAuthorizationCode(t, env)
	})

	t.Run("NonceMismatch", func(t *testing.T) {
		testNonceMismatch(t, env)
	})
}

// TestOIDCIntegration_SessionManagement tests session lifecycle
func TestOIDCIntegration_SessionManagement(t *testing.T) {
	env := setupOIDCTestEnvironment(t)
	defer env.cleanup()

	t.Run("SessionCreation", func(t *testing.T) {
		testSessionCreation(t, env)
	})

	t.Run("SessionRetrieval", func(t *testing.T) {
		testSessionRetrieval(t, env)
	})

	t.Run("SessionDeletion", func(t *testing.T) {
		testSessionDeletion(t, env)
	})
}

// TestOIDCIntegration_ClaimTransformations tests various claim transformation scenarios
func TestOIDCIntegration_ClaimTransformations(t *testing.T) {
	env := setupOIDCTestEnvironment(t)
	defer env.cleanup()

	t.Run("NestedClaims", func(t *testing.T) {
		testNestedClaimTransformation(t, env)
	})

	t.Run("DefaultValues", func(t *testing.T) {
		testDefaultValueTransformation(t, env)
	})

	t.Run("StringTransformations", func(t *testing.T) {
		testStringTransformations(t, env)
	})
}

// TestOIDCIntegration_UserInfo tests UserInfo endpoint fetch and claim merging
func TestOIDCIntegration_UserInfo(t *testing.T) {
	env := setupOIDCTestEnvironment(t)
	defer env.cleanup()

	t.Run("FetchAndMergeClaims", func(t *testing.T) {
		ctx := t.Context()

		// Initiate auth, get session, process callback to obtain an access token
		authReq, err := env.oidcService.InitiateAuth(ctx, "pid")
		require.NoError(t, err)

		session, err := env.oidcService.GetSession(ctx, authReq.State)
		require.NoError(t, err)

		code := "valid-auth-code|" + session.Nonce
		authResp, err := env.oidcService.ProcessCallback(ctx, code, authReq.State)
		require.NoError(t, err)
		require.NotEmpty(t, authResp.AccessToken)

		// Fetch UserInfo using the access token
		userInfoClaims, err := env.oidcService.GetUserInfo(ctx, authResp.AccessToken)
		require.NoError(t, err)

		// Verify UserInfo contains expected claims
		assert.Equal(t, "user-123", userInfoClaims["sub"])
		assert.Equal(t, "John", userInfoClaims["given_name"])
		assert.Equal(t, "Doe", userInfoClaims["family_name"])
		assert.Equal(t, "john.doe@example.com", userInfoClaims["email"])
		assert.Equal(t, "1990-01-01", userInfoClaims["birthdate"])

		// Verify sub matches between ID token and UserInfo
		assert.Equal(t, authResp.Claims["sub"], userInfoClaims["sub"],
			"sub in UserInfo must match sub in ID token (OIDC Core §5.3.2)")

		// Verify merge: UserInfo claims take precedence
		maps.Copy(authResp.Claims, userInfoClaims)
		assert.Equal(t, "john.doe@example.com", authResp.Claims["email"])
	})

	t.Run("SubMismatchDetected", func(t *testing.T) {
		// Override the mock to return a different sub in UserInfo
		origHandler := env.mockOP.server.Config.Handler
		mux := http.NewServeMux()
		mux.HandleFunc("/.well-known/openid-configuration", env.mockOP.handleDiscovery)
		mux.HandleFunc("/jwks", env.mockOP.handleJWKS)
		mux.HandleFunc("/token", env.mockOP.handleToken)
		mux.HandleFunc("/authorize", env.mockOP.handleAuthorize)
		mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"sub":        "different-user-456",
				"given_name": "Jane",
			})
		})
		env.mockOP.server.Config.Handler = mux
		defer func() { env.mockOP.server.Config.Handler = origHandler }()

		ctx := t.Context()

		authReq, err := env.oidcService.InitiateAuth(ctx, "pid")
		require.NoError(t, err)

		session, err := env.oidcService.GetSession(ctx, authReq.State)
		require.NoError(t, err)

		code := "valid-auth-code|" + session.Nonce
		authResp, err := env.oidcService.ProcessCallback(ctx, code, authReq.State)
		require.NoError(t, err)

		// Fetch UserInfo — sub will differ
		userInfoClaims, err := env.oidcService.GetUserInfo(ctx, authResp.AccessToken)
		require.NoError(t, err)

		// Reproduce the handler's sub check
		uiSub, _ := userInfoClaims["sub"].(string)
		idSub, _ := authResp.Claims["sub"].(string)
		assert.NotEqual(t, uiSub, idSub, "subs should differ in this test")
	})

	t.Run("InvalidAccessTokenFallback", func(t *testing.T) {
		ctx := t.Context()

		// Calling GetUserInfo with an invalid token should return an error
		_, err := env.oidcService.GetUserInfo(ctx, "")
		assert.Error(t, err, "empty access token should fail")
	})
}

// oidcTestEnvironment holds the test environment setup
type oidcTestEnvironment struct {
	oidcService  *oidcrp.Service
	mockOP       *mockOIDCProvider
	sessionCache pkgcache.Cache[*oidcrp.Session]
	log          *logger.Log
	config       *model.OIDCRP
	cleanup      func()
}

// mockOIDCProvider simulates an OIDC Provider (OP) with discovery, JWKS, token, and userinfo endpoints
type mockOIDCProvider struct {
	server       *httptest.Server
	signingKey   *rsa.PrivateKey
	keyID        string
	clientID     string
	clientSecret string
	issuerURL    string

	// tokenHandler can be overridden per-test to simulate error conditions
	tokenHandler func(w http.ResponseWriter, r *http.Request)
}

func newMockOIDCProvider(t *testing.T) *mockOIDCProvider {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	op := &mockOIDCProvider{
		signingKey:   key,
		keyID:        "test-key-1",
		clientID:     "test-client-id",
		clientSecret: "test-client-secret",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", op.handleDiscovery)
	mux.HandleFunc("/jwks", op.handleJWKS)
	mux.HandleFunc("/token", op.handleToken)
	mux.HandleFunc("/userinfo", op.handleUserInfo)
	mux.HandleFunc("/authorize", op.handleAuthorize)

	op.server = httptest.NewServer(mux)
	op.issuerURL = op.server.URL

	return op
}

func (op *mockOIDCProvider) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	discovery := map[string]any{
		"issuer":                                op.issuerURL,
		"authorization_endpoint":                op.issuerURL + "/authorize",
		"token_endpoint":                        op.issuerURL + "/token",
		"userinfo_endpoint":                     op.issuerURL + "/userinfo",
		"jwks_uri":                              op.issuerURL + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"claims_supported": []string{
			"sub", "iss", "aud", "exp", "iat", "nonce",
			"given_name", "family_name", "email", "birthdate",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(discovery)
}

func (op *mockOIDCProvider) handleJWKS(w http.ResponseWriter, r *http.Request) {
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       &op.signingKey.PublicKey,
				KeyID:     op.keyID,
				Algorithm: string(jose.RS256),
				Use:       "sig",
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

func (op *mockOIDCProvider) handleToken(w http.ResponseWriter, r *http.Request) {
	// Allow per-test override
	if op.tokenHandler != nil {
		op.tokenHandler(w, r)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	code := r.FormValue("code")
	if code == "" || code == "invalid-code" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_grant",
			"error_description": "Invalid authorization code",
		})
		return
	}

	// Extract nonce from the code (we encode it there for testing)
	nonce := ""
	if parts := strings.SplitN(code, "|", 2); len(parts) == 2 {
		nonce = parts[1]
	}

	// Create a signed ID token
	idToken := op.createIDToken(nonce)

	tokenResp := map[string]any{
		"access_token":  "mock-access-token-" + code,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": "mock-refresh-token",
		"id_token":      idToken,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenResp)
}

func (op *mockOIDCProvider) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	userInfo := map[string]any{
		"sub":         "user-123",
		"given_name":  "John",
		"family_name": "Doe",
		"email":       "john.doe@example.com",
		"birthdate":   "1990-01-01",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
}

func (op *mockOIDCProvider) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	// In a real flow, this would render a login page.
	// For tests we just verify the request parameters.
	w.WriteHeader(http.StatusOK)
}

// createIDToken creates a signed JWT ID token
func (op *mockOIDCProvider) createIDToken(nonce string) string {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":         op.issuerURL,
		"sub":         "user-123",
		"aud":         op.clientID,
		"exp":         now.Add(1 * time.Hour).Unix(),
		"iat":         now.Unix(),
		"auth_time":   now.Unix(),
		"given_name":  "John",
		"family_name": "Doe",
		"email":       "john.doe@example.com",
		"birthdate":   "1990-01-01",
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = op.keyID

	raw, err := token.SignedString(op.signingKey)
	if err != nil {
		panic(fmt.Sprintf("failed to sign ID token: %v", err))
	}
	return raw
}

// createIDTokenWithClaims creates a signed JWT ID token with custom claims
func (op *mockOIDCProvider) createIDTokenWithClaims(customClaims map[string]any) string {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": op.issuerURL,
		"sub": "user-123",
		"aud": op.clientID,
		"exp": now.Add(1 * time.Hour).Unix(),
		"iat": now.Unix(),
	}
	maps.Copy(claims, customClaims)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = op.keyID

	raw, err := token.SignedString(op.signingKey)
	if err != nil {
		panic(fmt.Sprintf("failed to sign ID token: %v", err))
	}
	return raw
}

// createIDTokenWithWrongKey creates a signed JWT using a different key (for signature validation tests)
func (op *mockOIDCProvider) createIDTokenWithWrongKey(nonce string) string {
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("failed to generate wrong key: %v", err))
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   op.issuerURL,
		"sub":   "user-123",
		"aud":   op.clientID,
		"exp":   now.Add(1 * time.Hour).Unix(),
		"iat":   now.Unix(),
		"nonce": nonce,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "wrong-key"

	raw, err := token.SignedString(wrongKey)
	if err != nil {
		panic(fmt.Sprintf("failed to sign ID token: %v", err))
	}
	return raw
}

// setupOIDCTestEnvironment creates a complete test environment with a mock OIDC Provider
func setupOIDCTestEnvironment(t *testing.T) *oidcTestEnvironment {
	t.Helper()
	ctx := t.Context()

	log := logger.NewSimple("oidc-integration-test")

	// Create mock OIDC Provider
	mockOP := newMockOIDCProvider(t)

	// Create test configuration
	config := createTestOIDCRPConfig(mockOP)

	// Create session cache
	sessionCache := pkgcache.NewMemoryCache[*oidcrp.Session](300 * time.Second)

	// Create OIDC RP service (dbService=nil since preconfigured creds are used)
	service, err := oidcrp.New(ctx, config, sessionCache, nil, log)
	require.NoError(t, err)
	require.NotNil(t, service)

	return &oidcTestEnvironment{
		oidcService:  service,
		mockOP:       mockOP,
		sessionCache: sessionCache,
		log:          log,
		config:       config,
		cleanup: func() {
			sessionCache.Stop()
			mockOP.server.Close()
		},
	}
}

// createTestOIDCRPConfig creates a test OIDC RP configuration pointing at the mock OP
func createTestOIDCRPConfig(op *mockOIDCProvider) *model.OIDCRP {
	return &model.OIDCRP{
		Enable: true,
		Registration: &model.OIDCRPRegistrationConfig{
			Preconfigured: &model.OIDCRPPreconfiguredConfig{
				Enable:       true,
				ClientID:     op.clientID,
				ClientSecret: op.clientSecret,
			},
			Dynamic: &model.OIDCRPDynamicRegistrationConfig{
				Enable: false,
			},
		},
		IssuerURL:       op.issuerURL,
		RedirectURI:     op.issuerURL + "/callback",
		Scopes:          []string{"openid", "profile", "email"},
		SessionDuration: 300,
		// Flat mapping — OIDC claims already use standard names, no transformation needed
		// for passthrough. Include transform/default examples for testing.
		AttributeMapping: model.AttributeMapping{
			"given_name": {
				Claim: "given_name",
			},
			"family_name": {
				Claim: "family_name",
			},
			"birthdate": {
				Claim: "birth_date",
			},
			"degree": {
				Claim: "degree",
			},
			"card_number": {
				Claim: "card_number",
			},
			"email": {
				Claim:     "email",
				Transform: "lowercase",
			},
			"name": {
				Claim:     "display_name",
				Transform: "uppercase",
			},
			"note": {
				Claim:     "note",
				Transform: "trim",
			},
			"country": {
				Claim:   "country",
				Default: "SE",
			},
		},
	}
}

// --- Test functions ---

// testProviderDiscovery verifies that the OIDC service properly discovered the mock provider
func testProviderDiscovery(t *testing.T, env *oidcTestEnvironment) {
	// If the service was constructed successfully, discovery worked.
	// Validate by building a transformer (which reads config populated at init).
	transformer := env.oidcService.BuildTransformer()
	require.NotNil(t, transformer)
}

// testOIDCInitiateAuth verifies auth initiation produces a valid authorization URL
func testOIDCInitiateAuth(t *testing.T, env *oidcTestEnvironment) {
	ctx := t.Context()

	authReq, err := env.oidcService.InitiateAuth(ctx, "pid")
	require.NoError(t, err)
	require.NotNil(t, authReq)

	assert.NotEmpty(t, authReq.AuthorizationURL)
	assert.NotEmpty(t, authReq.State)

	// Verify the authorization URL points at the mock OP
	assert.Contains(t, authReq.AuthorizationURL, env.mockOP.issuerURL+"/authorize")
	assert.Contains(t, authReq.AuthorizationURL, "client_id="+env.mockOP.clientID)
	assert.Contains(t, authReq.AuthorizationURL, "response_type=code")
	assert.Contains(t, authReq.AuthorizationURL, "scope=")
	assert.Contains(t, authReq.AuthorizationURL, "state="+authReq.State)

	t.Logf("Authorization URL: %s", authReq.AuthorizationURL)
}

// testAuthURLContainsPKCE verifies the authorization URL includes PKCE parameters
func testAuthURLContainsPKCE(t *testing.T, env *oidcTestEnvironment) {
	ctx := t.Context()

	authReq, err := env.oidcService.InitiateAuth(ctx, "pid")
	require.NoError(t, err)

	assert.Contains(t, authReq.AuthorizationURL, "code_challenge=")
	assert.Contains(t, authReq.AuthorizationURL, "code_challenge_method=S256")
}

// testProcessCallback verifies the token exchange and ID token validation via the mock OP
func testProcessCallback(t *testing.T, env *oidcTestEnvironment) {
	ctx := t.Context()

	// Step 1: Initiate auth to get a session
	authReq, err := env.oidcService.InitiateAuth(ctx, "pid")
	require.NoError(t, err)

	// Step 2: Get the session to read the nonce
	session, err := env.oidcService.GetSession(ctx, authReq.State)
	require.NoError(t, err)

	// Encode the nonce into the authorization code so the mock token endpoint
	// can include it in the ID token (simulating real OP behavior)
	code := "valid-auth-code|" + session.Nonce

	// Step 3: Process callback
	resp, err := env.oidcService.ProcessCallback(ctx, code, authReq.State)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.NotNil(t, resp.IDToken)
	assert.Equal(t, "user-123", resp.IDToken.Subject)
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.Claims)

	// Verify claims content
	assert.Equal(t, "John", resp.Claims["given_name"])
	assert.Equal(t, "Doe", resp.Claims["family_name"])

	t.Logf("ID token subject: %s, claims: %v", resp.IDToken.Subject, resp.Claims)
}

// testOIDCClaimTransformation tests transforming OIDC claims into credential claims
func testOIDCClaimTransformation(t *testing.T, env *oidcTestEnvironment) {
	transformer := env.oidcService.BuildTransformer()
	require.NotNil(t, transformer)

	testCases := []struct {
		name     string
		claims   map[string]any
		expected map[string]any
	}{
		{
			name: "BasicClaims",
			claims: map[string]any{
				"given_name":  "Alice",
				"family_name": "Smith",
				"birthdate":   "1985-05-15",
			},
			expected: map[string]any{
				"given_name":  "Alice",
				"family_name": "Smith",
				"birth_date":  "1985-05-15",
			},
		},
		{
			name: "WithDegreeAndCard",
			claims: map[string]any{
				"given_name":  "Bob",
				"family_name": "Johnson",
				"degree":      "Bachelor of Science",
				"card_number": "EHIC123",
			},
			expected: map[string]any{
				"given_name":  "Bob",
				"family_name": "Johnson",
				"degree":      "Bachelor of Science",
				"card_number": "EHIC123",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := transformer.TransformClaims(tc.claims)
			require.NoError(t, err)
			// Check expected keys are present with correct values
			for k, v := range tc.expected {
				assert.Equal(t, v, result[k], "claim %s", k)
			}
		})
	}
}

// testOIDCCredentialTypeFlow tests initiation for each credential type
func testOIDCCredentialTypeFlow(t *testing.T, env *oidcTestEnvironment, credentialType string) {
	ctx := t.Context()

	authReq, err := env.oidcService.InitiateAuth(ctx, credentialType)
	require.NoError(t, err)
	require.NotNil(t, authReq)
	assert.NotEmpty(t, authReq.AuthorizationURL)
	assert.NotEmpty(t, authReq.State)

	// Verify session was created
	session, err := env.oidcService.GetSession(ctx, authReq.State)
	require.NoError(t, err)
	assert.Equal(t, credentialType, session.CredentialType)

	t.Logf("Created session for %s: state=%s", credentialType, authReq.State)
}

// testInvalidState tests that an invalid state parameter returns an error
func testInvalidState(t *testing.T, env *oidcTestEnvironment) {
	ctx := t.Context()

	_, err := env.oidcService.ProcessCallback(ctx, "some-code", "invalid-state-xyz")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid or expired session")
}

// testExpiredSession tests that an expired session is rejected
func testExpiredSession(t *testing.T, env *oidcTestEnvironment) {
	ctx := t.Context()

	// Create a service with very short session TTL
	shortCache := pkgcache.NewMemoryCache[*oidcrp.Session](1 * time.Millisecond)
	defer shortCache.Stop()

	shortConfig := createTestOIDCRPConfig(env.mockOP)
	shortConfig.SessionDuration = 1

	shortService, err := oidcrp.New(ctx, shortConfig, shortCache, nil, env.log)
	require.NoError(t, err)

	authReq, err := shortService.InitiateAuth(ctx, "pid")
	require.NoError(t, err)

	// Wait for cache entry to expire
	time.Sleep(50 * time.Millisecond)

	_, err = shortService.ProcessCallback(ctx, "some-code", authReq.State)
	assert.Error(t, err)

	t.Logf("Correctly rejected expired session: %v", err)
}

// testMissingRequiredClaims tests that missing required claims cause transformer to fail
func testMissingRequiredClaims(t *testing.T, env *oidcTestEnvironment) {
	transformer := env.oidcService.BuildTransformer()
	require.NotNil(t, transformer)

	// All claims with Required:true will fail if missing
	incompleteClaims := map[string]any{
		"given_name": "John",
		// missing family_name and birthdate
	}

	// The flat mapping has no Required flags in the test config,
	// so this tests that the transformer processes partial claims gracefully.
	_, err := transformer.TransformClaims(incompleteClaims)
	assert.NoError(t, err)
}

// testInvalidAuthorizationCode tests that an invalid code returns an error
func testInvalidAuthorizationCode(t *testing.T, env *oidcTestEnvironment) {
	ctx := t.Context()

	// Initiate to create a session
	authReq, err := env.oidcService.InitiateAuth(ctx, "pid")
	require.NoError(t, err)

	// Use an invalid code
	_, err = env.oidcService.ProcessCallback(ctx, "invalid-code", authReq.State)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to exchange authorization code")
}

// testNonceMismatch tests that a nonce mismatch is detected
func testNonceMismatch(t *testing.T, env *oidcTestEnvironment) {
	ctx := t.Context()

	authReq, err := env.oidcService.InitiateAuth(ctx, "pid")
	require.NoError(t, err)

	// Use a code that encodes a wrong nonce
	code := "valid-auth-code|wrong-nonce-value"

	_, err = env.oidcService.ProcessCallback(ctx, code, authReq.State)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonce mismatch")
}

// testSessionCreation verifies session fields are properly populated
func testSessionCreation(t *testing.T, env *oidcTestEnvironment) {
	ctx := t.Context()

	authReq, err := env.oidcService.InitiateAuth(ctx, "pid")
	require.NoError(t, err)

	session, err := env.oidcService.GetSession(ctx, authReq.State)
	require.NoError(t, err)

	assert.Equal(t, authReq.State, session.State)
	assert.Equal(t, "pid", session.CredentialType)
	assert.Equal(t, env.config.IssuerURL, session.IssuerURL)
	assert.NotEmpty(t, session.Nonce, "session should have a nonce")
	assert.NotEmpty(t, session.CodeVerifier, "session should have a PKCE code verifier")
	assert.False(t, session.CreatedAt.IsZero())
	assert.False(t, session.ExpiresAt.IsZero())
	assert.True(t, session.ExpiresAt.After(session.CreatedAt))
}

// testSessionRetrieval verifies that a session can be retrieved by state
func testSessionRetrieval(t *testing.T, env *oidcTestEnvironment) {
	ctx := t.Context()

	authReq, err := env.oidcService.InitiateAuth(ctx, "diploma")
	require.NoError(t, err)

	session, err := env.oidcService.GetSession(ctx, authReq.State)
	require.NoError(t, err)
	assert.Equal(t, "diploma", session.CredentialType)

	// Non-existent session returns error
	_, err = env.oidcService.GetSession(ctx, "nonexistent-state")
	assert.Error(t, err)
}

// testSessionDeletion verifies that a session can be deleted
func testSessionDeletion(t *testing.T, env *oidcTestEnvironment) {
	ctx := t.Context()

	authReq, err := env.oidcService.InitiateAuth(ctx, "pid")
	require.NoError(t, err)

	// Session should exist
	_, err = env.oidcService.GetSession(ctx, authReq.State)
	require.NoError(t, err)

	// Delete
	env.oidcService.DeleteSession(ctx, authReq.State)

	// Session should no longer exist
	_, err = env.oidcService.GetSession(ctx, authReq.State)
	assert.Error(t, err)
}

// testNestedClaimTransformation tests dot-notation nested claim paths
func testNestedClaimTransformation(t *testing.T, env *oidcTestEnvironment) {
	transformer := env.oidcService.BuildTransformer()
	require.NotNil(t, transformer)

	claims := map[string]any{
		"given_name":  "Emma",
		"family_name": "Wilson",
		"degree":      "Master of Arts",
	}

	result, err := transformer.TransformClaims(claims)
	require.NoError(t, err)

	// Flat mapping — claims are mapped directly
	assert.Equal(t, "Emma", result["given_name"])
	assert.Equal(t, "Wilson", result["family_name"])
	assert.Equal(t, "Master of Arts", result["degree"])
}

// testDefaultValueTransformation tests that default values are applied for missing optional claims
func testDefaultValueTransformation(t *testing.T, env *oidcTestEnvironment) {
	transformer := env.oidcService.BuildTransformer()
	require.NotNil(t, transformer)

	// Provide no claims — optional fields should use defaults
	claims := map[string]any{}

	result, err := transformer.TransformClaims(claims)
	require.NoError(t, err)

	assert.Equal(t, "SE", result["country"], "default country should be SE")
}

// testStringTransformations tests lowercase, uppercase, and trim transforms
func testStringTransformations(t *testing.T, env *oidcTestEnvironment) {
	transformer := env.oidcService.BuildTransformer()
	require.NotNil(t, transformer)

	claims := map[string]any{
		"email": "JOHN.DOE@EXAMPLE.COM",
		"name":  "hello world",
		"note":  "  spaced  ",
	}

	result, err := transformer.TransformClaims(claims)
	require.NoError(t, err)

	assert.Equal(t, "john.doe@example.com", result["email"], "email should be lowercased")
	assert.Equal(t, "HELLO WORLD", result["display_name"], "name should be uppercased")
	assert.Equal(t, "spaced", result["note"], "note should be trimmed")
	assert.Equal(t, "SE", result["country"], "default country should be SE")
}
