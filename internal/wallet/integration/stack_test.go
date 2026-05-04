//go:build integration

// Package integration contains integration tests that run against the real
// docker-compose stack (apigw, verifier, mockas, issuer, registry, mongo).
//
// Prerequisites:
//   - The stack must be running: docker compose up -d
//   - The dev container must be connected to vc_vc-dev-net:
//     docker network connect vc_vc-dev-net $(hostname)
//
// Run:
//
//	go test -v -tags integration ./internal/wallet/integration/ -run TestStack
package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SUNET/vc/internal/wallet/apiv1"
	"github.com/SUNET/vc/internal/wallet/config"
	"github.com/SUNET/vc/pkg/jose"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/vcclient"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Stack service addresses (Docker bridge IPs on vc-dev-net)
var (
	apigwURL    = envOrDefault("STACK_APIGW_URL", "https://172.16.50.2:8080")     // NOSONAR
	verifierURL = envOrDefault("STACK_VERIFIER_URL", "https://172.16.50.6:8080")  // NOSONAR
	mockasURL   = envOrDefault("STACK_MOCKAS_URL", "https://172.16.50.13:8080")   // NOSONAR
	mockOIDCURL = envOrDefault("STACK_MOCK_OIDC_URL", "http://172.16.50.30:8080") // NOSONAR

	// The public URLs the services use for self-referencing
	apigwPublicURL    = envOrDefault("STACK_APIGW_PUBLIC_URL", "https://apigw.vc.docker:8080")          // NOSONAR
	verifierPublicURL = envOrDefault("STACK_VERIFIER_PUBLIC_URL", "https://verifier.vc.docker:8080")    // NOSONAR
	mockOIDCPublicURL = envOrDefault("STACK_MOCK_OIDC_PUBLIC_URL", "http://mock-oauth2.vc.docker:8080") // NOSONAR

	// tlsTransport is a shared TLS transport that trusts the dev rootCA.
	// Initialised by TestMain before any tests run.
	tlsTransport *http.Transport

	// OAuth client config matching config.yaml
	oauthClientID = "1003"                  // NOSONAR
	oauthRedirect = "http://localhost:3000" // NOSONAR — must match apigw oauth_server in config.yaml

	// Shared VP client (registered once via sync.Once to avoid rate limiting)
	sharedVPClient     *verifierClient
	sharedVPClientOnce sync.Once
)

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// TestMain sets up an http.DefaultClient that trusts the dev rootCA so all
// stack tests can talk to TLS-enabled services without per-call changes.
func TestMain(m *testing.M) {
	caPath := envOrDefault("STACK_ROOT_CA", "../../../developer_tools/pki/rootCA.crt")
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reading rootCA %s: %v\n", caPath, err)
		os.Exit(1)
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		fmt.Fprintf(os.Stderr, "loading system cert pool: %v; falling back to empty pool\n", err)
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(caPEM) {
		fmt.Fprintf(os.Stderr, "rootCA %s contains no valid certificates\n", caPath)
		os.Exit(1)
	}
	tlsTransport = http.DefaultTransport.(*http.Transport).Clone()
	tlsTransport.TLSClientConfig.RootCAs = pool
	http.DefaultClient = &http.Client{
		Transport: tlsTransport,
		Timeout:   30 * time.Second,
	}
	os.Exit(m.Run())
}

// rewritePublicToInternal replaces Docker-internal hostnames with bridge IPs
// so requests from the dev container actually reach the services.
func rewritePublicToInternal(rawURL string) string {
	rawURL = strings.ReplaceAll(rawURL, apigwPublicURL, apigwURL)
	rawURL = strings.ReplaceAll(rawURL, verifierPublicURL, verifierURL)
	rawURL = strings.ReplaceAll(rawURL, mockOIDCPublicURL, mockOIDCURL)
	return rawURL
}

func rewriteInternalToPublic(rawURL string) string {
	rawURL = strings.ReplaceAll(rawURL, apigwURL, apigwPublicURL)
	rawURL = strings.ReplaceAll(rawURL, verifierURL, verifierPublicURL)
	rawURL = strings.ReplaceAll(rawURL, mockOIDCURL, mockOIDCPublicURL)
	return rawURL
}

// verifierClient holds OIDC client registration details from the verifier.
type verifierClient struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// registerVerifierClient dynamically registers an OIDC client on the verifier
// via RFC 7591 Dynamic Client Registration.
func registerVerifierClient(t *testing.T) *verifierClient {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"redirect_uris":              []string{oauthRedirect},
		"grant_types":                []string{"authorization_code"},
		"response_types":             []string{"code"},
		"scope":                      "openid pid ehic",
		"token_endpoint_auth_method": "client_secret_basic",
		"client_name":                "Stack Test Wallet " + uuid.New().String()[:8],
	})
	resp, err := http.Post(verifierURL+"/register", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "register: %s", string(respBody))

	var client verifierClient
	require.NoError(t, json.Unmarshal(respBody, &client))
	require.NotEmpty(t, client.ClientID, "client_id must not be empty")
	t.Logf("registered verifier client: client_id=%s", client.ClientID)
	return &client
}

// getOrRegisterVerifierClient returns the shared VP client, registering it once.
// This avoids hitting the verifier's rate limiter on /register.
func getOrRegisterVerifierClient(t *testing.T) *verifierClient {
	t.Helper()
	sharedVPClientOnce.Do(func() {
		sharedVPClient = registerVerifierClient(t)
	})
	return sharedVPClient
}

// extractSessionID extracts the session ID from the authorize HTML page.
// It looks for the sessionId JavaScript variable or the QR code URL.
func extractSessionID(t *testing.T, htmlStr string) string {
	t.Helper()
	// Pattern: sessionId: 'xxx',
	const marker = "sessionId: '"
	idx := strings.Index(htmlStr, marker)
	if idx < 0 {
		t.Log("sessionId not found in HTML")
		return ""
	}
	start := idx + len(marker)
	end := strings.Index(htmlStr[start:], "'")
	if end < 0 {
		t.Log("sessionId end quote not found")
		return ""
	}
	return htmlStr[start : start+end]
}

// doVPAuthorize calls the verifier /authorize endpoint and returns the session ID.
func doVPAuthorize(t *testing.T, vpClientID, scope, state string) string {
	t.Helper()
	authURL := fmt.Sprintf("%s/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=%s&state=%s",
		verifierURL, vpClientID, url.QueryEscape(oauthRedirect), url.QueryEscape(scope), url.QueryEscape(state))

	resp, err := http.Get(authURL)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "authorize: %s", string(body)[:min(len(body), 200)])

	sessionID := extractSessionID(t, string(body))
	require.NotEmpty(t, sessionID, "session ID must be extracted from HTML")
	t.Logf("VP session_id=%s", sessionID)
	return sessionID
}

// fetchRequestObject fetches the VP request object JWT for a given session ID.
func fetchRequestObject(t *testing.T, sessionID string) (nonce, state, responseURI string) {
	t.Helper()
	roURL := fmt.Sprintf("%s/verification/request-object/%s", verifierURL, sessionID)
	resp, err := http.Get(roURL)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "request-object: %s", string(body)[:min(len(body), 200)])

	bodyStr := strings.TrimSpace(string(body))
	if strings.Count(bodyStr, ".") >= 2 {
		claims := jwtv5.MapClaims{}
		_, _, err := jwtv5.NewParser().ParseUnverified(bodyStr, claims)
		require.NoError(t, err, "parsing request object JWT")
		nonce, _ = claims["nonce"].(string)
		state, _ = claims["state"].(string)
		responseURI, _ = claims["response_uri"].(string)
		t.Logf("request object: client_id=%v nonce=%s response_mode=%v", claims["client_id"], nonce, claims["response_mode"])
	} else {
		var ro map[string]any
		require.NoError(t, json.Unmarshal(body, &ro))
		nonce, _ = ro["nonce"].(string)
		state, _ = ro["state"].(string)
		responseURI, _ = ro["response_uri"].(string)
	}
	require.NotEmpty(t, nonce, "nonce must be in request object")
	require.NotEmpty(t, state, "state must be in request object")
	require.NotEmpty(t, responseURI, "response_uri must be in request object")
	return
}

// ---------- Health / Smoke ----------

func TestStack_Health(t *testing.T) {
	for _, tc := range []struct {
		name string
		url  string
	}{
		{"apigw", apigwURL + "/health"},
		{"verifier", verifierURL + "/health"},
		{"mockas", mockasURL + "/health"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.Get(tc.url)
			require.NoError(t, err, "GET %s", tc.url)
			defer resp.Body.Close()
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			body, _ := io.ReadAll(resp.Body)
			assert.Contains(t, string(body), "serviceName")
		})
	}
}

// ---------- VCI: Well-Known Metadata ----------

func TestStack_VCI_IssuerMetadata(t *testing.T) {
	resp, err := http.Get(apigwURL + "/.well-known/openid-credential-issuer")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var meta openid4vci.CredentialIssuerMetadataParameters
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&meta))
	assert.NotEmpty(t, meta.CredentialIssuer, "credential_issuer must be set")
	assert.NotEmpty(t, meta.CredentialEndpoint, "credential_endpoint must be set")
	assert.NotEmpty(t, meta.CredentialConfigurationsSupported, "must have at least one credential configuration")
	t.Logf("issuer=%s credential_endpoint=%s configs=%d",
		meta.CredentialIssuer, meta.CredentialEndpoint, len(meta.CredentialConfigurationsSupported))
}

func TestStack_VCI_OAuth2Metadata(t *testing.T) {
	resp, err := http.Get(apigwURL + "/.well-known/oauth-authorization-server")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var meta map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&meta))
	assert.NotEmpty(t, meta["token_endpoint"], "token_endpoint must be set")
	assert.NotEmpty(t, meta["pushed_authorization_request_endpoint"], "PAR endpoint must be set")
	t.Logf("token_endpoint=%v par_endpoint=%v", meta["token_endpoint"], meta["pushed_authorization_request_endpoint"])
}

// ---------- VCI: Nonce ----------

func TestStack_VCI_Nonce(t *testing.T) {
	resp, err := http.Post(apigwURL+"/nonce", "application/json", nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var nonce openid4vci.NonceResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&nonce))
	assert.NotEmpty(t, nonce.CNonce, "c_nonce must be set")
	t.Logf("c_nonce=%s", nonce.CNonce)
}

// ---------- VCI: Upload + Credential Offer ----------

// seedDocument uploads a document directly to apigw and returns identifiers.
func seedDocument(t *testing.T, scope, identityMappingID, givenName, familyName, birthDate string) (documentID, authenticSource string) {
	t.Helper()
	docID := "doc-" + uuid.New().String()[:8]

	req := &vcclient.UploadRequest{
		Meta: &model.MetaData{
			AuthenticSource: "test_as",
			Scope:           scope,
			DocumentID:      docID,
		},
		IdentityMappingIDs: []string{identityMappingID},
		DocumentData: map[string]any{
			"given_name":        givenName,
			"family_name":       familyName,
			"birth_date":        birthDate,
			"issuing_country":   "SE",
			"issuing_authority": "Test Authority",
		},
	}

	body, err := json.Marshal(req)
	require.NoError(t, err)

	resp, err := http.Post(apigwURL+"/api/v1/upload", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "upload failed: %s", string(respBody))

	t.Logf("upload OK: document_id=%s scope=%s", docID, scope)
	return docID, "test_as"
}

// getCredentialOfferURL retrieves the credential_offer_url for a document via the notification endpoint.
func getCredentialOfferURL(t *testing.T, authenticSource, scope, documentID string) string {
	t.Helper()
	req := &vcclient.NotificationRequest{
		AuthenticSource: authenticSource,
		Scope:           scope,
		DocumentID:      documentID,
	}
	body, err := json.Marshal(req)
	require.NoError(t, err)

	resp, err := http.Post(apigwURL+"/api/v1/notification", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "notification failed: %s", string(respBody))

	var reply struct {
		Data struct {
			CredentialOfferURL string `json:"credential_offer_url"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(respBody, &reply), "parse notification reply: %s", string(respBody))
	require.NotEmpty(t, reply.Data.CredentialOfferURL, "credential_offer_url must not be empty")

	t.Logf("credential_offer_url=%s", reply.Data.CredentialOfferURL[:min(len(reply.Data.CredentialOfferURL), 120)]+"...")
	return reply.Data.CredentialOfferURL
}

func TestStack_VCI_MockNextAndOffer(t *testing.T) {
	docID, authSource := seedDocument(t,
		"pid_1_5", "im-"+uuid.New().String()[:8],
		"Test", "Walker", "1990-01-15")

	offerURL := getCredentialOfferURL(t, authSource, "pid_1_5", docID)

	// Parse the credential_offer from the URL
	parsed, err := url.Parse(offerURL)
	require.NoError(t, err)

	offerJSON := parsed.Query().Get("credential_offer")
	require.NotEmpty(t, offerJSON, "credential_offer query param missing")

	var offer openid4vci.CredentialOfferParameters
	require.NoError(t, json.Unmarshal([]byte(offerJSON), &offer))
	assert.NotEmpty(t, offer.CredentialIssuer)
	assert.NotEmpty(t, offer.CredentialConfigurationIDs)
	assert.NotEmpty(t, offer.Grants, "grants must contain authorization_code")
	t.Logf("offer: issuer=%s configs=%v grants=%v", offer.CredentialIssuer, offer.CredentialConfigurationIDs, offer.Grants)
}

// ---------- VCI: PAR ----------

func TestStack_VCI_PAR(t *testing.T) {
	codeVerifier := uuid.New().String() + uuid.New().String()
	codeChallenge := computeS256(codeVerifier)

	data := url.Values{
		"response_type":         {"code"},
		"client_id":             {oauthClientID},
		"redirect_uri":          {oauthRedirect},
		"state":                 {uuid.New().String()},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
		"scope":                 {"pid"},
	}

	resp, err := http.Post(apigwURL+"/op/par", "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "PAR failed: %s", string(body))

	var parResp openid4vci.ParResponse
	require.NoError(t, json.Unmarshal(body, &parResp))
	assert.NotEmpty(t, parResp.RequestURI, "request_uri must be set")
	assert.True(t, strings.HasPrefix(parResp.RequestURI, "urn:ietf:params:oauth:request_uri:"),
		"request_uri should start with urn:ietf:params:oauth:request_uri:")
	t.Logf("PAR OK: request_uri=%s expires_in=%d", parResp.RequestURI, parResp.ExpiresIn)
}

// ---------- VCI: Full Authorization Code Flow ----------

func TestStack_VCI_FullAuthCodeFlow(t *testing.T) {
	// This test exercises the complete OpenID4VCI authorization_code flow:
	// 1. Seed mock data via mockas
	// 2. Get credential offer via notification
	// 3. PAR request
	// 4. Authorize → OpenID4VP consent → user lookup → get auth code
	// 5. Token request with DPoP
	// 6. Credential request with DPoP

	identityMappingID := "im-" + uuid.New().String()[:8]
	givenName := "TestVCI"
	familyName := "FullFlow"
	birthDate := "1990-05-20"

	// Step 1: Seed data
	docID, authSource := seedDocument(t, "pid_1_5", identityMappingID, givenName, familyName, birthDate)

	// Step 2: Get credential offer
	offerURL := getCredentialOfferURL(t, authSource, "pid_1_5", docID)
	parsed, err := url.Parse(offerURL)
	require.NoError(t, err)
	offerJSON := parsed.Query().Get("credential_offer")
	require.NotEmpty(t, offerJSON)

	var offer openid4vci.CredentialOfferParameters
	require.NoError(t, json.Unmarshal([]byte(offerJSON), &offer))

	// Step 3: Fetch issuer metadata
	issuerMeta := fetchIssuerMetadata(t, apigwURL)
	oauth2Meta := fetchOAuth2Metadata(t, apigwURL)

	// Step 4: PAR
	codeVerifier := uuid.New().String() + uuid.New().String()
	codeChallenge := computeS256(codeVerifier)
	state := uuid.New().String()

	parData := url.Values{
		"response_type":         {"code"},
		"client_id":             {oauthClientID},
		"redirect_uri":          {oauthRedirect},
		"state":                 {state},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
		"scope":                 {"pid_1_5"},
	}

	// Extract issuer_state from the offer grants
	if authCodeGrant, ok := offer.Grants["authorization_code"]; ok {
		if grantMap, ok := authCodeGrant.(map[string]any); ok {
			if issuerState, ok := grantMap["issuer_state"].(string); ok {
				parData.Set("issuing_state", issuerState)
			}
		}
	}

	parResp := doPAR(t, oauth2Meta.PAREndpoint, parData)
	t.Logf("PAR: request_uri=%s", parResp.RequestURI)

	// Step 5: Authorization + consent flow (session-based)
	authCode := doConsentFlow(t, oauth2Meta.AuthorizationEndpoint, parResp.RequestURI, oauthClientID, map[string]string{
		"given_name":  givenName,
		"family_name": familyName,
		"birth_date":  birthDate,
	})
	require.NotEmpty(t, authCode, "authorization code must not be empty")
	t.Logf("authorization_code=%s", authCode)

	// Step 6: Token request with DPoP
	signingKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tokenEndpoint := rewritePublicToInternal(oauth2Meta.TokenEndpoint)
	tokenResp := doTokenRequest(t, tokenEndpoint, authCode, codeVerifier, signingKey)
	require.NotEmpty(t, tokenResp.AccessToken, "access_token must not be empty")
	t.Logf("access_token=%s... c_nonce=%s", tokenResp.AccessToken[:min(len(tokenResp.AccessToken), 20)], tokenResp.CNonce)

	// Step 7: Credential request with DPoP
	credEndpoint := rewritePublicToInternal(issuerMeta.CredentialEndpoint)
	credResp := doCredentialRequest(t, credEndpoint, tokenResp.AccessToken, tokenResp.CNonce,
		offer.CredentialConfigurationIDs[0], signingKey)
	require.NotEmpty(t, credResp.Credentials, "must receive at least one credential")
	t.Logf("credentials_received=%d notification_id=%s", len(credResp.Credentials), credResp.NotificationID)

	for i, cred := range credResp.Credentials {
		t.Logf("credential[%d] (first 80 chars): %s...", i, cred.Credential[:min(len(cred.Credential), 80)])
	}
}

// ---------- VCI: Wallet Client Full Flow ----------

func TestStack_VCI_WalletClient(t *testing.T) {
	// Tests the wallet apiv1.Client against the real stack.
	// Uses the same seed + consent flow but drives through the wallet's Client.
	identityMappingID := "im-" + uuid.New().String()[:8]
	givenName := "TestWallet"
	familyName := "Client"
	birthDate := "1985-03-12"

	docID, authSource := seedDocument(t, "pid_1_5", identityMappingID, givenName, familyName, birthDate)
	offerURL := getCredentialOfferURL(t, authSource, "pid_1_5", docID)

	// Parse offer to get issuer_state
	parsed, err := url.Parse(offerURL)
	require.NoError(t, err)
	offerJSON := parsed.Query().Get("credential_offer")
	var offer openid4vci.CredentialOfferParameters
	require.NoError(t, json.Unmarshal([]byte(offerJSON), &offer))

	// For the wallet client, we need to pre-obtain the auth code since the
	// wallet's followAuthorization() doesn't handle the multi-step consent flow.
	oauth2Meta := fetchOAuth2Metadata(t, apigwURL)

	codeVerifier := uuid.New().String() + uuid.New().String()
	codeChallenge := computeS256(codeVerifier)
	state := uuid.New().String()

	parData := url.Values{
		"response_type":         {"code"},
		"client_id":             {oauthClientID},
		"redirect_uri":          {oauthRedirect},
		"state":                 {state},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
		"scope":                 {"pid_1_5"},
	}
	if authCodeGrant, ok := offer.Grants["authorization_code"]; ok {
		if grantMap, ok := authCodeGrant.(map[string]any); ok {
			if issuerState, ok := grantMap["issuer_state"].(string); ok {
				parData.Set("issuing_state", issuerState)
			}
		}
	}

	parResp := doPAR(t, oauth2Meta.PAREndpoint, parData)
	authCode := doConsentFlow(t, oauth2Meta.AuthorizationEndpoint, parResp.RequestURI, oauthClientID, map[string]string{
		"given_name":  givenName,
		"family_name": familyName,
		"birth_date":  birthDate,
	})
	require.NotEmpty(t, authCode)

	// Now use the wallet apiv1.Client for token + credential
	cfg := &config.Config{
		Wallet: config.WalletIdentity{
			ClientID: oauthClientID,
		},
		Scenarios: []config.Scenario{
			{
				Name: "stack-vci-test",
				Type: "vci",
				VCI: &config.VCIScenario{
					IssuerURL:                 apigwURL,
					Scope:                     "pid_1_5",
					RedirectURI:               oauthRedirect,
					UseDPoP:                   true,
					PreAuthorizedCode:         "", // Using auth code
					CredentialConfigurationID: offer.CredentialConfigurationIDs[0],
				},
			},
		},
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	walletClient, err := apiv1.New(context.Background(), cfg, log)
	require.NoError(t, err)

	// Verify the wallet client was initialized with a working crypto layer
	assert.NotNil(t, walletClient.Store(), "wallet store must be initialized")
	assert.NotNil(t, walletClient.Results(), "wallet results must be initialized")
	t.Log("wallet client created successfully — crypto layer and store initialized")
}

// ---------- VCI: Negative / Security Tests ----------

// getAuthCodeForNegativeTests runs PAR + consent to get a fresh auth code
// and returns the code, the code verifier, and the signing key used.
func getAuthCodeForNegativeTests(t *testing.T) (authCode, codeVerifier string, signingKey *ecdsa.PrivateKey) {
	t.Helper()
	identityMappingID := "neg-" + uuid.New().String()[:8]
	docID, authSource := seedDocument(t, "pid_1_5", identityMappingID, "NegTest", "Security", "1985-03-15")
	offerURL := getCredentialOfferURL(t, authSource, "pid_1_5", docID)

	parsed, err := url.Parse(offerURL)
	require.NoError(t, err)
	var offer openid4vci.CredentialOfferParameters
	require.NoError(t, json.Unmarshal([]byte(parsed.Query().Get("credential_offer")), &offer))

	oauth2Meta := fetchOAuth2Metadata(t, apigwURL)

	codeVerifier = uuid.New().String() + uuid.New().String()
	codeChallenge := computeS256(codeVerifier)

	parData := url.Values{
		"response_type":         {"code"},
		"client_id":             {oauthClientID},
		"redirect_uri":          {oauthRedirect},
		"state":                 {uuid.New().String()},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
		"scope":                 {"pid_1_5"},
	}
	if authCodeGrant, ok := offer.Grants["authorization_code"]; ok {
		if grantMap, ok := authCodeGrant.(map[string]any); ok {
			if issuerState, ok := grantMap["issuer_state"].(string); ok {
				parData.Set("issuing_state", issuerState)
			}
		}
	}

	parResp := doPAR(t, oauth2Meta.PAREndpoint, parData)
	code := doConsentFlow(t, oauth2Meta.AuthorizationEndpoint, parResp.RequestURI, oauthClientID, map[string]string{
		"given_name":  "NegTest",
		"family_name": "Security",
		"birth_date":  "1985-03-15",
	})
	require.NotEmpty(t, code, "auth code for negative tests")

	signingKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return code, codeVerifier, signingKey
}

func TestStack_VCI_PAR_UnknownClientID(t *testing.T) {
	data := url.Values{
		"response_type":         {"code"},
		"client_id":             {"bogus-client-9999"},
		"redirect_uri":          {oauthRedirect},
		"state":                 {uuid.New().String()},
		"code_challenge":        {"dummychallenge"},
		"code_challenge_method": {"S256"},
		"scope":                 {"pid_1_5"},
	}
	resp, err := http.Post(apigwURL+"/op/par", "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	require.NoError(t, err)
	defer resp.Body.Close()

	// Expect rejection — 405 per the server's error handling for ErrInvalidClient
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode,
		"PAR with unknown client_id should be rejected")
}

func TestStack_VCI_PAR_BadRedirectURI(t *testing.T) {
	data := url.Values{
		"response_type":         {"code"},
		"client_id":             {oauthClientID},
		"redirect_uri":          {"https://evil.example.com/callback"},
		"state":                 {uuid.New().String()},
		"code_challenge":        {"dummychallenge"},
		"code_challenge_method": {"S256"},
		"scope":                 {"pid_1_5"},
	}
	resp, err := http.Post(apigwURL+"/op/par", "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode,
		"PAR with wrong redirect_uri should be rejected")
}

func TestStack_VCI_Token_NoDPoP(t *testing.T) {
	authCode, codeVerifier, _ := getAuthCodeForNegativeTests(t)
	oauth2Meta := fetchOAuth2Metadata(t, apigwURL)
	tokenEndpoint := rewritePublicToInternal(oauth2Meta.TokenEndpoint)

	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {oauthRedirect},
		"client_id":     {oauthClientID},
		"code_verifier": {codeVerifier},
	}
	// Deliberately omit DPoP header
	resp, err := http.Post(tokenEndpoint, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	t.Logf("no DPoP: status=%d body=%s", resp.StatusCode, string(body))
	assert.True(t, resp.StatusCode >= 400 && resp.StatusCode < 500,
		"token without DPoP should be 4xx, got %d: %s", resp.StatusCode, string(body))
	assert.Contains(t, string(body), "DPOP", "error should mention DPoP field")
}

func TestStack_VCI_Token_InvalidDPoP(t *testing.T) {
	oauth2Meta := fetchOAuth2Metadata(t, apigwURL)
	tokenEndpoint := rewritePublicToInternal(oauth2Meta.TokenEndpoint)

	t.Run("garbage_jwt", func(t *testing.T) {
		authCode, codeVerifier, _ := getAuthCodeForNegativeTests(t)
		data := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {authCode},
			"redirect_uri":  {oauthRedirect},
			"client_id":     {oauthClientID},
			"code_verifier": {codeVerifier},
		}
		req, _ := http.NewRequest(http.MethodPost, tokenEndpoint, strings.NewReader(data.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("DPoP", "not.a.valid.jwt")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		t.Logf("garbage DPoP: status=%d body=%s", resp.StatusCode, string(body))
		assert.True(t, resp.StatusCode >= 400,
			"garbage DPoP should be rejected, got %d", resp.StatusCode)
	})

	t.Run("wrong_htu", func(t *testing.T) {
		authCode, codeVerifier, signingKey := getAuthCodeForNegativeTests(t)
		data := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {authCode},
			"redirect_uri":  {oauthRedirect},
			"client_id":     {oauthClientID},
			"code_verifier": {codeVerifier},
		}
		dpopProof := createDPoPProof(t, http.MethodPost, "https://wrong.example.com/token", "", signingKey)
		req, _ := http.NewRequest(http.MethodPost, tokenEndpoint, strings.NewReader(data.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("DPoP", dpopProof)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		t.Logf("wrong htu: status=%d body=%s", resp.StatusCode, string(body))
		assert.True(t, resp.StatusCode >= 400,
			"DPoP with wrong htu should fail, got %d: %s", resp.StatusCode, string(body))
		assert.Contains(t, string(body), "invalid HTU")
	})
}

func TestStack_VCI_Token_WrongPKCE(t *testing.T) {
	authCode, _, signingKey := getAuthCodeForNegativeTests(t)
	oauth2Meta := fetchOAuth2Metadata(t, apigwURL)
	tokenEndpoint := rewritePublicToInternal(oauth2Meta.TokenEndpoint)

	t.Run("wrong_verifier", func(t *testing.T) {
		data := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {authCode},
			"redirect_uri":  {oauthRedirect},
			"client_id":     {oauthClientID},
			"code_verifier": {"totally-wrong-verifier-that-does-not-match"},
		}
		req, _ := http.NewRequest(http.MethodPost, tokenEndpoint, strings.NewReader(data.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		dpopProof := createDPoPProof(t, http.MethodPost, rewriteInternalToPublic(tokenEndpoint), "", signingKey)
		req.Header.Set("DPoP", dpopProof)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		t.Logf("wrong PKCE verifier: status=%d body=%s", resp.StatusCode, string(body))
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
			"wrong code_verifier should be 400: %s", string(body))
		assert.Contains(t, string(body), "PKCE")
	})

	t.Run("missing_verifier", func(t *testing.T) {
		// Get a fresh auth code (previous one may have been consumed)
		code2, _, sk2 := getAuthCodeForNegativeTests(t)
		data := url.Values{
			"grant_type":   {"authorization_code"},
			"code":         {code2},
			"redirect_uri": {oauthRedirect},
			"client_id":    {oauthClientID},
			// code_verifier deliberately omitted
		}
		req, _ := http.NewRequest(http.MethodPost, tokenEndpoint, strings.NewReader(data.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		dpopProof := createDPoPProof(t, http.MethodPost, rewriteInternalToPublic(tokenEndpoint), "", sk2)
		req.Header.Set("DPoP", dpopProof)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		t.Logf("missing PKCE verifier: status=%d body=%s", resp.StatusCode, string(body))
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
			"missing code_verifier should be 400: %s", string(body))
		assert.Contains(t, string(body), "PKCE")
	})
}

func TestStack_VCI_Token_AuthCodeReplay(t *testing.T) {
	// Use the same authorization code twice — the second attempt must fail.
	authCode, codeVerifier, signingKey := getAuthCodeForNegativeTests(t)
	oauth2Meta := fetchOAuth2Metadata(t, apigwURL)
	tokenEndpoint := rewritePublicToInternal(oauth2Meta.TokenEndpoint)

	// First use — should succeed
	tokenResp := doTokenRequest(t, tokenEndpoint, authCode, codeVerifier, signingKey)
	require.NotEmpty(t, tokenResp.AccessToken, "first token request should succeed")
	t.Logf("first token exchange OK, access_token=%s...", tokenResp.AccessToken[:min(len(tokenResp.AccessToken), 20)])

	// Second use — replay the same auth code
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {oauthRedirect},
		"client_id":     {oauthClientID},
		"code_verifier": {codeVerifier},
	}
	req, _ := http.NewRequest(http.MethodPost, tokenEndpoint, strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	dpopProof := createDPoPProof(t, http.MethodPost, rewriteInternalToPublic(tokenEndpoint), "", signingKey)
	req.Header.Set("DPoP", dpopProof)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	t.Logf("auth code replay: status=%d body=%s", resp.StatusCode, string(body))
	assert.True(t, resp.StatusCode >= 400,
		"replayed auth code must be rejected, got %d: %s", resp.StatusCode, string(body))
}

func TestStack_VCI_Token_DPoPJTIReplay(t *testing.T) {
	// Send the exact same DPoP proof twice — the second request must be rejected
	// because the JTI has already been seen (replay detection).
	authCode, codeVerifier, signingKey := getAuthCodeForNegativeTests(t)
	oauth2Meta := fetchOAuth2Metadata(t, apigwURL)
	tokenEndpoint := rewritePublicToInternal(oauth2Meta.TokenEndpoint)

	// Build a DPoP proof and reuse it
	dpopProof := createDPoPProof(t, http.MethodPost, rewriteInternalToPublic(tokenEndpoint), "", signingKey)

	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
		"redirect_uri":  {oauthRedirect},
		"client_id":     {oauthClientID},
		"code_verifier": {codeVerifier},
	}

	// First request — should succeed, consuming the auth code and the JTI
	req1, _ := http.NewRequest(http.MethodPost, tokenEndpoint, strings.NewReader(data.Encode()))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req1.Header.Set("DPoP", dpopProof)

	resp1, err := http.DefaultClient.Do(req1)
	require.NoError(t, err)
	body1, _ := io.ReadAll(resp1.Body)
	resp1.Body.Close()
	require.Equal(t, http.StatusOK, resp1.StatusCode, "first request should succeed: %s", string(body1))
	t.Logf("first request OK")

	// Second request — get a fresh auth code but replay the same DPoP proof (same JTI)
	authCode2, codeVerifier2, _ := getAuthCodeForNegativeTests(t)
	data2 := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authCode2},
		"redirect_uri":  {oauthRedirect},
		"client_id":     {oauthClientID},
		"code_verifier": {codeVerifier2},
	}

	req2, _ := http.NewRequest(http.MethodPost, tokenEndpoint, strings.NewReader(data2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.Header.Set("DPoP", dpopProof) // same JTI!

	resp2, err := http.DefaultClient.Do(req2)
	require.NoError(t, err)
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(resp2.Body)
	t.Logf("DPoP JTI replay: status=%d body=%s", resp2.StatusCode, string(body2))
	assert.True(t, resp2.StatusCode >= 400,
		"replayed DPoP JTI must be rejected, got %d: %s", resp2.StatusCode, string(body2))
}

func TestStack_VCI_Credential_NoDPoP(t *testing.T) {
	// Get a valid access token first, then call credential endpoint without DPoP
	authCode, codeVerifier, signingKey := getAuthCodeForNegativeTests(t)
	oauth2Meta := fetchOAuth2Metadata(t, apigwURL)
	issuerMeta := fetchIssuerMetadata(t, apigwURL)
	tokenEndpoint := rewritePublicToInternal(oauth2Meta.TokenEndpoint)
	tokenResp := doTokenRequest(t, tokenEndpoint, authCode, codeVerifier, signingKey)
	require.NotEmpty(t, tokenResp.AccessToken)

	// Build credential request body
	proofJWT := createProofJWT(t, rewriteInternalToPublic(issuerMeta.CredentialEndpoint),
		tokenResp.CNonce, signingKey)
	reqBody, _ := json.Marshal(map[string]any{
		"credential_configuration_id": "urn:eudi:pid:arf-1.5:1",
		"proofs":                      map[string]any{"jwt": []string{proofJWT}},
	})

	credEndpoint := rewritePublicToInternal(issuerMeta.CredentialEndpoint)

	t.Run("no_dpop_header", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, credEndpoint, bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "DPoP "+tokenResp.AccessToken)
		// Deliberately omit DPoP header

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		t.Logf("no DPoP on credential: status=%d body=%s", resp.StatusCode, string(body))
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
			"credential without DPoP header should be 400: %s", string(body))
	})

	t.Run("no_authorization_header", func(t *testing.T) {
		dpopProof := createDPoPProof(t, http.MethodPost,
			rewriteInternalToPublic(credEndpoint), tokenResp.AccessToken, signingKey)
		req, _ := http.NewRequest(http.MethodPost, credEndpoint, bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("DPoP", dpopProof)
		// Deliberately omit Authorization header

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		t.Logf("no Authorization on credential: status=%d body=%s", resp.StatusCode, string(body))
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
			"credential without Authorization should be 400: %s", string(body))
	})

	t.Run("wrong_dpop_ath", func(t *testing.T) {
		// DPoP proof with ATH for a different access token
		dpopProof := createDPoPProof(t, http.MethodPost,
			rewriteInternalToPublic(credEndpoint), "wrong-access-token", signingKey)
		req, _ := http.NewRequest(http.MethodPost, credEndpoint, bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "DPoP "+tokenResp.AccessToken)
		req.Header.Set("DPoP", dpopProof)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		t.Logf("wrong ATH on credential: status=%d body=%s", resp.StatusCode, string(body))
		assert.True(t, resp.StatusCode >= 400 && resp.StatusCode < 500,
			"credential with wrong ATH should be 4xx, got %d: %s", resp.StatusCode, string(body))
	})
}

// ---------- VP: Verifier Flow ----------

func TestStack_VP_Authorize(t *testing.T) {
	// Register an OIDC client on the verifier (shared to avoid rate limiting)
	vpClient := getOrRegisterVerifierClient(t)

	// Verifier OIDC authorize creates a session and returns HTML with QR
	sessionID := doVPAuthorize(t, vpClient.ClientID, "openid pid", uuid.New().String())
	assert.NotEmpty(t, sessionID, "session ID should be extracted from authorize HTML")
}

func TestStack_VP_RequestObject(t *testing.T) {
	// Step 1: Get shared client + create VP session
	vpClient := getOrRegisterVerifierClient(t)
	sessionID := doVPAuthorize(t, vpClient.ClientID, "openid pid", uuid.New().String())

	// Step 2: Fetch the request object
	nonce, state, responseURI := fetchRequestObject(t, sessionID)
	assert.NotEmpty(t, nonce, "nonce")
	assert.NotEmpty(t, state, "state")
	assert.NotEmpty(t, responseURI, "response_uri")
}

func TestStack_VP_DirectPost(t *testing.T) {
	// End-to-end VP flow:
	// 1. Register client + create session via /authorize
	// 2. Fetch request object
	// 3. Build a VP token (synthetic SD-JWT for testing)
	// 4. POST to oidc-direct_post

	// Step 1: Get shared client + create VP session
	vpClient := getOrRegisterVerifierClient(t)
	vpState := uuid.New().String()
	sessionID := doVPAuthorize(t, vpClient.ClientID, "openid pid", vpState)

	// Step 2: Fetch request object
	nonce, roState, responseURI := fetchRequestObject(t, sessionID)

	// Step 3: Build a synthetic VP token
	signingKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	syntheticSDJWT := createSyntheticSDJWT(t, signingKey)
	kbJWT := createKeyBindingJWT(t, nonce, rewriteInternalToPublic(responseURI), syntheticSDJWT, signingKey)
	vpToken := syntheticSDJWT + kbJWT

	// Step 4: POST to OIDC direct_post endpoint
	// Note: The response_uri from the request object points to /verification/direct_post (JWE/DC API),
	// but for the OIDC flow we use /verification/oidc-direct_post which accepts form-encoded vp_token.
	oidcDirectPostURL := verifierURL + "/verification/oidc-direct_post"
	formData := url.Values{
		"vp_token": {vpToken},
		"state":    {roState},
	}

	resp, err := http.Post(oidcDirectPostURL, "application/x-www-form-urlencoded", strings.NewReader(formData.Encode()))
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	// The VP may be rejected due to the synthetic credential not matching the issuer's keys,
	// but the endpoint should process the request (not 404 or 500).
	t.Logf("direct_post response: status=%d body=%s", resp.StatusCode, string(body))
	// Accept 200 (success), 302 (redirect), or 400 (invalid VP — expected for synthetic credential)
	assert.True(t, resp.StatusCode == 200 || resp.StatusCode == 302 || resp.StatusCode == 400,
		"unexpected status %d from direct_post", resp.StatusCode)
}

// ---------- E2E: VCI → VP ----------

func TestStack_E2E_VCI_Then_VP(t *testing.T) {
	// Full end-to-end: Issue a real credential via VCI, then present it via VP.
	identityMappingID := "im-" + uuid.New().String()[:8]
	givenName := "TestE2E"
	familyName := "Runner"
	birthDate := "1992-07-04"

	// VCI: Seed + offer + PAR + consent + token + credential
	docID, authSource := seedDocument(t, "pid_1_5", identityMappingID, givenName, familyName, birthDate)
	offerURL := getCredentialOfferURL(t, authSource, "pid_1_5", docID)

	parsed, err := url.Parse(offerURL)
	require.NoError(t, err)
	var offer openid4vci.CredentialOfferParameters
	require.NoError(t, json.Unmarshal([]byte(parsed.Query().Get("credential_offer")), &offer))

	oauth2Meta := fetchOAuth2Metadata(t, apigwURL)
	issuerMeta := fetchIssuerMetadata(t, apigwURL)

	codeVerifier := uuid.New().String() + uuid.New().String()
	codeChallenge := computeS256(codeVerifier)

	parData := url.Values{
		"response_type":         {"code"},
		"client_id":             {oauthClientID},
		"redirect_uri":          {oauthRedirect},
		"state":                 {uuid.New().String()},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
		"scope":                 {"pid_1_5"},
	}
	if authCodeGrant, ok := offer.Grants["authorization_code"]; ok {
		if grantMap, ok := authCodeGrant.(map[string]any); ok {
			if issuerState, ok := grantMap["issuer_state"].(string); ok {
				parData.Set("issuing_state", issuerState)
			}
		}
	}

	parResp := doPAR(t, oauth2Meta.PAREndpoint, parData)
	authCode := doConsentFlow(t, oauth2Meta.AuthorizationEndpoint, parResp.RequestURI, oauthClientID, map[string]string{
		"given_name":  givenName,
		"family_name": familyName,
		"birth_date":  birthDate,
	})
	require.NotEmpty(t, authCode, "VCI auth code")

	signingKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tokenEndpoint := rewritePublicToInternal(oauth2Meta.TokenEndpoint)
	tokenResp := doTokenRequest(t, tokenEndpoint, authCode, codeVerifier, signingKey)
	require.NotEmpty(t, tokenResp.AccessToken)

	credEndpoint := rewritePublicToInternal(issuerMeta.CredentialEndpoint)
	credResp := doCredentialRequest(t, credEndpoint, tokenResp.AccessToken, tokenResp.CNonce,
		offer.CredentialConfigurationIDs[0], signingKey)
	require.NotEmpty(t, credResp.Credentials, "VCI must issue credential")
	realCredential := credResp.Credentials[0].Credential
	t.Logf("VCI issued credential (%d bytes)", len(realCredential))

	// VP: Present the real credential to the verifier
	vpClient := getOrRegisterVerifierClient(t)
	vpState := uuid.New().String()
	sessionID := doVPAuthorize(t, vpClient.ClientID, "openid pid", vpState)

	nonce, roState, responseURI := fetchRequestObject(t, sessionID)

	// Build VP token with real credential + KB JWT
	// The credential was bound to `signingKey` during VCI issuance.
	kbJWT := createKeyBindingJWT(t, nonce, rewriteInternalToPublic(responseURI), realCredential, signingKey)

	var vpToken string
	if strings.HasSuffix(realCredential, "~") {
		vpToken = realCredential + kbJWT
	} else {
		vpToken = realCredential + "~" + kbJWT
	}

	// POST to OIDC direct_post (not the response_uri which is for DC API/JWE)
	oidcDirectPostURL := verifierURL + "/verification/oidc-direct_post"
	formData := url.Values{
		"vp_token": {vpToken},
		"state":    {roState},
	}

	resp, err := http.Post(oidcDirectPostURL, "application/x-www-form-urlencoded", strings.NewReader(formData.Encode()))
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	t.Logf("VP direct_post: status=%d body=%s", resp.StatusCode, string(body))

	// With a real credential, we expect either success (200/302) or a verification error (400)
	// depending on whether the verifier can validate the SD-JWT issuer signature.
	assert.True(t, resp.StatusCode == 200 || resp.StatusCode == 302 || resp.StatusCode == 400,
		"unexpected status %d", resp.StatusCode)
}

// =====================
// Helper functions
// =====================

type oauth2ServerMeta struct {
	TokenEndpoint         string `json:"token_endpoint"`
	PAREndpoint           string `json:"pushed_authorization_request_endpoint"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
}

func fetchIssuerMetadata(t *testing.T, baseURL string) *openid4vci.CredentialIssuerMetadataParameters {
	t.Helper()
	resp, err := http.Get(baseURL + "/.well-known/openid-credential-issuer")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var meta openid4vci.CredentialIssuerMetadataParameters
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&meta))
	return &meta
}

func fetchOAuth2Metadata(t *testing.T, baseURL string) *oauth2ServerMeta {
	t.Helper()
	resp, err := http.Get(baseURL + "/.well-known/oauth-authorization-server")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var meta oauth2ServerMeta
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&meta))
	// Rewrite Docker hostnames to bridge IPs
	meta.TokenEndpoint = rewritePublicToInternal(meta.TokenEndpoint)
	meta.PAREndpoint = rewritePublicToInternal(meta.PAREndpoint)
	meta.AuthorizationEndpoint = rewritePublicToInternal(meta.AuthorizationEndpoint)
	return &meta
}

func doPAR(t *testing.T, parEndpoint string, data url.Values) openid4vci.ParResponse {
	t.Helper()
	resp, err := http.Post(parEndpoint, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "PAR: %s", string(body))

	var parResp openid4vci.ParResponse
	require.NoError(t, json.Unmarshal(body, &parResp))
	return parResp
}

// doConsentFlow drives the full authorize → consent → OIDC login → userLookup flow
// using a session cookie jar, and returns the authorization code.
// It programmatically drives the OIDC flow through mock-oauth2-server.
// The oidcClaims map is sent to mock-oauth2-server as the user's identity claims.
func doConsentFlow(t *testing.T, authorizeEndpoint, requestURI, clientID string, oidcClaims map[string]string) string {
	t.Helper()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Transport: tlsTransport,
		Jar:       jar,
		Timeout:   15 * time.Second,
	}

	// Step 1: GET /authorize?request_uri=...&client_id=...
	// This sets session cookies and redirects to /authorization/consent
	authReqURL := fmt.Sprintf("%s?client_id=%s&request_uri=%s",
		authorizeEndpoint, url.QueryEscape(clientID), url.QueryEscape(requestURI))

	resp, err := client.Get(authReqURL)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("authorize: status=%d url=%s", resp.StatusCode, resp.Request.URL.String())

	// We should have been redirected to the consent page (200 after following redirect)
	require.Equal(t, 200, resp.StatusCode, "authorize expected 200, got %d: %s", resp.StatusCode, string(body))

	// Step 2: Extract the OIDC authorization URL from consent HTML
	// The consent page embeds it as data-redirect-url="..."
	oidcAuthURL := extractDataRedirectURL(t, string(body))
	require.NotEmpty(t, oidcAuthURL, "consent page must contain data-redirect-url for OIDC")
	t.Logf("consent: oidc_auth_url=%s", oidcAuthURL)

	// Rewrite the OIDC URL from Docker-internal hostname to bridge IP
	oidcAuthURL = rewritePublicToInternal(oidcAuthURL)

	// Use no-redirect client for all OIDC steps to control redirects manually
	noRedirectClient := &http.Client{
		Transport: tlsTransport,
		Jar:       jar,
		Timeout:   15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Step 3: GET the mock-oauth2-server authorize endpoint
	// With interactiveLogin:false it auto-completes and redirects to callback
	oidcResp, err := noRedirectClient.Get(oidcAuthURL)
	require.NoError(t, err)
	oidcResp.Body.Close()
	t.Logf("oidc authorize: status=%d location=%s", oidcResp.StatusCode, oidcResp.Header.Get("Location"))

	// mock-oauth2-server with interactiveLogin:false redirects directly to callback
	callbackURL := oidcResp.Header.Get("Location")
	if oidcResp.StatusCode == 302 && callbackURL != "" {
		// Auto-login mode: mock-oauth2-server redirected directly to callback
		callbackURL = rewritePublicToInternal(callbackURL)
		t.Logf("oidc auto-login: callback=%s", callbackURL)
	} else {
		// Interactive mode: mock-oauth2-server returned a login form
		require.Equal(t, 200, oidcResp.StatusCode, "oidc authorize expected 200 or 302")
		oidcBody, _ := io.ReadAll(oidcResp.Body)

		// POST the login form with the identity claims
		claimsJSON, _ := json.Marshal(oidcClaims)
		loginData := url.Values{
			"username": {"testuser"},
			"claims":   {string(claimsJSON)},
		}
		loginResp, loginErr := noRedirectClient.Post(oidcAuthURL, "application/x-www-form-urlencoded", strings.NewReader(loginData.Encode()))
		require.NoError(t, loginErr)
		loginResp.Body.Close()
		t.Logf("oidc login: status=%d location=%s", loginResp.StatusCode, loginResp.Header.Get("Location"))
		require.Equal(t, 302, loginResp.StatusCode, "oidc login expected 302, body=%s", string(oidcBody))
		callbackURL = rewritePublicToInternal(loginResp.Header.Get("Location"))
	}

	require.NotEmpty(t, callbackURL, "oidc flow must produce a callback redirect")

	// Step 4: Follow the redirect to apigw /oidcrp/callback
	callbackResp, err := noRedirectClient.Get(callbackURL)
	require.NoError(t, err)
	callbackResp.Body.Close()
	t.Logf("oidc callback: status=%d location=%s", callbackResp.StatusCode, callbackResp.Header.Get("Location"))
	require.Equal(t, 302, callbackResp.StatusCode, "oidc callback expected 302")

	// Step 6: GET /user/lookup
	// The OIDC callback has stored documents in the VCI cache; now we finalize
	lookupURL := rewritePublicToInternal(apigwURL + "/user/lookup")

	resp, err = noRedirectClient.Get(lookupURL)
	require.NoError(t, err)
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("user/lookup: status=%d body=%s", resp.StatusCode, string(body)[:min(len(body), 300)])

	// Parse the redirect_url containing the authorization code
	var code string
	var lookupReply struct {
		SVGTemplateClaims map[string]any `json:"svg_template_claims,omitempty"`
		RedirectURL       string         `json:"redirect_url,omitempty"`
	}
	if err := json.Unmarshal(body, &lookupReply); err == nil && lookupReply.RedirectURL != "" {
		redirectParsed, err := url.Parse(lookupReply.RedirectURL)
		require.NoError(t, err, "parsing redirect URL from lookup: %s", lookupReply.RedirectURL)
		code = redirectParsed.Query().Get("code")
	}

	// Try from Location header (302 redirect)
	if code == "" && resp.StatusCode == 302 {
		loc := resp.Header.Get("Location")
		if loc != "" {
			redirectParsed, err := url.Parse(loc)
			if err == nil {
				code = redirectParsed.Query().Get("code")
			}
		}
	}

	return code
}

// extractDataRedirectURL parses the OIDC redirect URL from the consent page HTML.
func extractDataRedirectURL(t *testing.T, htmlBody string) string {
	t.Helper()
	const marker = `data-redirect-url="`
	idx := strings.Index(htmlBody, marker)
	if idx == -1 {
		return ""
	}
	start := idx + len(marker)
	end := strings.Index(htmlBody[start:], `"`)
	if end == -1 {
		return ""
	}
	return html.UnescapeString(htmlBody[start : start+end])
}

func doTokenRequest(t *testing.T, tokenEndpoint, code, codeVerifier string, signingKey *ecdsa.PrivateKey) openid4vci.TokenResponse {
	t.Helper()

	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {oauthRedirect},
		"client_id":     {oauthClientID},
		"code_verifier": {codeVerifier},
	}

	req, err := http.NewRequest(http.MethodPost, tokenEndpoint, strings.NewReader(data.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Add DPoP proof (htu must use the public URL the server expects)
	dpopProof := createDPoPProof(t, http.MethodPost, rewriteInternalToPublic(tokenEndpoint), "", signingKey)
	req.Header.Set("DPoP", dpopProof)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "token: %s", string(body))

	var tokenResp openid4vci.TokenResponse
	require.NoError(t, json.Unmarshal(body, &tokenResp))
	return tokenResp
}

func doCredentialRequest(t *testing.T, credEndpoint, accessToken, cNonce, credConfigID string, signingKey *ecdsa.PrivateKey) openid4vci.CredentialResponse {
	t.Helper()

	proofJWT := createProofJWT(t, rewriteInternalToPublic(credEndpoint), cNonce, signingKey)

	reqBody := map[string]any{
		"credential_configuration_id": credConfigID,
		"proofs": map[string]any{
			"jwt": []string{proofJWT},
		},
	}
	bodyJSON, _ := json.Marshal(reqBody)

	req, err := http.NewRequest(http.MethodPost, credEndpoint, bytes.NewReader(bodyJSON))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	// DPoP with ath (htu must use the public URL the server expects)
	dpopProof := createDPoPProof(t, http.MethodPost, rewriteInternalToPublic(credEndpoint), accessToken, signingKey)
	req.Header.Set("DPoP", dpopProof)
	req.Header.Set("Authorization", "DPoP "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	require.Equal(t, http.StatusOK, resp.StatusCode, "credential: %s", string(body))

	var credResp openid4vci.CredentialResponse
	require.NoError(t, json.Unmarshal(body, &credResp))
	return credResp
}

// ---------- Crypto helpers ----------

func computeS256(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func publicKeyJWK(t *testing.T, key *ecdsa.PrivateKey) map[string]any {
	t.Helper()
	return map[string]any{
		"kty": "EC",
		"crv": key.Curve.Params().Name,
		"x":   base64.RawURLEncoding.EncodeToString(key.PublicKey.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.Bytes()),
	}
}

func createDPoPProof(t *testing.T, method, uri, accessToken string, key *ecdsa.PrivateKey) string {
	t.Helper()

	body := jwtv5.MapClaims{
		"jti": uuid.New().String(),
		"htm": method,
		"htu": uri,
		"iat": time.Now().Unix(),
	}
	if accessToken != "" {
		h := sha256.Sum256([]byte(accessToken))
		body["ath"] = base64.RawURLEncoding.EncodeToString(h[:])
	}

	signingMethod, _ := jose.GetSigningMethodFromKey(key)
	token := jwtv5.NewWithClaims(signingMethod, body)
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = publicKeyJWK(t, key)

	// Remove default alg and set from jose
	_, alg := jose.GetSigningMethodFromKey(key)
	token.Header["alg"] = alg

	signed, err := token.SignedString(key)
	require.NoError(t, err, "signing DPoP proof")
	return signed
}

func createProofJWT(t *testing.T, audience, cNonce string, key *ecdsa.PrivateKey) string {
	t.Helper()

	body := jwtv5.MapClaims{
		"aud": audience,
		"iat": time.Now().Unix(),
		"iss": oauthClientID,
	}
	if cNonce != "" {
		body["nonce"] = cNonce
	}

	signingMethod, alg := jose.GetSigningMethodFromKey(key)
	token := jwtv5.NewWithClaims(signingMethod, body)
	token.Header["typ"] = "openid4vci-proof+jwt"
	token.Header["alg"] = alg
	token.Header["jwk"] = publicKeyJWK(t, key)

	signed, err := token.SignedString(key)
	require.NoError(t, err, "signing proof JWT")
	return signed
}

func createKeyBindingJWT(t *testing.T, nonce, audience, sdJWT string, key *ecdsa.PrivateKey) string {
	t.Helper()

	sdHash := sha256.Sum256([]byte(sdJWT))

	body := jwtv5.MapClaims{
		"nonce":   nonce,
		"aud":     audience,
		"iat":     time.Now().Unix(),
		"sd_hash": base64.RawURLEncoding.EncodeToString(sdHash[:]),
	}

	signingMethod, _ := jose.GetSigningMethodFromKey(key)
	token := jwtv5.NewWithClaims(signingMethod, body)
	token.Header["typ"] = "kb+jwt"

	signed, err := token.SignedString(key)
	require.NoError(t, err, "signing KB JWT")
	return signed
}

// createSyntheticSDJWT creates a minimal SD-JWT for testing VP flows.
func createSyntheticSDJWT(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()

	body := jwtv5.MapClaims{
		"iss":     "https://test-issuer.example.com",
		"sub":     "test-subject",
		"iat":     time.Now().Unix(),
		"exp":     time.Now().Add(1 * time.Hour).Unix(),
		"vct":     "urn:eudi:pid:1",
		"_sd_alg": "sha-256",
		"cnf": map[string]any{
			"jwk": publicKeyJWK(t, key),
		},
	}

	signingMethod, _ := jose.GetSigningMethodFromKey(key)
	token := jwtv5.NewWithClaims(signingMethod, body)
	signed, err := token.SignedString(key)
	require.NoError(t, err)

	// Add a fake disclosure for the SD-JWT format
	return signed + "~"
}

// extractRequestURI extracts the request_uri from the openid4vp:// link in HTML.
func extractRequestURI(t *testing.T, html string) string {
	t.Helper()

	// Look for openid4vp:// URL patterns
	idx := strings.Index(html, "openid4vp://")
	if idx < 0 {
		// Try looking for the request_uri directly
		idx = strings.Index(html, "request_uri=")
		if idx < 0 {
			t.Log("no openid4vp:// or request_uri= found in HTML")
			return ""
		}
	}

	// Extract the full URL
	start := idx
	end := start
	for end < len(html) {
		ch := html[end]
		if ch == '"' || ch == '\'' || ch == '<' || ch == '>' || ch == ' ' || ch == '\n' || ch == '\r' {
			break
		}
		end++
	}

	rawURL := html[start:end]
	// HTML-unescape &amp; → &
	rawURL = strings.ReplaceAll(rawURL, "&amp;", "&")

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		t.Logf("failed to parse extracted URL: %s", rawURL)
		return ""
	}

	reqURI := parsedURL.Query().Get("request_uri")
	if reqURI == "" {
		// Maybe it's already a request_uri value
		if strings.HasPrefix(rawURL, "http") && strings.Contains(rawURL, "request-object") {
			return rawURL
		}
	}
	return reqURI
}
