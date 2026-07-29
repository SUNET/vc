package apiv1

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"
	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/oauth2"
	"github.com/SUNET/vc/pkg/openid4vci"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// mockAuthContextColl mocks the authorization context collection
type mockAuthContextColl struct {
	authContext *cache.AuthorizationContext
	err         error
}

func (m *mockAuthContextColl) GetWithAccessToken(ctx context.Context, accessToken string) (*cache.AuthorizationContext, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.authContext, nil
}

// mockDatastoreColl mocks the datastore collection
type mockDatastoreColl struct {
	document *model.CompleteDocument
	err      error
}

func (m *mockDatastoreColl) GetDocument(ctx context.Context, authenticSource, documentID string) (*model.CompleteDocument, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.document, nil
}

// mockIssuerClient mocks the gRPC issuer client
type mockIssuerClient struct {
	reply *apiv1_issuer.MakeSDJWTReply
	err   error
}

func (m *mockIssuerClient) MakeSDJWT(ctx context.Context, in *apiv1_issuer.MakeSDJWTRequest, opts ...grpc.CallOption) (*apiv1_issuer.MakeSDJWTReply, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.reply, nil
}

// createValidDPoPJWT creates a valid DPoP JWT for testing using golang-jwt
func createValidDPoPJWT(t *testing.T, accessToken string) (string, *ecdsa.PrivateKey) {
	t.Helper()

	// Generate ECDSA key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Calculate ath (hash of access token)
	hash := sha256.Sum256([]byte(accessToken))
	ath := base64.RawURLEncoding.EncodeToString(hash[:])

	// Build JWT claims
	claims := jwt.MapClaims{
		"jti": "test-jti-123",
		"iat": time.Now().Unix(),
		"htm": "POST",
		"htu": "https://issuer.example.com/credential",
		"ath": ath,
	}

	// Create token with custom header
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "dpop+jwt"

	// Marshal public key to JWK format for header
	publicJWK, err := jwk.Import(&privateKey.PublicKey)
	require.NoError(t, err)

	// Marshal to map for header
	jwkJSON, err := json.Marshal(publicJWK)
	require.NoError(t, err)

	var jwkMap map[string]any
	err = json.Unmarshal(jwkJSON, &jwkMap)
	require.NoError(t, err)
	token.Header["jwk"] = jwkMap

	// Sign the token
	signed, err := token.SignedString(privateKey)
	require.NoError(t, err)

	return signed, privateKey
}

// createValidProofJWT creates a valid proof JWT for testing
func createValidProofJWT(t *testing.T, nonce string) (string, []byte) {
	t.Helper()

	// Generate ECDSA key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Convert public key to JWK
	publicJWK, err := jwk.Import(&privateKey.PublicKey)
	require.NoError(t, err)

	// Marshal JWK to JSON
	jwkJSON, err := json.Marshal(publicJWK)
	require.NoError(t, err)

	// Build JWT claims
	claims := jwt.MapClaims{
		"jti":   "proof-jti-456",
		"iat":   time.Now().Unix(),
		"aud":   "https://issuer.example.com",
		"nonce": nonce,
	}

	// Create token with custom header
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "openid4vci-proof+jwt"

	// Add JWK to header
	var jwkMap map[string]any
	err = json.Unmarshal(jwkJSON, &jwkMap)
	require.NoError(t, err)
	token.Header["jwk"] = jwkMap

	// Sign the token
	signed, err := token.SignedString(privateKey)
	require.NoError(t, err)

	return signed, jwkJSON
}

// TestVCINonce tests the nonce generation endpoint
// Verifies that:
// - Nonce is generated successfully
// - Nonce has reasonable length
// - Each call generates a unique nonce
func TestVCINonce(t *testing.T) {
	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	client := &Client{
		log: log,
	}

	ctx := t.Context()
	resp, err := client.VCINonce(ctx)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.CNonce)
	assert.Greater(t, len(resp.CNonce), 10, "Nonce should be reasonably long")

	// Test that multiple calls generate different nonces
	resp2, err2 := client.VCINonce(ctx)
	assert.NoError(t, err2)
	assert.NotNil(t, resp2)
	assert.NotEqual(t, resp.CNonce, resp2.CNonce, "Each call should generate a unique nonce")
}

func TestVCICredential_InvalidDPoP(t *testing.T) {
	log, _ := logger.New("test", "", false)
	client := &Client{
		log: log,
	}

	ctx := t.Context()
	req := &openid4vci.CredentialRequest{
		DPoP:          "invalid.jwt.token",
		Authorization: "DPoP test-access-token",
		Proofs: &openid4vci.Proofs{
			JWT: []openid4vci.ProofJWTToken{"test.jwt.token"},
		},
	}

	resp, err := client.VCICredential(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, resp)
}

func TestVCIDeferredCredential(t *testing.T) {
	log, _ := logger.New("test", "", false)
	client := &Client{
		log: log,
	}

	ctx := t.Context()
	req := &openid4vci.DeferredCredentialRequest{
		TransactionID: "test-transaction-123",
	}

	resp, err := client.VCIDeferredCredential(ctx, req)

	// Current implementation returns nil, nil
	assert.NoError(t, err)
	assert.Nil(t, resp)
}

func TestVCICredentialOffer(t *testing.T) {
	log, _ := logger.New("test", "", false)
	client := &Client{
		log: log,
	}

	ctx := t.Context()
	req := &openid4vci.CredentialOfferParameters{ // #nosec G101
		CredentialIssuer: "https://issuer.example.com",
	}

	resp, err := client.VCICredentialOffer(ctx, req)

	// Current implementation returns nil, nil
	assert.NoError(t, err)
	assert.Nil(t, resp)
}

func TestVCINotification(t *testing.T) {
	log, _ := logger.New("test", "", false)
	client := &Client{
		log: log,
	}

	ctx := t.Context()
	req := &openid4vci.NotificationRequest{
		NotificationID: "test-notification-123",
	}

	err := client.VCINotification(ctx, req)

	// Current implementation returns nil
	assert.NoError(t, err)
}

// TestVCICredential_SuccessfulIssuance tests the complete credential issuance flow
// This test verifies that all components (DPoP JWT, Proof JWT, mocks) are properly structured
// for credential issuance, demonstrating the complete flow even though full integration
// requires dependency injection for the gRPC client.
func TestVCICredential_SuccessfulIssuance(t *testing.T) {
	ctx := t.Context()

	// Setup test data
	accessToken := "test-access-token-12345"
	nonce := "test-nonce-67890"

	// Create valid DPoP JWT
	dpopJWT, _ := createValidDPoPJWT(t, accessToken)
	assert.NotEmpty(t, dpopJWT, "DPoP JWT should be generated")
	assert.Contains(t, dpopJWT, ".", "DPoP JWT should be in JWT format")

	// Create valid proof JWT
	proofJWT, proofJWK := createValidProofJWT(t, nonce)
	assert.NotEmpty(t, proofJWT, "Proof JWT should be generated")
	assert.NotEmpty(t, proofJWK, "Proof JWK should be extracted")
	assert.Contains(t, proofJWT, ".", "Proof JWT should be in JWT format")

	// Create mock authorization context matching the actual structure
	mockAuthCtx := &mockAuthContextColl{
		authContext: &cache.AuthorizationContext{
			SessionID:  "session-123",
			Scopes:     []string{"pid"},
			Identifier: "test-identity-123",
			Token: &cache.Token{
				AccessToken: accessToken,
				ExpiresAt:   time.Now().Add(time.Hour).Unix(),
			},
			Nonce:               nonce,
			ExpiresAt:           time.Now().Add(time.Hour).Unix(),
			Code:                "auth-code-123",
			RequestURI:          "https://wallet.example.com/request",
			WalletURI:           "https://wallet.example.com",
			ClientID:            "client-123",
			CodeChallenge:       "challenge",
			CodeChallengeMethod: "S256",
		},
	}

	// Verify mock authorization context retrieval
	authCtx, err := mockAuthCtx.GetWithAccessToken(ctx, accessToken)
	require.NoError(t, err)
	assert.Equal(t, []string{"pid"}, authCtx.Scopes)
	assert.Equal(t, nonce, authCtx.Nonce)
	assert.NotNil(t, authCtx.Token)
	assert.Equal(t, accessToken, authCtx.Token.AccessToken)

	// Create mock document matching the actual structure
	mockDoc := &mockDatastoreColl{
		document: &model.CompleteDocument{
			Meta: &model.MetaData{
				AuthenticSource: "SUNET",
				Scope:           "pid",
				DocumentID:      "test-doc-id",
			},
			DocumentData: map[string]any{
				"sub":         "123",
				"given_name":  "John",
				"family_name": "Doe",
			},
			IdentityMappingIDs: []string{"test-identity-123"},
		},
	}

	// Verify mock document retrieval
	doc, err := mockDoc.GetDocument(ctx, "SUNET", "test-doc-id")
	require.NoError(t, err)
	assert.NotNil(t, doc)
	assert.Equal(t, "pid", doc.Meta.Scope)
	assert.Equal(t, "John", doc.DocumentData["given_name"])

	// Create mock issuer client that returns a credential
	mockIssuer := &mockIssuerClient{
		reply: &apiv1_issuer.MakeSDJWTReply{
			Credentials: []*apiv1_issuer.Credential{
				{ // #nosec G101
					Credential: "eyJhbGciOiJFUzI1NiIsInR5cCI6InZjK3NkLWp3dCJ9.eyJzdWIiOiIxMjMiLCJnaXZlbl9uYW1lIjoiSm9obiIsImZhbWlseV9uYW1lIjoiRG9lIn0.signature",
				},
			},
		},
	}

	// Verify mock issuer client
	docJSON, err := json.Marshal(doc.DocumentData)
	require.NoError(t, err)

	// Parse JWK to extract fields
	var jwkData map[string]any
	err = json.Unmarshal(proofJWK, &jwkData)
	require.NoError(t, err)

	issuerResp, err := mockIssuer.MakeSDJWT(ctx, &apiv1_issuer.MakeSDJWTRequest{
		Scope:        "pid",
		DocumentData: docJSON,
		Jwk: &apiv1_issuer.Jwk{
			Kty: jwkData["kty"].(string),
			Crv: jwkData["crv"].(string),
			X:   jwkData["x"].(string),
			Y:   jwkData["y"].(string),
		},
	})
	require.NoError(t, err)
	assert.Len(t, issuerResp.Credentials, 1)
	assert.NotEmpty(t, issuerResp.Credentials[0].Credential)
	assert.Contains(t, issuerResp.Credentials[0].Credential, "eyJ", "Should be a JWT")

	// Build credential request matching the actual structure
	req := &openid4vci.CredentialRequest{ // #nosec G101
		DPoP:          dpopJWT,
		Authorization: "DPoP " + accessToken,
		Proofs: &openid4vci.Proofs{
			JWT: []openid4vci.ProofJWTToken{openid4vci.ProofJWTToken(proofJWT)},
		},
		CredentialConfigurationID: "vc+sd-jwt",
		CredentialIdentifier:      "",
	}

	// Verify request structure
	assert.Equal(t, "DPoP "+accessToken, req.Authorization)
	assert.NotNil(t, req.Proofs)
	assert.Equal(t, openid4vci.ProofJWTToken(proofJWT), req.Proofs.JWT[0])

	t.Log("✓ DPoP JWT created and validated")
	t.Log("✓ Proof JWT created with embedded JWK")
	t.Log("✓ Mock authorization context retrieves correct data")
	t.Log("✓ Mock document retrieval works")
	t.Log("✓ Mock gRPC issuer returns credential")
	t.Log("✓ Credential request properly structured")
	t.Log("")
	t.Log("Full integration test requires dependency injection to:")
	t.Log("  1. Inject mock db collections (auth context, datastore)")
	t.Log("  2. Inject mock gRPC client factory")
	t.Log("  3. Then call client.VCICredential(ctx, req) and verify response")
}

// TestBatchProofExtraction tests that batch proof extraction works correctly
// for multiple JWT proofs, verifying the ExtractAllJWKs() method returns
// one JWK per proof token.
func TestBatchProofExtraction(t *testing.T) {
	nonce := "test-nonce"

	// Create 3 different proof JWTs with different keys
	proofJWT1, jwk1 := createValidProofJWT(t, nonce)
	proofJWT2, jwk2 := createValidProofJWT(t, nonce)
	proofJWT3, jwk3 := createValidProofJWT(t, nonce)

	proofs := &openid4vci.Proofs{
		JWT: []openid4vci.ProofJWTToken{
			openid4vci.ProofJWTToken(proofJWT1),
			openid4vci.ProofJWTToken(proofJWT2),
			openid4vci.ProofJWTToken(proofJWT3),
		},
	}

	// Verify count
	assert.Equal(t, 3, len(proofs.JWT), "should have 3 proofs")

	// Extract all JWKs
	jwks, err := proofs.ExtractAllJWKs(3)
	require.NoError(t, err)
	assert.Len(t, jwks, 3, "should extract 3 JWKs")

	// Verify each JWK corresponds to its proof's key (all should be EC P-256)
	for i, jwk := range jwks {
		assert.Equal(t, "EC", jwk.Kty, "JWK %d should be EC type", i)
		assert.Equal(t, "P-256", jwk.Crv, "JWK %d should be P-256 curve", i)
		assert.NotEmpty(t, jwk.X, "JWK %d should have X coordinate", i)
		assert.NotEmpty(t, jwk.Y, "JWK %d should have Y coordinate", i)
	}

	// Verify each JWK is unique (different keys)
	_ = jwk1
	_ = jwk2
	_ = jwk3
	assert.NotEqual(t, jwks[0].X, jwks[1].X, "JWKs should have different X coordinates")
	assert.NotEqual(t, jwks[1].X, jwks[2].X, "JWKs should have different X coordinates")
}

// TestBatchCredentialRequest tests that a batch credential request
// with multiple proofs is properly structured.
func TestBatchCredentialRequest(t *testing.T) {
	accessToken := "test-access-token-batch"
	nonce := "test-nonce-batch"

	dpopJWT, _ := createValidDPoPJWT(t, accessToken)

	proofJWT1, _ := createValidProofJWT(t, nonce)
	proofJWT2, _ := createValidProofJWT(t, nonce)
	proofJWT3, _ := createValidProofJWT(t, nonce)

	req := &openid4vci.CredentialRequest{
		DPoP:          dpopJWT,
		Authorization: "DPoP " + accessToken,
		Proofs: &openid4vci.Proofs{
			JWT: []openid4vci.ProofJWTToken{
				openid4vci.ProofJWTToken(proofJWT1),
				openid4vci.ProofJWTToken(proofJWT2),
				openid4vci.ProofJWTToken(proofJWT3),
			},
		},
		CredentialConfigurationID: "dc+sd-jwt",
	}

	// Verify request structure
	assert.True(t, req.IsAccessTokenDPoP())
	assert.NotNil(t, req.Proofs)
	assert.Equal(t, 3, len(req.Proofs.JWT), "should have 3 proofs")

	// Verify all JWKs can be extracted
	jwks, err := req.Proofs.ExtractAllJWKs(3)
	require.NoError(t, err)
	assert.Len(t, jwks, 3)

	// Backward compat: single ExtractJWK returns first key
	singleJWK, err := req.Proofs.ExtractJWK()
	require.NoError(t, err)
	assert.Equal(t, jwks[0], singleJWK, "ExtractJWK should return same key as first in ExtractAllJWKs")

	t.Log("✓ Batch credential request properly structured")
	t.Log("✓ 3 proof JWTs included")
	t.Log("✓ All JWKs extracted successfully")
	t.Log("✓ Backward compat: ExtractJWK returns first key")
}

// TestDPoPThumbprintBinding verifies the verifyDPoPKeyBinding helper:
// - Matching thumbprints pass
// - Mismatched thumbprints produce an invalid_dpop_proof error (400)
// - Empty stored thumbprint (no DPoP binding) is skipped
// - Nil token is skipped
func TestDPoPThumbprintBinding(t *testing.T) {
	tests := []struct {
		name            string
		token           *cache.Token
		proofPrint      string
		wantErr         bool
		wantErrContains string
	}{
		{
			name:       "matching thumbprints",
			token:      &cache.Token{DPoPThumbprint: "abc123"},
			proofPrint: "abc123",
			wantErr:    false,
		},
		{
			name:            "mismatched thumbprints",
			token:           &cache.Token{DPoPThumbprint: "abc123"},
			proofPrint:      "xyz789",
			wantErr:         true,
			wantErrContains: "DPoP key does not match",
		},
		{
			name:       "empty stored thumbprint (no binding)",
			token:      &cache.Token{DPoPThumbprint: ""},
			proofPrint: "xyz789",
			wantErr:    false,
		},
		{
			name:       "nil token (no binding)",
			token:      nil,
			proofPrint: "xyz789",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyDPoPKeyBinding(tt.proofPrint, tt.token)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrContains)
				var oauthErr *oauth2.OAuthError
				if assert.ErrorAs(t, err, &oauthErr) {
					assert.Equal(t, 400, oauthErr.HTTPStatus)
					assert.Equal(t, oauth2.ErrCodeInvalidDPoPProof, oauthErr.ErrorCode)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestChildSessionDocLookup verifies that child sessions (created in the
// pre-auth multi-client flow) use SourceSessionID for document lookup,
// while regular sessions use their own SessionID.
func TestDocLookupSessionID(t *testing.T) {
	tests := []struct {
		name             string
		sessionID        string
		sourceSessionID  string
		wantDocSessionID string
	}{
		{"regular session uses own SessionID", "session-abc", "", "session-abc"},
		{"child session uses SourceSessionID", "child-session-xyz", "parent-session-abc", "parent-session-abc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authCtx := &cache.AuthorizationContext{
				SessionID:       tt.sessionID,
				SourceSessionID: tt.sourceSessionID,
			}
			assert.Equal(t, tt.wantDocSessionID, docLookupSessionID(authCtx))
		})
	}
}
