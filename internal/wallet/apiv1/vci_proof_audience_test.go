package apiv1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SUNET/vc/internal/wallet/config"
	"github.com/SUNET/vc/pkg/openid4vci"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The proof JWT's aud is the Credential Issuer IDENTIFIER, never the
// credential endpoint it is posted to.
//
// This is a CALL-SITE test, through requestCredential and a real HTTP
// round trip, not a test of createProofJWT: the helper was always
// correct about what it signs, and the bug was in what the caller
// handed it. A test of the helper would have passed throughout.
//
// The bug itself: the endpoint was sent as aud, every issuance was
// refused with "aud claim does not match expected audience", and
// nothing in the default test run noticed, because the only tests that
// exercised this path are behind the `integration` build tag and need a
// docker-compose stack.
func TestCredentialRequestProofNamesTheIssuerIdentifier(t *testing.T) {
	var received map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &received))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"credentials":[{"credential":"x"}]}`))
	}))
	defer server.Close()

	const issuerIdentifier = "https://issuer.example"
	credentialEndpoint := server.URL + "/credential"
	require.NotEqual(t, issuerIdentifier, credentialEndpoint,
		"the two values must differ, or this test cannot tell them apart")

	client := newProofTestClient(t)
	_, err := client.requestCredential(t.Context(), credentialEndpoint, issuerIdentifier,
		"access-token", "Bearer", "nonce-1", "pid", &config.VCIScenario{})
	require.NoError(t, err)

	aud := proofAudience(t, received)
	assert.Equal(t, issuerIdentifier, aud)
	assert.NotEqual(t, credentialEndpoint, aud,
		"sending the endpoint is what the issuer refuses with \"aud claim does not match expected audience\"")
}

// Metadata with no credential_issuer is refused, rather than defaulted
// to the endpoint. Defaulting is what produced an unreadable refusal
// from the issuer instead of a legible one here.
func TestCredentialRequestRefusesMetadataWithNoIssuerIdentifier(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("no request may be sent when the audience is unknown")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := newProofTestClient(t)
	_, err := client.requestCredential(t.Context(), server.URL+"/credential", "",
		"access-token", "Bearer", "nonce-1", "pid", &config.VCIScenario{})
	assert.ErrorContains(t, err, "no credential_issuer")
}

// A scenario that sends no proof at all still works, and reaches the
// endpoint: the audience check must not become a second gate on a flow
// that has no proof to put an audience in.
func TestCredentialRequestWithoutAProofNeedsNoAudience(t *testing.T) {
	reached := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"credentials":[{"credential":"x"}]}`))
	}))
	defer server.Close()

	client := newProofTestClient(t)
	_, err := client.requestCredential(t.Context(), server.URL+"/credential", "",
		"access-token", "Bearer", "", "pid", &config.VCIScenario{ProofType: "none"})
	require.NoError(t, err)
	assert.True(t, reached)
}

func newProofTestClient(t *testing.T) *Client {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return &Client{
		cfg:        &config.Config{},
		log:        slog.New(slog.DiscardHandler),
		httpClient: &http.Client{},
		signingKey: key,
		results:    NewResultStore(),
	}
}

// proofAudience pulls aud out of the proof JWT the request carried.
func proofAudience(t *testing.T, body map[string]any) string {
	t.Helper()
	require.NotNil(t, body, "no credential request was received")

	proofs, ok := body["proofs"].(map[string]any)
	require.Truef(t, ok, "the request carries no proofs: %v", body)
	jwts, ok := proofs["jwt"].([]any)
	require.True(t, ok)
	require.Len(t, jwts, 1)
	token, ok := jwts[0].(string)
	require.True(t, ok)

	// Parsed as the issuer parses it, through the same type, so the
	// field this asserts on is the field an issuer reads.
	require.NoError(t, openid4vci.ProofJWTToken(token).Validate())

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims openid4vci.ProofJWTClaims
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims.Aud
}
