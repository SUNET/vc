package trust

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/SUNET/vc/pkg/jose"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sirosfoundation/go-trust/pkg/trustapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testScope = "test_credential"

// testLogger is a minimal Logger for tests.
type testLogger struct{}

func (l *testLogger) Debug(_ string, _ ...any) {}
func (l *testLogger) Warn(_ string, _ ...any)  {}
func (l *testLogger) Info(_ string, _ ...any)  {}

// mockEvaluator is a mock TrustEvaluator for testing.
type mockEvaluator struct {
	trustDecision bool
	trustReason   string
	shouldError   bool
}

func (m *mockEvaluator) Evaluate(_ context.Context, _ *EvaluationRequest) (*trustapi.TrustDecision, error) {
	if m.shouldError {
		return nil, assert.AnError
	}
	return &trustapi.TrustDecision{
		Trusted:        m.trustDecision,
		Reason:         m.trustReason,
		TrustFramework: "test-framework",
	}, nil
}

func (m *mockEvaluator) SupportsKeyType(_ KeyType) bool {
	return true
}

func newTestVerifier(evaluator TrustEvaluator) *JWTTrustVerifier {
	return NewJWTTrustVerifier(JWTTrustVerifierConfig{
		TrustEvaluator: evaluator,
		ParseX5C:       func(x5cRaw any) ([]*x509.Certificate, error) { return jose.ParseX5CHeader(x5cRaw) },
		ParseJWK:       jose.ParseJWKToPublicKey,
		Log:            &testLogger{},
	})
}

// signTestJWTWithJWK creates a signed ES256 JWT with an embedded JWK header.
// The JWT contains the given issuer and credential type claims.
func signTestJWTWithJWK(t *testing.T, issuer, credentialType string) string {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": issuer,
		"vct": credentialType,
	})
	pubKey := privateKey.PublicKey
	token.Header["jwk"] = map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(pubKey.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(pubKey.Y.Bytes()),
	}

	signedJWT, err := token.SignedString(privateKey)
	require.NoError(t, err)
	return signedJWT
}

func TestJWTTrustVerifier_NilEvaluator(t *testing.T) {
	verifier := NewJWTTrustVerifier(JWTTrustVerifierConfig{
		Log: &testLogger{},
	})

	err := verifier.EvaluateIssuerTrust(context.Background(), "dummy.jwt.token", testScope)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "trust evaluator not initialized")
}

func TestJWTTrustVerifier_EmptyJWT(t *testing.T) {
	verifier := newTestVerifier(&mockEvaluator{trustDecision: true})

	err := verifier.EvaluateIssuerTrust(context.Background(), "", testScope)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty issuer JWT")
}

func TestJWTTrustVerifier_MissingKeyMaterial(t *testing.T) {
	verifier := newTestVerifier(&mockEvaluator{trustDecision: true})

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": "https://issuer.example.com",
		"vct": "urn:credential:test",
	})
	signedJWT, err := token.SignedString(privateKey)
	require.NoError(t, err)

	err = verifier.EvaluateIssuerTrust(context.Background(), signedJWT+"~disclosure1~disclosure2~", testScope)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing x5c, jwk, or kid header")
}

func TestJWTTrustVerifier_EvaluateIssuerTrust(t *testing.T) {
	tests := []struct {
		name       string
		verifier   *JWTTrustVerifier
		vpToken    string
		wantErr    bool
		errContain string
	}{
		{
			name:     "trusted with JWK",
			verifier: newTestVerifier(&mockEvaluator{trustDecision: true}),
			vpToken:  signTestJWTWithJWK(t, "https://issuer.example.com", "urn:credential:test") + "~",
		},
		{
			name:       "untrusted issuer",
			verifier:   newTestVerifier(&mockEvaluator{trustDecision: false, trustReason: "unknown issuer"}),
			vpToken:    signTestJWTWithJWK(t, "https://untrusted-issuer.example.com", "urn:credential:test") + "~",
			wantErr:    true,
			errContain: "issuer not trusted",
		},
		{
			name:       "evaluator error",
			verifier:   newTestVerifier(&mockEvaluator{shouldError: true}),
			vpToken:    signTestJWTWithJWK(t, "https://issuer.example.com", "urn:credential:test") + "~",
			wantErr:    true,
			errContain: "trust evaluation error",
		},
		{
			name: "disallowed algorithm",
			verifier: NewJWTTrustVerifier(JWTTrustVerifierConfig{
				TrustEvaluator:             &mockEvaluator{trustDecision: true},
				AllowedSignatureAlgorithms: []string{"ES384"}, // Only ES384
				ParseX5C:                   func(x5cRaw any) ([]*x509.Certificate, error) { return jose.ParseX5CHeader(x5cRaw) },
				ParseJWK:                   jose.ParseJWKToPublicKey,
				Log:                        &testLogger{},
			}),
			vpToken:    signTestJWTWithJWK(t, "https://issuer.example.com", "urn:credential:test") + "~",
			wantErr:    true,
			errContain: "not in the allowed list",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.verifier.EvaluateIssuerTrust(context.Background(), tt.vpToken, testScope)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContain)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestBuildAllowedAlgorithmSet_Defaults(t *testing.T) {
	set := BuildAllowedAlgorithmSet(nil)

	assert.True(t, set["ES256"])
	assert.True(t, set["ES384"])
	assert.True(t, set["EdDSA"])
	assert.False(t, set["none"])
}

func TestBuildAllowedAlgorithmSet_NoneAlwaysRemoved(t *testing.T) {
	set := BuildAllowedAlgorithmSet([]string{"ES256", "none"})

	assert.True(t, set["ES256"])
	assert.False(t, set["none"])
	assert.False(t, set["RS256"])
}

func TestValidateSigningMethodForKey_ECDSA(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ecToken := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{})
	assert.NoError(t, ValidateSigningMethodForKey(ecToken, &ecKey.PublicKey))

	rsaToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{})
	err = ValidateSigningMethodForKey(rsaToken, &ecKey.PublicKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected signing method")
}
