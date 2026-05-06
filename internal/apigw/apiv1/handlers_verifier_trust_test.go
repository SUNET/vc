package apiv1

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trust"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirosfoundation/go-trust/pkg/trustapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testScope = "test_credential"

// mockTrustEvaluator is a mock implementation for testing
type mockTrustEvaluator struct {
	trustDecision bool
	trustReason   string
	shouldError   bool
}

func (m *mockTrustEvaluator) Evaluate(_ context.Context, _ *trust.EvaluationRequest) (*trustapi.TrustDecision, error) {
	if m.shouldError {
		return nil, assert.AnError
	}
	return &trustapi.TrustDecision{
		Trusted:        m.trustDecision,
		Reason:         m.trustReason,
		TrustFramework: "test-framework",
	}, nil
}

func (m *mockTrustEvaluator) SupportsKeyType(_ trust.KeyType) bool {
	return true
}

func newTrustTestClient() *Client {
	log, _ := logger.New("test", "", false)
	return &Client{
		log: log,
		cfg: &model.Cfg{
			APIGW: &model.APIGW{
				Trust: model.TrustConfig{},
			},
		},
	}
}

func TestEvaluateIssuerTrust_NilEvaluator(t *testing.T) {
	client := newTrustTestClient()
	// trustEvaluator is nil by default

	err := client.evaluateIssuerTrust(context.Background(), "dummy.jwt.token", testScope)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "trust evaluator not initialized")
}

func TestEvaluateIssuerTrust_EmptyJWT(t *testing.T) {
	client := newTrustTestClient()
	client.trustEvaluator = &mockTrustEvaluator{trustDecision: true}

	err := client.evaluateIssuerTrust(context.Background(), "", testScope)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty issuer JWT")
}

func TestEvaluateIssuerTrust_MissingKeyMaterial(t *testing.T) {
	client := newTrustTestClient()
	client.trustEvaluator = &mockTrustEvaluator{trustDecision: true}

	// Create a JWT without x5c or jwk header and non-DID issuer
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": "https://issuer.example.com",
		"vct": "urn:credential:test",
	})
	signedJWT, err := token.SignedString(privateKey)
	require.NoError(t, err)

	err = client.evaluateIssuerTrust(context.Background(), signedJWT+"~disclosure1~disclosure2~", testScope)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing x5c, jwk, or kid header")
}

func TestEvaluateIssuerTrust_TrustedWithJWK(t *testing.T) {
	client := newTrustTestClient()
	client.trustEvaluator = &mockTrustEvaluator{trustDecision: true}

	// Create a JWT with embedded JWK header
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": "https://issuer.example.com",
		"vct": "urn:credential:test",
	})

	// Add JWK to header
	pubKey := privateKey.PublicKey
	token.Header["jwk"] = map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   encodeECPoint(pubKey.X.Bytes(), 32),
		"y":   encodeECPoint(pubKey.Y.Bytes(), 32),
	}

	signedJWT, err := token.SignedString(privateKey)
	require.NoError(t, err)

	err = client.evaluateIssuerTrust(context.Background(), signedJWT+"~", testScope)

	assert.NoError(t, err)
}

func TestEvaluateIssuerTrust_UntrustedIssuer(t *testing.T) {
	client := newTrustTestClient()
	client.trustEvaluator = &mockTrustEvaluator{trustDecision: false, trustReason: "unknown issuer"}

	// Create a JWT with embedded JWK header
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": "https://untrusted-issuer.example.com",
		"vct": "urn:credential:test",
	})

	pubKey := privateKey.PublicKey
	token.Header["jwk"] = map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   encodeECPoint(pubKey.X.Bytes(), 32),
		"y":   encodeECPoint(pubKey.Y.Bytes(), 32),
	}

	signedJWT, err := token.SignedString(privateKey)
	require.NoError(t, err)

	err = client.evaluateIssuerTrust(context.Background(), signedJWT+"~", testScope)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "issuer not trusted")
}

func TestEvaluateIssuerTrust_EvaluatorError(t *testing.T) {
	client := newTrustTestClient()
	client.trustEvaluator = &mockTrustEvaluator{shouldError: true}

	// Create a JWT with embedded JWK header
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": "https://issuer.example.com",
		"vct": "urn:credential:test",
	})

	pubKey := privateKey.PublicKey
	token.Header["jwk"] = map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   encodeECPoint(pubKey.X.Bytes(), 32),
		"y":   encodeECPoint(pubKey.Y.Bytes(), 32),
	}

	signedJWT, err := token.SignedString(privateKey)
	require.NoError(t, err)

	err = client.evaluateIssuerTrust(context.Background(), signedJWT+"~", testScope)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "trust evaluation error")
}

func TestBuildAllowedAlgorithmSet_Default(t *testing.T) {
	set := buildAllowedAlgorithmSet(nil)

	assert.True(t, set["ES256"])
	assert.True(t, set["ES384"])
	assert.True(t, set["EdDSA"])
	assert.False(t, set["none"])
}

func TestBuildAllowedAlgorithmSet_Custom(t *testing.T) {
	set := buildAllowedAlgorithmSet([]string{"ES256", "none"})

	assert.True(t, set["ES256"])
	assert.False(t, set["none"]) // "none" always removed
	assert.False(t, set["RS256"])
}

func TestBuildAllowedAlgorithmSet_DisallowedAlgorithm(t *testing.T) {
	client := newTrustTestClient()
	client.trustEvaluator = &mockTrustEvaluator{trustDecision: true}
	client.cfg.APIGW.Trust.AllowedSignatureAlgorithms = []string{"ES384"} // Only ES384

	// Create a JWT signed with ES256 (not in allowed list)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": "https://issuer.example.com",
		"vct": "urn:credential:test",
	})

	pubKey := privateKey.PublicKey
	token.Header["jwk"] = map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   encodeECPoint(pubKey.X.Bytes(), 32),
		"y":   encodeECPoint(pubKey.Y.Bytes(), 32),
	}

	signedJWT, err := token.SignedString(privateKey)
	require.NoError(t, err)

	err = client.evaluateIssuerTrust(context.Background(), signedJWT+"~", testScope)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not in the allowed list")
}

// encodeECPoint encodes a big-endian EC point coordinate with zero-padding to size bytes,
// then base64url-encodes it (no padding).
func encodeECPoint(b []byte, size int) string {
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return base64RawURLEncode(padded)
}

func base64RawURLEncode(data []byte) string {
	const encodeURL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	buf := make([]byte, 0, (len(data)*4+2)/3)
	for i := 0; i < len(data); i += 3 {
		val := uint(data[i]) << 16
		if i+1 < len(data) {
			val |= uint(data[i+1]) << 8
		}
		if i+2 < len(data) {
			val |= uint(data[i+2])
		}
		buf = append(buf, encodeURL[(val>>18)&0x3F])
		buf = append(buf, encodeURL[(val>>12)&0x3F])
		if i+1 < len(data) {
			buf = append(buf, encodeURL[(val>>6)&0x3F])
		}
		if i+2 < len(data) {
			buf = append(buf, encodeURL[val&0x3F])
		}
	}
	return string(buf)
}
