package trust

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/sirosfoundation/go-trust/pkg/trustapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateAttestationPoP_Valid(t *testing.T) {
	// Generate instance key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create a mock WIA with cnf.jwk
	wia := createTestWIA(t, key)

	// Create a valid PoP
	pop := createTestPoP(t, key, "test-client", "https://as.example.com")

	// Validate
	err = validateAttestationPoP(wia, pop, "https://as.example.com")
	assert.NoError(t, err)
}

func TestValidateAttestationPoP_WrongKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	wia := createTestWIA(t, key)
	pop := createTestPoP(t, wrongKey, "test-client", "https://as.example.com")

	err = validateAttestationPoP(wia, pop, "https://as.example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature verification")
}

func TestValidateAttestationPoP_WrongAudience(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	wia := createTestWIA(t, key)
	pop := createTestPoP(t, key, "test-client", "https://other-as.example.com")

	err = validateAttestationPoP(wia, pop, "https://as.example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "aud")
}

func TestValidateAttestationPoP_MissingIat(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	wia := createTestWIA(t, key)

	// Create PoP without iat
	claims := jwt.RegisteredClaims{
		Issuer:    "test-client",
		Audience:  jwt.ClaimStrings{"https://as.example.com"},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		ID:        uuid.New().String(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = "oauth-client-attestation-pop+jwt"
	pop, err := tok.SignedString(key)
	require.NoError(t, err)

	err = validateAttestationPoP(wia, pop, "https://as.example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "iat")
}

func TestValidateAttestationPoP_WrongTyp(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	wia := createTestWIA(t, key)

	// Create PoP with wrong typ
	claims := jwt.RegisteredClaims{
		Issuer:    "test-client",
		Audience:  jwt.ClaimStrings{"https://as.example.com"},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ID:        uuid.New().String(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = "dpop+jwt" // wrong!
	pop, err := tok.SignedString(key)
	require.NoError(t, err)

	err = validateAttestationPoP(wia, pop, "https://as.example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "typ")
}

func TestExtractCNFKeyFromWIA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	wia := createTestWIA(t, key)

	extracted, err := extractCNFKeyFromWIA(wia)
	require.NoError(t, err)

	// Verify it's the same key
	assert.Equal(t, key.PublicKey.X, extracted.X)
	assert.Equal(t, key.PublicKey.Y, extracted.Y)
}

func TestExtractCNFKeyFromWIA_MissingCNF(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// WIA without cnf
	claims := jwt.MapClaims{
		"iss": "https://wallet-provider.example.com",
		"sub": "thumbprint123",
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	wia, err := tok.SignedString(key)
	require.NoError(t, err)

	_, err = extractCNFKeyFromWIA(wia)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cnf")
}

// createTestWIA creates a test WIA JWT with cnf.jwk bound to the given key.
func createTestWIA(t *testing.T, instanceKey *ecdsa.PrivateKey) string {
	t.Helper()

	// Create a "wallet provider" signing key (different from instance key)
	wpKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ecdhKey, err := instanceKey.PublicKey.ECDH()
	require.NoError(t, err)
	raw := ecdhKey.Bytes()

	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(raw[1:33]),
		"y":   base64.RawURLEncoding.EncodeToString(raw[33:65]),
	}

	// Compute JKT
	canonical := fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q,"y":%q}`,
		jwk["crv"], jwk["kty"], jwk["x"], jwk["y"])
	hash := sha256.Sum256([]byte(canonical))
	jkt := base64.RawURLEncoding.EncodeToString(hash[:])

	claims := jwt.MapClaims{
		"iss": "https://wallet-provider.example.com",
		"sub": jkt,
		"cnf": map[string]interface{}{
			"jwk": jwk,
			"jkt": jkt,
		},
		"iat":                time.Now().Unix(),
		"exp":                time.Now().Add(24 * time.Hour).Unix(),
		"attestation_source": "backend_attested",
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = "oauth-client-attestation+jwt"
	wia, err := tok.SignedString(wpKey)
	require.NoError(t, err)
	return wia
}

// createTestPoP creates a test PoP JWT signed by the instance key.
func createTestPoP(t *testing.T, key *ecdsa.PrivateKey, clientID, audience string) string {
	t.Helper()

	claims := jwt.RegisteredClaims{
		Issuer:    clientID,
		Audience:  jwt.ClaimStrings{audience},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ID:        uuid.New().String(),
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = "oauth-client-attestation-pop+jwt"
	pop, err := tok.SignedString(key)
	require.NoError(t, err)
	return pop
}

// signTestWIAWithJWK creates a signed ES256 WIA with an embedded jwk header
// (self-contained key material, no JWKS lookup needed - a valid WIA shape
// per draft-ietf-oauth-attestation-based-client-auth, and the simplest case
// that still exercises the exact bug this test suite guards against: passing
// the resolved JWK to the PDP, not the raw attestation string).
func signTestWIAWithJWK(t *testing.T, signingKey *ecdsa.PrivateKey, issuer, sub, attestationSource string) string {
	t.Helper()
	claims := jwt.MapClaims{"iss": issuer, "sub": sub}
	if attestationSource != "" {
		claims["attestation_source"] = attestationSource
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "oauth-client-attestation+jwt"
	pubKey := signingKey.PublicKey
	// P-256 JWK x/y must be fixed-width 32-byte values; X.Bytes()/Y.Bytes()
	// drop leading zero bytes, which would intermittently produce a
	// non-compliant (shorter) encoding that strict JWK parsers reject.
	xBytes := make([]byte, 32)
	yBytes := make([]byte, 32)
	pubKey.X.FillBytes(xBytes)
	pubKey.Y.FillBytes(yBytes)
	token.Header["jwk"] = map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(xBytes),
		"y":   base64.RawURLEncoding.EncodeToString(yBytes),
	}
	signed, err := token.SignedString(signingKey)
	require.NoError(t, err)
	return signed
}

// signTestWIAWithX5C creates a signed ES256 WIA with an x5c header (TS03/EUDI
// format): a self-signed cert whose DNS SAN is dnsSAN, plus an `iss` claim
// that is a URL over that same host - the shape that previously tripped the
// belt-and-suspenders issuer check, since parseAttestationIdentity derives
// the issuer as the bare DNS SAN while the generic verifier's IssuerID is the
// raw (URL-shaped) iss claim.
func signTestWIAWithX5C(t *testing.T, dnsSAN, iss, sub string) string {
	t.Helper()
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsSAN},
		DNSNames:     []string{dnsSAN},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &signingKey.PublicKey, signingKey)
	require.NoError(t, err)

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"iss": iss, "sub": sub})
	token.Header["typ"] = "oauth-client-attestation+jwt"
	token.Header["x5c"] = []any{base64.StdEncoding.EncodeToString(certDER)}

	signed, err := token.SignedString(signingKey)
	require.NoError(t, err)
	return signed
}

// capturingEvaluator is a TrustEvaluator that records the last EvaluationRequest
// it received, so tests can assert exactly what was sent to the PDP.
type capturingEvaluator struct {
	trustDecision bool
	trustReason   string
	shouldError   bool
	lastRequest   *EvaluationRequest
}

func (m *capturingEvaluator) Evaluate(_ context.Context, req *EvaluationRequest) (*trustapi.TrustDecision, error) {
	m.lastRequest = req
	if m.shouldError {
		return nil, assert.AnError
	}
	return &trustapi.TrustDecision{Trusted: m.trustDecision, Reason: m.trustReason, TrustFramework: "test-framework"}, nil
}

func (m *capturingEvaluator) SupportsKeyType(_ KeyType) bool { return true }

func TestWalletAttestationEvaluator_Evaluate_SignatureVerified(t *testing.T) {
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	wia := signTestWIAWithJWK(t, signingKey, "https://wallet-provider.example.com", "instance-jkt-123", "backend_attested")

	evaluator := &capturingEvaluator{trustDecision: true}
	we := NewWalletAttestationEvaluator(evaluator, newTestVerifier(evaluator))

	result, err := we.Evaluate(context.Background(), wia)
	require.NoError(t, err)
	assert.True(t, result.Trusted)
	assert.Equal(t, "https://wallet-provider.example.com", result.Issuer)
	assert.Equal(t, "instance-jkt-123", result.Subject)
	assert.Equal(t, "backend_attested", result.AttestationSource)

	// Regression: the PDP must receive the resolved JWK (a map), not the raw
	// compact-serialized attestation string - confirmed live against a real
	// PDP client, which rejected the latter with "unsupported public key
	// type: string" ("failed to build evaluation request" further up the
	// call chain).
	require.NotNil(t, evaluator.lastRequest)
	assert.Equal(t, KeyTypeJWK, evaluator.lastRequest.KeyType)
	jwkMap, ok := evaluator.lastRequest.Key.(map[string]any)
	require.True(t, ok, "expected Key to be a map[string]any (a resolved JWK), got %T", evaluator.lastRequest.Key)
	assert.Equal(t, "EC", jwkMap["kty"])
	assert.Equal(t, RoleWalletProvider, evaluator.lastRequest.Role)
	assert.Equal(t, "https://wallet-provider.example.com", evaluator.lastRequest.SubjectID)
}

// Regression for a bug the belt-and-suspenders issuer check introduced: for
// x5c-based (TS03) WIAs, parseAttestationIdentity derives the issuer from the
// cert's DNS SAN (a bare hostname), while the generic verifier's IssuerID
// falls back to the raw `iss` claim (a URL) when present. A valid WIA with
// iss="https://<dnsSAN>" was being rejected by a strict-equality check
// between the two, even though parseAttestationIdentity already validated
// iss↔cert consistency (via issMatchesCertIdentity, which understands the
// URL-vs-hostname shape difference). The check must be skipped for x5c WIAs.
func TestWalletAttestationEvaluator_Evaluate_X5CIssuerFormatMismatchAllowed(t *testing.T) {
	wia := signTestWIAWithX5C(t, "wallet-provider.example.com", "https://wallet-provider.example.com", "instance-jkt-123")

	evaluator := &capturingEvaluator{trustDecision: true}
	we := NewWalletAttestationEvaluator(evaluator, newTestVerifier(evaluator))

	result, err := we.Evaluate(context.Background(), wia)
	require.NoError(t, err)
	assert.True(t, result.Trusted)
	assert.Equal(t, "wallet-provider.example.com", result.Issuer)

	require.NotNil(t, evaluator.lastRequest)
	assert.Equal(t, KeyTypeX5C, evaluator.lastRequest.KeyType)
}

func TestWalletAttestationEvaluator_Evaluate_RejectsSignatureMismatch(t *testing.T) {
	// A WIA whose signature does not match its embedded jwk - if signature
	// verification is skipped (the original bug: ParseUnverified, "PDP
	// already validated"), this would sail through unnoticed. It must fail
	// here instead, since nothing verifies that the embedded jwk actually
	// signed this token.
	attackerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	wia := signTestWIAWithJWK(t, attackerKey, "https://real-wallet-provider.example.com", "instance-jkt-123", "backend_attested")

	// Splice in a signature from a token with the SAME header+payload length
	// shape but signed by a DIFFERENT key, so the result stays well-formed
	// (valid base64url, valid DER/raw ECDSA signature encoding) but no
	// longer matches the embedded jwk - simulates a forged/corrupted
	// attestation without also corrupting the token's basic structure
	// (which would fail at parsing, before signature verification is even
	// reached, and prove nothing about this test's actual target).
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	decoy := signTestWIAWithJWK(t, otherKey, "https://real-wallet-provider.example.com", "instance-jkt-123", "backend_attested")
	wiaParts := strings.Split(wia, ".")
	decoyParts := strings.Split(decoy, ".")
	require.Len(t, wiaParts, 3)
	require.Len(t, decoyParts, 3)
	forged := wiaParts[0] + "." + wiaParts[1] + "." + decoyParts[2]

	evaluator := &capturingEvaluator{trustDecision: true}
	we := NewWalletAttestationEvaluator(evaluator, newTestVerifier(evaluator))

	_, err = we.Evaluate(context.Background(), forged)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature verification failed")
	assert.Nil(t, evaluator.lastRequest, "PDP must never be called when signature verification fails")
}

func TestWalletAttestationEvaluator_Evaluate_UntrustedWalletProvider(t *testing.T) {
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	wia := signTestWIAWithJWK(t, signingKey, "https://wallet-provider.example.com", "instance-jkt-123", "backend_attested")

	evaluator := &capturingEvaluator{trustDecision: false, trustReason: "not in trust list"}
	we := NewWalletAttestationEvaluator(evaluator, newTestVerifier(evaluator))

	_, err = we.Evaluate(context.Background(), wia)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not trusted")
}

func TestWalletAttestationEvaluator_Evaluate_MissingVerifier(t *testing.T) {
	evaluator := &capturingEvaluator{trustDecision: true}
	we := &WalletAttestationEvaluator{TrustEvaluator: evaluator}

	_, err := we.Evaluate(context.Background(), "irrelevant")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no JWT verifier configured")
}
