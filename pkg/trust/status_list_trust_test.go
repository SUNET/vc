package trust

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/testsupport/jwktest"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sirosfoundation/go-trust/pkg/trustapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// actionEvaluator answers per action name and records the order in which it
// was asked, so a test can assert both the decision and the sequence of
// questions that produced it.
type actionEvaluator struct {
	trusted  map[string]bool
	errors   map[string]bool
	asked    []string
	subjects []string
}

func (e *actionEvaluator) Evaluate(_ context.Context, req *EvaluationRequest) (*trustapi.TrustDecision, error) {
	action := req.GetEffectiveAction()
	e.asked = append(e.asked, action)
	e.subjects = append(e.subjects, req.SubjectID)
	if e.errors[action] {
		return nil, assert.AnError
	}
	return &trustapi.TrustDecision{
		Trusted:        e.trusted[action],
		Reason:         "decided for " + action,
		TrustFramework: "test-framework",
	}, nil
}

func (e *actionEvaluator) SupportsKeyType(_ KeyType) bool { return true }

// signStatusListToken produces a status list token signed with a fresh key
// whose public half rides in the jwk header, which is one of the two header
// forms a status list signer is allowed to use.
func signStatusListToken(t *testing.T, issuer string) string {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	claims := jwt.MapClaims{"sub": "https://status.example.com/lists/1"}
	if issuer != "" {
		claims["iss"] = issuer
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	pub := privateKey.PublicKey
	token.Header["jwk"] = jwktest.PublicKeyJWK(&pub)

	signed, err := token.SignedString(privateKey)
	require.NoError(t, err)
	return signed
}

const testListURI = "https://status.example.com/lists/1"

// TestVerifyStatusListToken_StatusListSignerFirst pins the order: the
// specific action is asked first, and when it answers yes the generic
// credential-issuer question is never put.
func TestVerifyStatusListToken_StatusListSignerFirst(t *testing.T) {
	ev := &actionEvaluator{trusted: map[string]bool{StatusListSignerAction: true}}
	verifier := newTestVerifier(ev)

	token, err := verifier.VerifyStatusListToken(context.Background(),
		signStatusListToken(t, "https://status.example.com"), testListURI)

	require.NoError(t, err)
	require.NotNil(t, token)
	assert.Equal(t, []string{StatusListSignerAction}, ev.asked,
		"a trusted status-list-signer must not also be asked about as a credential issuer")
}

// TestVerifyStatusListToken_FallsBackToCredentialIssuer covers the common
// deployment: the credential issuer signs the status lists for its own
// credentials, and is named in policy only as an issuer.
func TestVerifyStatusListToken_FallsBackToCredentialIssuer(t *testing.T) {
	ev := &actionEvaluator{trusted: map[string]bool{StatusListIssuerFallbackAction: true}}
	verifier := newTestVerifier(ev)

	token, err := verifier.VerifyStatusListToken(context.Background(),
		signStatusListToken(t, "https://issuer.example.com"), testListURI)

	require.NoError(t, err)
	require.NotNil(t, token)
	assert.Equal(t, []string{StatusListSignerAction, StatusListIssuerFallbackAction}, ev.asked)
	assert.Equal(t, "credential-issuer", StatusListIssuerFallbackAction)
	assert.Equal(t, []string{"https://issuer.example.com", "https://issuer.example.com"}, ev.subjects,
		"both questions are asked about the same party")
}

// TestVerifyStatusListToken_BothActionsRefused keeps the check fail-closed:
// two noes are still a no.
func TestVerifyStatusListToken_BothActionsRefused(t *testing.T) {
	ev := &actionEvaluator{trusted: map[string]bool{}}
	verifier := newTestVerifier(ev)

	token, err := verifier.VerifyStatusListToken(context.Background(),
		signStatusListToken(t, "https://issuer.example.com"), testListURI)

	require.Error(t, err)
	assert.Nil(t, token)
	assert.Contains(t, err.Error(), "untrusted party")
	assert.Equal(t, []string{StatusListSignerAction, StatusListIssuerFallbackAction}, ev.asked)
}

// TestVerifyStatusListToken_FirstActionErrors: an evaluator error is not an
// answer, so the fallback is still asked, and its answer is what counts.
func TestVerifyStatusListToken_FirstActionErrors(t *testing.T) {
	ev := &actionEvaluator{
		trusted: map[string]bool{StatusListIssuerFallbackAction: true},
		errors:  map[string]bool{StatusListSignerAction: true},
	}
	verifier := newTestVerifier(ev)

	token, err := verifier.VerifyStatusListToken(context.Background(),
		signStatusListToken(t, "https://issuer.example.com"), testListURI)

	require.NoError(t, err)
	require.NotNil(t, token)
	assert.Equal(t, []string{StatusListSignerAction, StatusListIssuerFallbackAction}, ev.asked)
}

// TestVerifyStatusListToken_BothActionsError: with no answer at all the
// verifier refuses rather than assuming either way.
func TestVerifyStatusListToken_BothActionsError(t *testing.T) {
	ev := &actionEvaluator{
		trusted: map[string]bool{},
		errors: map[string]bool{
			StatusListSignerAction:         true,
			StatusListIssuerFallbackAction: true,
		},
	}
	verifier := newTestVerifier(ev)

	token, err := verifier.VerifyStatusListToken(context.Background(),
		signStatusListToken(t, "https://issuer.example.com"), testListURI)

	require.Error(t, err)
	assert.Nil(t, token)
	assert.Contains(t, err.Error(), "trust evaluation error")
	assert.Equal(t, []string{StatusListSignerAction, StatusListIssuerFallbackAction}, ev.asked)
}

// TestVerifyStatusListToken_SubjectFromListURI: Section 5.1 does not require
// iss, so without one the party asked about is the origin that served the
// list.
func TestVerifyStatusListToken_SubjectFromListURI(t *testing.T) {
	ev := &actionEvaluator{trusted: map[string]bool{StatusListSignerAction: true}}
	verifier := newTestVerifier(ev)

	_, err := verifier.VerifyStatusListToken(context.Background(),
		signStatusListToken(t, ""), testListURI)

	require.NoError(t, err)
	assert.Equal(t, []string{"https://status.example.com"}, ev.subjects)
}

// signStatusListTokenX5C mints a status list token signed with a fresh key
// whose certificate rides in the x5c header, with a deliberately misleading
// common name.
func signStatusListTokenX5C(t *testing.T, commonName, issuer string) string {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	claims := jwt.MapClaims{"sub": testListURI}
	if issuer != "" {
		claims["iss"] = issuer
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["x5c"] = []any{base64.StdEncoding.EncodeToString(der)}

	signed, err := token.SignedString(privateKey)
	require.NoError(t, err)
	return signed
}

// TestVerifyStatusListToken_X5CWithoutIssUsesTheListOrigin: for an x5c
// token, JWTKeyMaterial.IssuerID falls back to the leaf certificate's common
// name. Using that as the trust subject asked the PDP about whatever the
// certificate happened to be named, while this function's rule - and the
// deployment's policy - say the list origin.
//
// Section 5.1 does not require iss, so a conforming status service signing
// with x5c and omitting it is the ordinary case, not a corner.
func TestVerifyStatusListToken_X5CWithoutIssUsesTheListOrigin(t *testing.T) {
	ev := &actionEvaluator{trusted: map[string]bool{StatusListSignerAction: true}}
	verifier := newTestVerifier(ev)

	_, err := verifier.VerifyStatusListToken(context.Background(),
		signStatusListTokenX5C(t, "some-internal-ca-name", ""), testListURI)

	require.NoError(t, err)
	require.NotEmpty(t, ev.subjects)
	assert.Equal(t, "https://status.example.com", ev.subjects[0],
		"a token with no iss is judged as the origin that served the list")
	assert.NotContains(t, ev.subjects, "some-internal-ca-name",
		"the certificate's common name is not an issuer identity")
}

// TestVerifyStatusListToken_X5CWithIssUsesIt keeps the other half: when the
// token does say who issued it, that is the party asked about.
func TestVerifyStatusListToken_X5CWithIssUsesIt(t *testing.T) {
	ev := &actionEvaluator{trusted: map[string]bool{StatusListSignerAction: true}}
	verifier := newTestVerifier(ev)

	_, err := verifier.VerifyStatusListToken(context.Background(),
		signStatusListTokenX5C(t, "some-internal-ca-name", "https://issuer.example.com"), testListURI)

	require.NoError(t, err)
	assert.Equal(t, []string{"https://issuer.example.com"}, ev.subjects)
}
