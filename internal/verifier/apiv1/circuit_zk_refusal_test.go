package apiv1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// assertRefusal is what every case below checks: the error names a stable
// code, renders as a 4xx, and is CLASSIFIED - so the HTTP layer returns
// the code instead of redacting it behind a req_id.
func assertRefusal(t *testing.T, err error, wantCode string) {
	t.Helper()
	require.Error(t, err)

	refusal, ok := zkpReqRefusalFrom(err)
	if !ok {
		shape, isShape := zkpReqShapeRefusal(err)
		require.Truef(t, isShape, "not a classified refusal at all, so this reaches a wallet as a 500: %v", err)
		refusal = shape
	}
	assert.Equal(t, wantCode, refusal.Code)

	shaped := refusal.HTTPError()
	assert.Equal(t, http.StatusBadRequest, shaped.HTTPStatus, "a refused presentation is not a server fault")
	assert.Equal(t, wantCode, shaped.Title, "the code is what a wallet branches on")
	assert.Falsef(t, helpers.NewErrorFromError(shaped).IsUnclassified(),
		"the HTTP layer would redact %s behind a req_id", wantCode)
}

func refusalClient(t *testing.T, evaluator trust.TrustEvaluator) *Client {
	t.Helper()
	log, err := logger.New("test", "", false)
	require.NoError(t, err)
	return &Client{log: log, cfg: &model.Cfg{Verifier: &model.Verifier{}}, trustEvaluator: evaluator}
}

// The refusal the first live Pixel round hit. It reached the wallet as
// HTTP 500 internal_server_error with a bare req_id, so the round was
// spent looking at the wallet for a decision the verifier had already
// made and could name.
func TestZkpReqIssuerKeySetSizeIsClassified(t *testing.T) {
	presentation, _ := testP256Chain(t)
	leaf := presentation.IssuerKeySet[0]
	presentation.IssuerKeySet = [][]byte{leaf, leaf} // leaf + root, as the wallet sent
	presentation.SystemID = "urn:circuits:longfellow:nym_auth:v1"

	_, err := refusalClient(t, &fakeTrustEvaluator{trusted: true}).
		circuitZkIssuerKey(t.Context(), presentation, "eu.europa.ec.eudi.nym_auth.1", time.Now())

	assertRefusal(t, err, CodeZkpReqIssuerKeySetSize)
	assert.Contains(t, err.Error(), "Document Signer certificate alone",
		"the refusal must say what to send instead, or the prover has to guess")
}

func TestZkpReqIssuerKeyRefusalsAreClassified(t *testing.T) {
	trusted, _ := testP256Chain(t)

	for _, tc := range []struct {
		name         string
		evaluator    trust.TrustEvaluator
		presentation openid4vp.ZkpPresentation
		code         string
	}{
		{"no key set", &fakeTrustEvaluator{trusted: true}, openid4vp.ZkpPresentation{}, CodeZkpReqIssuerKeySetEmpty},
		{"not a certificate", &fakeTrustEvaluator{trusted: true},
			openid4vp.ZkpPresentation{IssuerKeySet: [][]byte{[]byte("not DER")}}, CodeZkpReqIssuerKeyNotACert},
		{"the PDP says no", &fakeTrustEvaluator{trusted: false, reason: "unknown issuer"},
			trusted, CodeZkpReqIssuerNotTrusted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := refusalClient(t, tc.evaluator).
				circuitZkIssuerKey(t.Context(), tc.presentation, "eu.europa.ec.eudi.nym_auth.1", time.Now())
			assertRefusal(t, err, tc.code)
		})
	}
}

// The circuit's field arithmetic is over P-256, so a key on another
// curve or of another kind cannot be a public input to it. Refused with
// its own code rather than folded into "not trusted": the chain may be
// perfectly trustworthy and still carry a key this circuit cannot use.
func TestZkpReqIssuerKeyShapeRefusalsAreClassified(t *testing.T) {
	now := time.Now()

	t.Run("a key on another curve", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)
		cert := testDSCertificate(t, key, &key.PublicKey, now.Add(-time.Hour), now.Add(time.Hour))

		_, err = refusalClient(t, &fakeTrustEvaluator{trusted: true}).circuitZkIssuerKey(
			t.Context(), openid4vp.ZkpPresentation{IssuerKeySet: [][]byte{cert.Raw}},
			"eu.europa.ec.eudi.nym_auth.1", now)
		assertRefusal(t, err, CodeZkpReqIssuerKeyWrongCurve)
	})

	t.Run("a key that is not ECDSA at all", func(t *testing.T) {
		signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		cert := testDSCertificate(t, signer, &rsaKey.PublicKey, now.Add(-time.Hour), now.Add(time.Hour))

		_, err = refusalClient(t, &fakeTrustEvaluator{trusted: true}).circuitZkIssuerKey(
			t.Context(), openid4vp.ZkpPresentation{IssuerKeySet: [][]byte{cert.Raw}},
			"eu.europa.ec.eudi.nym_auth.1", now)
		assertRefusal(t, err, CodeZkpReqIssuerKeyNotECDSA)
	})
}

func TestZkpReqProofTimeRefusalsAreClassified(t *testing.T) {
	client := refusalClient(t, &fakeTrustEvaluator{trusted: true})
	client.cfg.Verifier.NymAuth = model.NymAuthVerifier{}

	t.Run("absent", func(t *testing.T) {
		_, err := client.circuitZkProofTime(openid4vp.ZkpPresentation{}, time.Now())
		assertRefusal(t, err, CodeZkpReqProofTimeMissing)
	})

	t.Run("outside the window", func(t *testing.T) {
		stale := time.Now().Add(-48 * time.Hour)
		_, err := client.circuitZkProofTime(openid4vp.ZkpPresentation{
			HasProofTime:  true,
			ProofTime:     stale,
			ProofTimeText: openid4vp.RenderProofTimeOrPanic(stale),
		}, time.Now())
		assertRefusal(t, err, CodeZkpReqProofTimeOutOfRange)
		// Without the window in the message a wallet cannot tell a
		// wrong clock from a stale proof, and both land here.
		assert.Contains(t, err.Error(), "window")
	})
}

func TestZkpReqNoPresentationIsClassified(t *testing.T) {
	_, err := circuitZkRawToken(openid4vp.VPResponse{
		VPTokenRaw:      map[string]json.RawMessage{},
		VPTokenEnvelope: []byte(`{}`),
	}, "nym")
	assertRefusal(t, err, CodeZkpReqNoPresentation)
}

func TestZkpReqWrongChannelIsClassified(t *testing.T) {
	client := refusalClient(t, &fakeTrustEvaluator{trusted: true})
	client.cfg.Verifier.NymAuth = model.NymAuthVerifier{VerifierID: "x509_san_dns:verifier.example"}

	_, err := client.circuitZkSessionFor(nil, "no-such-channel", "", "client", "nonce", "", "doc", nil)
	assertRefusal(t, err, CodeZkpReqWrongChannel)
}

// A shape refusal keeps the SHARED validator's reason code rather than
// being renamed here, so a wallet author compares one vocabulary against
// the matcher vectors instead of two.
func TestZkpReqShapeRefusalKeepsTheSharedReasonCode(t *testing.T) {
	refusal, ok := zkpReqShapeRefusal(&openid4vp.ZkpReqResponseError{
		Reason: "presentations_empty", Detail: "nothing to validate",
	})
	require.True(t, ok)
	assert.Equal(t, "presentations_empty", refusal.Code)
	assert.Equal(t, http.StatusBadRequest, refusal.HTTPError().HTTPStatus)
}

// A verifier that cannot judge a presentation has not refused one. Those
// must stay 5xx: a wallet author told "your presentation is bad" would go
// hunting for a defect that is not theirs.
func TestVerifierFaultsAreNotClassifiedAsRefusals(t *testing.T) {
	t.Run("no trust evaluator", func(t *testing.T) {
		presentation, _ := testP256Chain(t)
		_, err := refusalClient(t, nil).
			circuitZkIssuerKey(t.Context(), presentation, "eu.europa.ec.eudi.nym_auth.1", time.Now())
		require.Error(t, err)
		_, isRefusal := zkpReqRefusalFrom(err)
		assert.False(t, isRefusal, "an absent trust evaluator is this verifier's fault, not the wallet's")
	})
}

// Every declared code must be exercised above. A code added without a
// test is a refusal nobody has seen rendered, which is how the 500 got
// there in the first place.
func TestEveryDeclaredRefusalCodeIsTested(t *testing.T) {
	source, err := os.ReadFile("circuit_zk_refusal.go")
	require.NoError(t, err)
	// Every refusal test file, because three of the codes are on the
	// cgo path and can only be exercised behind the zknative tag.
	var tests strings.Builder
	for _, name := range []string{"circuit_zk_refusal_test.go", "circuit_zk_refusal_zknative_test.go"} {
		body, err := os.ReadFile(name)
		require.NoErrorf(t, err, "%s is missing; this guard is reading the wrong files", name)
		tests.Write(body)
	}

	declared := regexp.MustCompile(`(CodeZkpReq[A-Za-z]+)\s+=`).FindAllStringSubmatch(string(source), -1)
	require.NotEmpty(t, declared)

	for _, match := range declared {
		name := match[1]
		t.Run(name, func(t *testing.T) {
			assert.Truef(t, strings.Contains(tests.String(), name),
				"%s is declared but never asserted, so nobody has seen it rendered", name)
		})
	}
}
