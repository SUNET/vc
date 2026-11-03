package apiv1

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/trust"
)

// fakeTrustEvaluator records what it was asked and answers as told.
//
// A fake rather than a live PDP because what these cases are about is
// the REQUEST this verifier builds and what it does with the answer -
// that the docType comes from the request, that a refusal is a
// refusal. Whether a given chain is trusted is go-trust's question,
// tested there.
type fakeTrustEvaluator struct {
	trusted bool
	reason  string
	err     error
	seen    *trust.EvaluationRequest
}

func (f *fakeTrustEvaluator) Evaluate(_ context.Context, req *trust.EvaluationRequest) (*trust.TrustDecision, error) {
	f.seen = req
	if f.err != nil {
		return nil, f.err
	}
	return &trust.TrustDecision{Trusted: f.trusted, Reason: f.reason}, nil
}

func (f *fakeTrustEvaluator) SupportsKeyType(trust.KeyType) bool { return true }
func (f *fakeTrustEvaluator) Name() string                       { return "fake" }
func (f *fakeTrustEvaluator) Healthy() bool                      { return true }

const testIssuerURL = "https://issuer.example"

// testDSCertificate builds a DS certificate the way the fixture shape
// has it: a URI SAN naming the issuer, which is where
// mdoc.VerifyIssuerChain takes the subject id from.
//
// PROVISIONAL fixture: the matcher PR that defines the wire shape is
// still in review. What is being asserted here is this verifier's
// behaviour given a chain, not the chain's exact bytes.
func testDSCertificate(t *testing.T, signer any, public any, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()

	issuerURI, err := url.Parse(testIssuerURL)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test DS"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		URIs:         []*url.URL{issuerURI},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, signer)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// testP256Chain is a one-certificate chain and the key inside it.
func testP256Chain(t *testing.T) (openid4vp.ZkpPresentation, *ecdsa.PublicKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	now := time.Now()
	cert := testDSCertificate(t, key, &key.PublicKey, now.Add(-time.Hour), now.Add(time.Hour))
	return openid4vp.ZkpPresentation{IssuerKeySet: [][]byte{cert.Raw}}, &key.PublicKey
}

func issuerKeyClient(evaluator trust.TrustEvaluator) *Client {
	return &Client{cfg: &model.Cfg{Verifier: &model.Verifier{}}, trustEvaluator: evaluator}
}

// Q comes from the presentation's chain, and only after the trust
// layer has said the chain belongs to an issuer this verifier accepts.
func TestCircuitZkIssuerKeyFromATrustedChain(t *testing.T) {
	presentation, want := testP256Chain(t)
	evaluator := &fakeTrustEvaluator{trusted: true}

	got, err := issuerKeyClient(evaluator).circuitZkIssuerKey(
		t.Context(), presentation, "eu.europa.ec.eudi.nym_auth.1", time.Now())
	require.NoError(t, err)
	assert.True(t, want.Equal(got), "Q is the leaf's public key")
}

// The trust request is the one a plain mdoc presentation makes: the
// issuer URL from the leaf's SAN, the chain as x5c, the credential
// issuer role - and the docType from the REQUEST.
func TestCircuitZkIssuerKeyAsksTheSameQuestionAsPlainMdoc(t *testing.T) {
	presentation, _ := testP256Chain(t)
	evaluator := &fakeTrustEvaluator{trusted: true}

	_, err := issuerKeyClient(evaluator).circuitZkIssuerKey(
		t.Context(), presentation, "eu.europa.ec.eudi.nym_auth.1", time.Now())
	require.NoError(t, err)
	require.NotNil(t, evaluator.seen)

	assert.Equal(t, testIssuerURL, evaluator.seen.SubjectID, "the issuer id comes from the leaf's URI SAN")
	assert.Equal(t, trust.KeyTypeX5C, evaluator.seen.KeyType)
	assert.Equal(t, trust.RoleCredentialIssuer, evaluator.seen.Role)
	assert.Equal(t, "eu.europa.ec.eudi.nym_auth.1", evaluator.seen.DocType,
		"the docType is the request's; the holder does not choose the trust policy it is judged under")
	assert.Len(t, evaluator.seen.Key, 1, "the chain is passed as-is")
}

// The docType is the REQUEST's and never the response's. A holder
// that could name it would be choosing which issuers count as
// trusted for its own presentation.
func TestCircuitZkIssuerKeyDocTypeComesFromTheCaller(t *testing.T) {
	presentation, _ := testP256Chain(t)
	evaluator := &fakeTrustEvaluator{trusted: true}

	_, err := issuerKeyClient(evaluator).circuitZkIssuerKey(
		t.Context(), presentation, "org.example.some.other.doctype", time.Now())
	require.NoError(t, err)
	assert.Equal(t, "org.example.some.other.doctype", evaluator.seen.DocType)
}

func TestCircuitZkIssuerKeyRefusals(t *testing.T) {
	trustedChain, _ := testP256Chain(t)

	for _, tc := range []struct {
		name         string
		client       func(t *testing.T) *Client
		presentation func(t *testing.T) openid4vp.ZkpPresentation
		contains     string
	}{{
		// Fail closed: a verifier that cannot ask whether an issuer
		// is trusted must not read its own silence as a yes.
		name:     "no trust evaluator configured",
		client:   func(*testing.T) *Client { return issuerKeyClient(nil) },
		contains: "no trust evaluator is configured",
	}, {
		// The shared vectors do not carry x5chain yet, so the
		// validator lets a chainless presentation through. It stops
		// here: there is no key, and a proof checked against no key
		// is not checked.
		name:         "no chain in the presentation",
		client:       func(*testing.T) *Client { return issuerKeyClient(&fakeTrustEvaluator{trusted: true}) },
		presentation: func(*testing.T) openid4vp.ZkpPresentation { return openid4vp.ZkpPresentation{} },
		contains:     "carries no issuer key set",
	}, {
		name:   "the chain is not DER",
		client: func(*testing.T) *Client { return issuerKeyClient(&fakeTrustEvaluator{trusted: true}) },
		presentation: func(*testing.T) openid4vp.ZkpPresentation {
			return openid4vp.ZkpPresentation{IssuerKeySet: [][]byte{[]byte("not a certificate")}}
		},
		contains: "does not parse",
	}, {
		// decision=false is a refusal, not an empty answer to carry
		// on from.
		name: "the PDP says no",
		client: func(*testing.T) *Client {
			return issuerKeyClient(&fakeTrustEvaluator{trusted: false, reason: "unknown issuer"})
		},
		contains: "is not trusted for docType",
	}, {
		// A PDP that could not answer is not a PDP that said no, and
		// either way nothing is trusted.
		name: "the PDP could not be reached",
		client: func(*testing.T) *Client {
			return issuerKeyClient(&fakeTrustEvaluator{err: assert.AnError})
		},
		contains: "is not trusted for docType",
	}, {
		// The circuit's arithmetic is over P-256. A key on another
		// curve cannot be a public input to it.
		name:   "the leaf key is not P-256",
		client: func(*testing.T) *Client { return issuerKeyClient(&fakeTrustEvaluator{trusted: true}) },
		presentation: func(t *testing.T) openid4vp.ZkpPresentation {
			key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			require.NoError(t, err)
			now := time.Now()
			cert := testDSCertificate(t, key, &key.PublicKey, now.Add(-time.Hour), now.Add(time.Hour))
			return openid4vp.ZkpPresentation{IssuerKeySet: [][]byte{cert.Raw}}
		},
		contains: "is on P-384, and the circuit takes P-256",
	}, {
		name:   "the leaf key is not ECDSA at all",
		client: func(*testing.T) *Client { return issuerKeyClient(&fakeTrustEvaluator{trusted: true}) },
		presentation: func(t *testing.T) openid4vp.ZkpPresentation {
			public, private, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)
			now := time.Now()
			cert := testDSCertificate(t, private, public, now.Add(-time.Hour), now.Add(time.Hour))
			return openid4vp.ZkpPresentation{IssuerKeySet: [][]byte{cert.Raw}}
		},
		contains: "and the circuit takes a P-256 key",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			presentation := trustedChain
			if tc.presentation != nil {
				presentation = tc.presentation(t)
			}
			_, err := tc.client(t).circuitZkIssuerKey(
				t.Context(), presentation, "eu.europa.ec.eudi.nym_auth.1", time.Now())
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.contains)
		})
	}
}

// An expired DS certificate is refused, and the moment it is judged
// at is the one passed in - not whenever the test happens to run.
func TestCircuitZkIssuerKeyHonoursTheCertificateValidityPeriod(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	issued := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cert := testDSCertificate(t, key, &key.PublicKey, issued, issued.Add(24*time.Hour))
	presentation := openid4vp.ZkpPresentation{IssuerKeySet: [][]byte{cert.Raw}}
	client := issuerKeyClient(&fakeTrustEvaluator{trusted: true})

	_, err = client.circuitZkIssuerKey(t.Context(), presentation, "eu.europa.ec.eudi.nym_auth.1", issued.Add(time.Hour))
	require.NoError(t, err, "inside the validity period")

	_, err = client.circuitZkIssuerKey(t.Context(), presentation, "eu.europa.ec.eudi.nym_auth.1", issued.Add(48*time.Hour))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")

	_, err = client.circuitZkIssuerKey(t.Context(), presentation, "eu.europa.ec.eudi.nym_auth.1", issued.Add(-time.Hour))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not yet valid")
}

// The key is taken only AFTER the chain is trusted. An untrusted
// chain's key is not one this verifier has any business looking at,
// and a refusal that still returned a key would invite a caller to
// use it.
func TestCircuitZkIssuerKeyReturnsNothingWhenUntrusted(t *testing.T) {
	presentation, _ := testP256Chain(t)

	got, err := issuerKeyClient(&fakeTrustEvaluator{trusted: false}).circuitZkIssuerKey(
		t.Context(), presentation, "eu.europa.ec.eudi.nym_auth.1", time.Now())
	require.Error(t, err)
	assert.Nil(t, got)
}

// An allow-all trust evaluator is refused, and the case that makes it
// matter is a chain the HOLDER minted.
//
// NewTrustEvaluatorFromConfig returns AllowAllEvaluator when
// verifier.trust.pdp_url is empty, and it is not nil - so the nil
// check above does not catch it, and every chain gets Trusted=true.
//
// That is not a weaker check, it is no check. The circuit proves "this
// credential was signed by Q" for whatever Q it is handed; the only
// thing standing between that and a holder issuing a credential to
// itself is the trust layer. Without it the holder picks its own
// issuer key and therefore its own pseudonym, and a flagged person
// presents a value that matches nothing and reads as innocent.
func TestCircuitZkIssuerKeyRefusesAnAllowAllEvaluator(t *testing.T) {
	// A certificate the "holder" signed for itself, which is exactly
	// what a real attacker would send.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	selfSigned := testDSCertificate(t, key, &key.PublicKey, now.Add(-time.Hour), now.Add(time.Hour))
	presentation := openid4vp.ZkpPresentation{IssuerKeySet: [][]byte{selfSigned.Raw}}

	client := issuerKeyClient(trust.NewTrustEvaluatorFromConfig(""))
	got, err := client.circuitZkIssuerKey(t.Context(), presentation, "eu.europa.ec.eudi.nym_auth.1", now)

	require.ErrorIs(t, err, ErrAllowAllTrustEvaluator)
	assert.Nil(t, got, "a self-signed holder-minted issuer must yield no key")

	// And a real evaluator still works, so this refuses the mode and
	// not the path.
	got, err = issuerKeyClient(&fakeTrustEvaluator{trusted: true}).circuitZkIssuerKey(
		t.Context(), presentation, "eu.europa.ec.eudi.nym_auth.1", now)
	require.NoError(t, err)
	assert.NotNil(t, got)
}

// The thumbprint names a key in a log line without putting one in it,
// and two keys are two thumbprints.
func TestIssuerKeyThumbprint(t *testing.T) {
	one, two := testKey(t), testKey(t)

	assert.NotEmpty(t, issuerKeyThumbprint(one))
	assert.Equal(t, issuerKeyThumbprint(one), issuerKeyThumbprint(one), "stable for one key")
	assert.NotEqual(t, issuerKeyThumbprint(one), issuerKeyThumbprint(two))
	assert.Empty(t, issuerKeyThumbprint(nil))
	assert.Empty(t, issuerKeyThumbprint(&ecdsa.PublicKey{}), "an incomplete key names nothing")
}

func testKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return &key.PublicKey
}
