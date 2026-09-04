package revocation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixture is one CA, one leaf it issued, and a CRL it signed. The CA key is
// kept so a test can sign a list with a validity window of its own choosing.
type fixture struct {
	leaf  *x509.Certificate
	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey
	crl   []byte
}

// crlFixture mints a CA, a leaf naming the given CRL URL, and a signed CRL
// listing whichever serials are passed. Real DER throughout - a hand-rolled
// mock would not exercise x509.ParseRevocationList or CheckSignatureFrom,
// which are the parts most likely to be wrong.
func crlFixture(t *testing.T, crlURL string, revokedSerials ...int64) fixture {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Access CA"},
		NotBefore:             time.Now().Add(-72 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "verifier.example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		CRLDistributionPoints: []string{crlURL},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	f := fixture{leaf: leaf, ca: ca, caKey: caKey}

	entries := make([]x509.RevocationListEntry, 0, len(revokedSerials))
	for _, s := range revokedSerials {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   big.NewInt(s),
			RevocationTime: time.Now().Add(-time.Minute),
		})
	}
	f.crl = f.signCRL(t, &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                time.Now().Add(-time.Minute),
		NextUpdate:                time.Now().Add(time.Hour),
		RevokedCertificateEntries: entries,
	})
	return f
}

// signCRL signs a list with this fixture's CA.
func (f fixture) signCRL(t *testing.T, list *x509.RevocationList) []byte {
	t.Helper()
	der, err := x509.CreateRevocationList(rand.Reader, list, f.ca, f.caKey)
	require.NoError(t, err)
	return der
}

// serveCRL starts a test server returning whatever der points at when the
// request arrives, so a fixture and the bytes served at its own distribution
// point can be built in either order.
func serveCRL(t *testing.T, der *[]byte) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(*der)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// servedFixture mints a leaf whose CRL distribution point is a live test
// server serving the matching CRL, so the certificate and the list it points
// at cannot drift apart.
func servedFixture(t *testing.T, revokedSerials ...int64) fixture {
	t.Helper()
	var der []byte
	f := crlFixture(t, serveCRL(t, &der), revokedSerials...)
	der = f.crl
	return f
}

func TestCRLChecker_NotRevoked(t *testing.T) {
	// The leaf's serial is 42; the list names a different one.
	f := servedFixture(t, 999)

	got, err := NewCRLChecker().CheckCertificate(t.Context(), f.leaf, f.ca)
	require.NoError(t, err)
	assert.Equal(t, StatusValid, got.Status)
}

func TestCRLChecker_Revoked(t *testing.T) {
	// The leaf's serial is 42, and the list names it.
	f := servedFixture(t, 42)

	got, err := NewCRLChecker().CheckCertificate(t.Context(), f.leaf, f.ca)
	require.NoError(t, err)
	assert.Equal(t, StatusInvalid, got.Status)
}

// TestCRLChecker_UnreachableIsUnknown is the property that matters most: a
// CRL that cannot be fetched must never read as valid.
func TestCRLChecker_UnreachableIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing listening now

	f := crlFixture(t, url, 42)

	got, err := NewCRLChecker().CheckCertificate(t.Context(), f.leaf, f.ca)
	require.Error(t, err)
	assert.Equal(t, StatusUnknown, got.Status, "unreachable must not be valid")
}

// TestCRLChecker_ForgedEmptyListIsNotValid is the reason the signature is
// checked at all. Whoever can answer the distribution point URI - a
// compromised CA endpoint, anyone on the path of a plain-http one - could
// otherwise serve an empty list and have a revoked certificate read as good.
func TestCRLChecker_ForgedEmptyListIsNotValid(t *testing.T) {
	var der []byte
	url := serveCRL(t, &der)
	f := crlFixture(t, url)     // the CA that actually issued the leaf
	other := crlFixture(t, url) // an unrelated CA, empty list
	der = other.crl

	got, err := NewCRLChecker().CheckCertificate(t.Context(), f.leaf, f.ca)
	require.Error(t, err)
	assert.Equal(t, StatusUnknown, got.Status,
		"an empty list from anyone but our own CA must not read as valid")
}

// TestCRLChecker_ForgedRevocationIsNotBelieved covers the other direction: a
// stranger must not be able to take our certificate out of service by serving
// a list that names its serial.
func TestCRLChecker_ForgedRevocationIsNotBelieved(t *testing.T) {
	var der []byte
	url := serveCRL(t, &der)
	f := crlFixture(t, url)
	other := crlFixture(t, url, 42) // unrelated CA naming our serial
	der = other.crl

	got, err := NewCRLChecker().CheckCertificate(t.Context(), f.leaf, f.ca)
	require.Error(t, err)
	assert.Equal(t, StatusUnknown, got.Status,
		"a list we cannot authenticate must not revoke us either")
}

// TestCRLChecker_ExpiredListIsNotValid covers a CA that stopped publishing.
// Honouring a stale list would freeze our answer at whatever it last said.
func TestCRLChecker_ExpiredListIsNotValid(t *testing.T) {
	var der []byte
	url := serveCRL(t, &der)
	f := crlFixture(t, url)
	der = f.signCRL(t, &x509.RevocationList{
		Number:     big.NewInt(2),
		ThisUpdate: time.Now().Add(-48 * time.Hour),
		NextUpdate: time.Now().Add(-24 * time.Hour),
	})

	got, err := NewCRLChecker().CheckCertificate(t.Context(), f.leaf, f.ca)
	require.Error(t, err)
	assert.Equal(t, StatusUnknown, got.Status, "a stale list is not evidence of validity")
	assert.Contains(t, err.Error(), "expired")
}

// TestCRLChecker_NoDistributionPoint covers a certificate that simply cannot
// be checked this way.
func TestCRLChecker_NoDistributionPoint(t *testing.T) {
	f := crlFixture(t, "ldap://ca.example/cn=crl") // not fetchable

	got, err := NewCRLChecker().CheckCertificate(t.Context(), f.leaf, f.ca)
	require.Error(t, err)
	assert.Equal(t, StatusUnknown, got.Status)
	assert.Contains(t, err.Error(), "no fetchable CRL distribution point")
}

func TestCRLChecker_NilCertificate(t *testing.T) {
	got, err := NewCRLChecker().CheckCertificate(t.Context(), nil, nil)
	require.Error(t, err)
	assert.Equal(t, StatusUnknown, got.Status)
}

// TestCRLChecker_NilIssuerIsUnknown: without the issuing CA there is nothing
// to authenticate a list against, so there is no answer to give.
func TestCRLChecker_NilIssuerIsUnknown(t *testing.T) {
	f := servedFixture(t, 999)

	got, err := NewCRLChecker().CheckCertificate(t.Context(), f.leaf, nil)
	require.Error(t, err)
	assert.Equal(t, StatusUnknown, got.Status)
	assert.Contains(t, err.Error(), "no issuer certificate")
}

// TestCRLChecker_RejectsNonHTTPScheme guards the SSRF surface. Reachable only
// if fetch is called directly, since CRLDistributionPoints filters these out,
// but the sibling StatusListChecker enforces it and one rule is better here.
func TestCRLChecker_RejectsNonHTTPScheme(t *testing.T) {
	_, err := NewCRLChecker().fetch(t.Context(), "file:///etc/passwd")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported CRL URI scheme")
}

// TestCRLChecker_AcceptsPEM covers distribution points that serve PEM despite
// the spec calling for DER.
func TestCRLChecker_AcceptsPEM(t *testing.T) {
	f := crlFixture(t, "http://ca.example.invalid/crl")
	der := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: f.crl})
	url := serveCRL(t, &der)

	list, err := NewCRLChecker().fetch(t.Context(), url)
	require.NoError(t, err)
	assert.Equal(t, f.ca.RawSubject, list.RawIssuer)
}

// TestCRLChecker_RejectsNonCRLPEM: a misconfigured endpoint serving some
// other PEM object should say so, not fail as malformed DER.
func TestCRLChecker_RejectsNonCRLPEM(t *testing.T) {
	der := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a crl")})
	url := serveCRL(t, &der)

	_, err := NewCRLChecker().fetch(t.Context(), url)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `PEM block is "CERTIFICATE", not a CRL`)
}

// TestCRLChecker_OversizedIsReportedAsSuch covers a response past the limit.
// Truncating at exactly the limit would hand ParseRevocationList half a CRL
// and surface as a parse error, saying nothing about what went wrong.
func TestCRLChecker_OversizedIsReportedAsSuch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// One byte past the cap.
		_, _ = w.Write(make([]byte, maxCRLBytes+1))
	}))
	t.Cleanup(srv.Close)

	_, err := NewCRLChecker().fetch(t.Context(), srv.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum size",
		"an oversized CRL must say so, not fail as malformed")
}
