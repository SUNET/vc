package revocation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// crlFixture mints a CA, a leaf naming the given CRL URL, and a signed CRL
// listing whichever serials are passed. Real DER throughout - a hand-rolled
// mock would not exercise x509.ParseRevocationList, which is the part most
// likely to be wrong.
func crlFixture(t *testing.T, crlURL string, revokedSerials ...int64) (*x509.Certificate, []byte) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Access CA"},
		NotBefore:             time.Now().Add(-time.Hour),
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

	entries := make([]x509.RevocationListEntry, 0, len(revokedSerials))
	for _, s := range revokedSerials {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   big.NewInt(s),
			RevocationTime: time.Now().Add(-time.Minute),
		})
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                time.Now().Add(-time.Minute),
		NextUpdate:                time.Now().Add(time.Hour),
		RevokedCertificateEntries: entries,
	}, ca, caKey)
	require.NoError(t, err)

	return leaf, crlDER
}

// servedFixture mints a leaf whose CRL distribution point is a live test
// server serving the matching CRL, so the certificate and the list it points
// at cannot drift apart.
func servedFixture(t *testing.T, revokedSerials ...int64) *x509.Certificate {
	t.Helper()

	var der []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(der)
	}))
	t.Cleanup(srv.Close)

	leaf, crlDER := crlFixture(t, srv.URL, revokedSerials...)
	der = crlDER
	return leaf
}

func TestCRLChecker_NotRevoked(t *testing.T) {
	// The leaf's serial is 42; the list names a different one.
	leaf := servedFixture(t, 999)

	got, err := NewCRLChecker().CheckCertificate(t.Context(), leaf)
	require.NoError(t, err)
	assert.Equal(t, StatusValid, got.Status)
}

func TestCRLChecker_Revoked(t *testing.T) {
	// The leaf's serial is 42, and the list names it.
	leaf := servedFixture(t, 42)

	got, err := NewCRLChecker().CheckCertificate(t.Context(), leaf)
	require.NoError(t, err)
	assert.Equal(t, StatusInvalid, got.Status)
}

// TestCRLChecker_UnreachableIsUnknown is the property that matters most: a
// CRL that cannot be fetched must never read as valid.
func TestCRLChecker_UnreachableIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close() // nothing listening now

	leaf, _ := crlFixture(t, url, 42)

	got, err := NewCRLChecker().CheckCertificate(t.Context(), leaf)
	require.Error(t, err)
	assert.Equal(t, StatusUnknown, got.Status, "unreachable must not be valid")
}

// TestCRLChecker_NoDistributionPoint covers a certificate that simply cannot
// be checked this way.
func TestCRLChecker_NoDistributionPoint(t *testing.T) {
	leaf, _ := crlFixture(t, "ldap://ca.example/cn=crl") // not fetchable

	got, err := NewCRLChecker().CheckCertificate(t.Context(), leaf)
	require.Error(t, err)
	assert.Equal(t, StatusUnknown, got.Status)
	assert.Contains(t, err.Error(), "no fetchable CRL distribution point")
}

func TestCRLChecker_NilCertificate(t *testing.T) {
	got, err := NewCRLChecker().CheckCertificate(t.Context(), nil)
	require.Error(t, err)
	assert.Equal(t, StatusUnknown, got.Status)
}
