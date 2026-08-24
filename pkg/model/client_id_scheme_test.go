package model

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newClientIDTestCert mints a throwaway self-signed leaf. x509_hash pins the
// certificate's exact DER bytes, so nothing about the issuer matters here -
// only that Raw is a stable, real DER encoding.
func newClientIDTestCert(t *testing.T, dnsNames ...string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "verifier.example.com"},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func TestVerifierClientID_X509SANDNS(t *testing.T) {
	v := &Verifier{ClientIDScheme: "x509_san_dns", PublicURL: "https://verifier.example.com"}

	got, err := v.VerifierClientID(nil)
	require.NoError(t, err, "x509_san_dns must not require a certificate")
	assert.Equal(t, "x509_san_dns:verifier.example.com", got)
}

func TestVerifierClientID_DID(t *testing.T) {
	v := &Verifier{ClientIDScheme: "did", DID: "did:web:verifier.example.com"}

	got, err := v.VerifierClientID(nil)
	require.NoError(t, err, "did must not require a certificate")
	assert.Equal(t, "did:web:verifier.example.com", got)
}

// TestVerifierClientID_X509Hash_IsBase64URLNotHex pins the encoding. OpenID4VP
// 1.0 requires the base64url-encoded SHA-256 of the DER-encoded leaf. Emitting
// hex would round-trip against our own stack - go-trust's VerifyLeafBinding
// accepts either - and fail against a spec-strict wallet, so the wrong choice
// would only surface at an interop event.
func TestVerifierClientID_X509Hash_IsBase64URLNotHex(t *testing.T) {
	cert := newClientIDTestCert(t)
	v := &Verifier{ClientIDScheme: "x509_hash", PublicURL: "https://verifier.example.com"}

	got, err := v.VerifierClientID(cert)
	require.NoError(t, err)

	value, ok := strings.CutPrefix(got, "x509_hash:")
	require.True(t, ok, "client_id must carry the x509_hash: prefix, got %q", got)

	digest := sha256.Sum256(cert.Raw)
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(digest[:]), value,
		"value must be unpadded base64url of SHA-256 over the DER bytes")
	assert.NotEqual(t, hex.EncodeToString(digest[:]), value,
		"hex is accepted by our own validator but violates OpenID4VP; it must never be emitted")
	assert.NotContains(t, value, "=", "base64url here is unpadded")
}

// TestVerifierClientID_X509Hash_RoundTripsThroughGoTrust is the test that
// actually matters: it feeds our emitted client_id straight into the verifier
// half (go-trust's registry.VerifyLeafBinding, which is what a relying party
// validating us would run) and requires it to bind. Emitter and validator are
// pinned together, so an encoding change on either side fails here rather than
// against a real wallet.
func TestVerifierClientID_X509Hash_RoundTripsThroughGoTrust(t *testing.T) {
	cert := newClientIDTestCert(t)
	v := &Verifier{ClientIDScheme: "x509_hash", PublicURL: "https://verifier.example.com"}

	clientID, err := v.VerifierClientID(cert)
	require.NoError(t, err)

	scheme, value, ok := registry.ParseClientIDScheme(clientID)
	require.True(t, ok, "go-trust must recognise the client_id we emit")
	require.Equal(t, registry.ClientIDSchemeX509Hash, scheme)

	require.NoError(t, registry.VerifyLeafBinding(scheme, value, cert),
		"our emitted client_id must bind to the certificate it was derived from")

	// A different certificate must NOT satisfy the binding - otherwise the
	// assertion above would pass for any input and prove nothing.
	other := newClientIDTestCert(t)
	assert.Error(t, registry.VerifyLeafBinding(scheme, value, other),
		"the digest must be specific to its own certificate")
}

func TestVerifierClientID_X509Hash_RequiresCertificate(t *testing.T) {
	v := &Verifier{ClientIDScheme: "x509_hash", PublicURL: "https://verifier.example.com"}

	_, err := v.VerifierClientID(nil)
	require.Error(t, err, "x509_hash cannot be derived without a certificate")
	assert.Contains(t, err.Error(), "x509_hash")
}

// TestVerifierClientID_X509SANDNS_RoundTripsThroughGoTrust covers the default
// scheme through the same validator, so the two schemes stay consistent about
// how the client_id is shaped.
func TestVerifierClientID_X509SANDNS_RoundTripsThroughGoTrust(t *testing.T) {
	cert := newClientIDTestCert(t, "verifier.example.com")
	v := &Verifier{ClientIDScheme: "x509_san_dns", PublicURL: "https://verifier.example.com"}

	clientID, err := v.VerifierClientID(cert)
	require.NoError(t, err)

	scheme, value, ok := registry.ParseClientIDScheme(clientID)
	require.True(t, ok)
	require.Equal(t, registry.ClientIDSchemeX509SANDNS, scheme)
	require.NoError(t, registry.VerifyLeafBinding(scheme, value, cert),
		"the host taken from PublicURL must match the certificate's DNS SAN")
}
