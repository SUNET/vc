package model

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/registry/rpcert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// wrpacCertOptions describes how far a generated certificate should deviate
// from a conformant WRPAC, so each test can break exactly one requirement.
type wrpacCertOptions struct {
	keyUsage  x509.KeyUsage
	uris      []*url.URL
	emails    []string
	policyOID string
	dnsNames  []string
	notBefore time.Time
	notAfter  time.Time
}

// conformantWRPACOptions returns options producing a certificate that passes
// every WRPAC profile check, as the baseline for one-thing-wrong variants.
func conformantWRPACOptions(t *testing.T) wrpacCertOptions {
	t.Helper()
	u, err := url.Parse("https://verifier.example.com/contact")
	require.NoError(t, err)
	return wrpacCertOptions{
		keyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		uris:      []*url.URL{u},
		policyOID: rpcert.OIDQCPLegalPerson,
		dnsNames:  []string{"verifier.example.com"},
		notBefore: time.Now().Add(-time.Hour),
		notAfter:  time.Now().Add(24 * time.Hour),
	}
}

func newWRPACTestCert(t *testing.T, opts wrpacCertOptions) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(1),
		Subject:        pkix.Name{CommonName: "verifier.example.com"},
		KeyUsage:       opts.keyUsage,
		URIs:           opts.uris,
		EmailAddresses: opts.emails,
		DNSNames:       opts.dnsNames,
		NotBefore:      opts.notBefore,
		NotAfter:       opts.notAfter,
	}
	if opts.policyOID != "" {
		// Policies, not the deprecated PolicyIdentifiers: current Go writes
		// the certificatePolicies extension only from Policies and silently
		// drops PolicyIdentifiers, which would produce a certificate with no
		// policy extension at all and make these tests fail for a reason
		// unrelated to what they are checking.
		oid, err := x509.ParseOID(opts.policyOID)
		require.NoError(t, err)
		tmpl.Policies = []x509.OID{oid}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func verifierWithAccessCert(validate bool, allowed ...string) *Verifier {
	return &Verifier{
		ClientIDScheme:    "x509_san_dns",
		PublicURL:         "https://verifier.example.com",
		AccessCertificate: &AccessCertificate{Validate: validate, AllowedPolicyOIDs: allowed},
	}
}

// TestValidateAccessCertificate_DisabledByDefault pins that a deployment that
// has not opted in is never failed by these checks - including one holding a
// certificate that would not pass them.
func TestValidateAccessCertificate_DisabledByDefault(t *testing.T) {
	nonConformant := newWRPACTestCert(t, wrpacCertOptions{
		keyUsage:  x509.KeyUsageDigitalSignature, // no contentCommitment
		notBefore: time.Now().Add(-time.Hour),
		notAfter:  time.Now().Add(time.Hour),
	})

	t.Run("nil config", func(t *testing.T) {
		v := &Verifier{ClientIDScheme: "x509_san_dns", PublicURL: "https://verifier.example.com"}
		require.NoError(t, v.ValidateAccessCertificate(nonConformant, time.Now()))
	})

	t.Run("validate false", func(t *testing.T) {
		v := verifierWithAccessCert(false)
		require.NoError(t, v.ValidateAccessCertificate(nonConformant, time.Now()))
	})
}

func TestValidateAccessCertificate_Conformant(t *testing.T) {
	cert := newWRPACTestCert(t, conformantWRPACOptions(t))
	v := verifierWithAccessCert(true)

	require.NoError(t, v.ValidateAccessCertificate(cert, time.Now()))
}

func TestValidateAccessCertificate_RequiresCertificate(t *testing.T) {
	v := verifierWithAccessCert(true)

	err := v.ValidateAccessCertificate(nil, time.Now())
	require.ErrorIs(t, err, ErrNoAccessCertificate)
}

// TestValidateAccessCertificate_ProfileViolations breaks one WRPAC
// requirement at a time, so each error is attributable to its own check
// rather than passing for an unrelated reason.
func TestValidateAccessCertificate_ProfileViolations(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*wrpacCertOptions)
		wantErr string
	}{
		{
			name:    "keyUsage without contentCommitment",
			mutate:  func(o *wrpacCertOptions) { o.keyUsage = x509.KeyUsageDigitalSignature },
			wantErr: "nonRepudiation",
		},
		{
			name:    "subjectAltName without contact information",
			mutate:  func(o *wrpacCertOptions) { o.uris = nil; o.emails = nil },
			wantErr: "contact information",
		},
		{
			name:    "no WRPAC policy OID",
			mutate:  func(o *wrpacCertOptions) { o.policyOID = "" },
			wantErr: "policy OID",
		},
		{
			name:    "a policy OID that is not a WRPAC one",
			mutate:  func(o *wrpacCertOptions) { o.policyOID = "1.2.3.4.5" },
			wantErr: "policy OID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := conformantWRPACOptions(t)
			tt.mutate(&opts)
			cert := newWRPACTestCert(t, opts)

			err := verifierWithAccessCert(true).ValidateAccessCertificate(cert, time.Now())
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
			assert.Contains(t, err.Error(), "WRPAC profile")
		})
	}
}

// TestValidateAccessCertificate_ValidityWindow uses an injected clock rather
// than minting short-lived certificates, so the assertions are not racing
// wall-clock time.
func TestValidateAccessCertificate_ValidityWindow(t *testing.T) {
	cert := newWRPACTestCert(t, conformantWRPACOptions(t))
	v := verifierWithAccessCert(true)

	t.Run("expired", func(t *testing.T) {
		err := v.ValidateAccessCertificate(cert, cert.NotAfter.Add(time.Second))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
	})

	t.Run("not yet valid", func(t *testing.T) {
		err := v.ValidateAccessCertificate(cert, cert.NotBefore.Add(-time.Second))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not valid until")
	})

	t.Run("inside the window", func(t *testing.T) {
		require.NoError(t, v.ValidateAccessCertificate(cert, cert.NotBefore.Add(time.Minute)))
	})
}

func TestValidateAccessCertificate_AllowedPolicyOIDs(t *testing.T) {
	// Certificate asserts the qualified legal-person policy.
	cert := newWRPACTestCert(t, conformantWRPACOptions(t))

	t.Run("accepted when listed", func(t *testing.T) {
		v := verifierWithAccessCert(true, rpcert.OIDQCPLegalPerson, rpcert.OIDQCPNaturalPerson)
		require.NoError(t, v.ValidateAccessCertificate(cert, time.Now()))
	})

	t.Run("rejected when the deployment requires a different policy", func(t *testing.T) {
		// A conformant WRPAC that nonetheless asserts only a normalised
		// policy where the deployment demands a qualified one.
		v := verifierWithAccessCert(true, rpcert.OIDNCPNaturalPerson)
		err := v.ValidateAccessCertificate(cert, time.Now())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "none of the allowed")
	})

	t.Run("empty list accepts any WRPAC policy", func(t *testing.T) {
		v := verifierWithAccessCert(true)
		require.NoError(t, v.ValidateAccessCertificate(cert, time.Now()))
	})
}

func TestCheckPublicURLMatchesCertificate(t *testing.T) {
	opts := conformantWRPACOptions(t)
	matching := newWRPACTestCert(t, opts)

	wrongHost := conformantWRPACOptions(t)
	wrongHost.dnsNames = []string{"other.example.com"}
	mismatched := newWRPACTestCert(t, wrongHost)

	t.Run("host present in DNS SANs", func(t *testing.T) {
		v := &Verifier{ClientIDScheme: "x509_san_dns", PublicURL: "https://verifier.example.com"}
		require.NoError(t, v.CheckPublicURLMatchesCertificate(matching))
	})

	t.Run("host absent from DNS SANs", func(t *testing.T) {
		v := &Verifier{ClientIDScheme: "x509_san_dns", PublicURL: "https://verifier.example.com"}
		err := v.CheckPublicURLMatchesCertificate(mismatched)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "DNS SANs")
	})

	// The other two schemes do not resolve the client_id against DNS SANs,
	// so a mismatch there is not a problem to report.
	t.Run("x509_hash ignores DNS SANs", func(t *testing.T) {
		v := &Verifier{ClientIDScheme: "x509_hash", PublicURL: "https://verifier.example.com"}
		require.NoError(t, v.CheckPublicURLMatchesCertificate(mismatched))
	})

	t.Run("did ignores DNS SANs", func(t *testing.T) {
		v := &Verifier{ClientIDScheme: "did", PublicURL: "https://verifier.example.com", DID: "did:web:x"}
		require.NoError(t, v.CheckPublicURLMatchesCertificate(mismatched))
	})

	// The advertised client_id keeps PublicURL's port, and a value with a
	// port can never appear in a DNS SAN - so a ported PublicURL is always
	// broken for this scheme. Deriving the host separately here (Hostname(),
	// which strips the port) would report a match for exactly that case and
	// hide it until wallets rejected every request.
	t.Run("a port makes the advertised client_id unmatchable", func(t *testing.T) {
		v := &Verifier{ClientIDScheme: "x509_san_dns", PublicURL: "https://verifier.example.com:444"}
		err := v.CheckPublicURLMatchesCertificate(matching)
		require.Error(t, err, "a ported PublicURL cannot match any DNS SAN")
		assert.Contains(t, err.Error(), "verifier.example.com:444",
			"the error must name the value actually advertised, port included")
	})

	t.Run("no certificate loaded is not an error", func(t *testing.T) {
		v := &Verifier{ClientIDScheme: "x509_san_dns", PublicURL: "https://verifier.example.com"}
		require.NoError(t, v.CheckPublicURLMatchesCertificate(nil))
	})
}
