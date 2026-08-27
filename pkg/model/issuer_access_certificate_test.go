package model

import (
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/pki"
	"github.com/sirosfoundation/go-trust/pkg/registry/rpcert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func issuerWithAccessCert(validate bool, key *pki.KeyConfig, allowed ...string) *Issuer {
	return &Issuer{
		AccessCertificate: &IssuerAccessCertificate{
			Validate:          validate,
			AllowedPolicyOIDs: allowed,
			KeyConfig:         key,
		},
	}
}

// TestIssuerValidateAccessCertificate_DisabledByDefault pins that an issuer
// which has not opted in is never failed by these checks, including one
// holding a certificate that would not pass them.
func TestIssuerValidateAccessCertificate_DisabledByDefault(t *testing.T) {
	opts := conformantWRPACOptions(t)
	opts.keyUsage = 0 // would fail the profile
	cert := newWRPACTestCert(t, opts)

	assert.NoError(t, (&Issuer{}).ValidateAccessCertificate(cert, time.Now()),
		"no access_certificate block configured")
	assert.NoError(t, issuerWithAccessCert(false, nil).ValidateAccessCertificate(cert, time.Now()),
		"configured but validate unset")

	var nilIssuer *Issuer
	assert.NoError(t, nilIssuer.ValidateAccessCertificate(cert, time.Now()))
}

func TestIssuerValidateAccessCertificate_Conformant(t *testing.T) {
	cert := newWRPACTestCert(t, conformantWRPACOptions(t))
	require.NoError(t, issuerWithAccessCert(true, nil).ValidateAccessCertificate(cert, time.Now()))
}

// TestIssuerValidateAccessCertificate_SharesTheVerifierRule is the point of
// embedding AccessCertificate rather than restating the profile: an issuer
// and a verifier must reach the same verdict on the same certificate, or the
// two copies will drift.
func TestIssuerValidateAccessCertificate_SharesTheVerifierRule(t *testing.T) {
	opts := conformantWRPACOptions(t)
	opts.keyUsage = 0
	broken := newWRPACTestCert(t, opts)

	issuerErr := issuerWithAccessCert(true, nil).ValidateAccessCertificate(broken, time.Now())
	verifierErr := verifierWithAccessCert(true).ValidateAccessCertificate(broken, time.Now())

	require.Error(t, issuerErr)
	require.Error(t, verifierErr)
	assert.Equal(t, verifierErr.Error(), issuerErr.Error())
}

func TestIssuerValidateAccessCertificate_RequiresCertificate(t *testing.T) {
	err := issuerWithAccessCert(true, nil).ValidateAccessCertificate(nil, time.Now())
	require.ErrorIs(t, err, ErrNoAccessCertificate)
}

func TestIssuerValidateAccessCertificate_ValidityWindow(t *testing.T) {
	opts := conformantWRPACOptions(t)
	cert := newWRPACTestCert(t, opts)

	err := issuerWithAccessCert(true, nil).ValidateAccessCertificate(cert, time.Now().Add(48*time.Hour))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")

	err = issuerWithAccessCert(true, nil).ValidateAccessCertificate(cert, time.Now().Add(-48*time.Hour))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not valid until")
}

func TestIssuerValidateAccessCertificate_AllowedPolicyOIDs(t *testing.T) {
	cert := newWRPACTestCert(t, conformantWRPACOptions(t)) // OIDQCPLegalPerson

	require.NoError(t, issuerWithAccessCert(true, nil, rpcert.OIDQCPLegalPerson).
		ValidateAccessCertificate(cert, time.Now()))

	err := issuerWithAccessCert(true, nil, rpcert.OIDNCPLegalPerson).
		ValidateAccessCertificate(cert, time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "include none of the allowed")
}

// TestAccessCertificateKeyConfig covers the signal the issuer client reads to
// decide whether to fall back to the credential key.
func TestAccessCertificateKeyConfig(t *testing.T) {
	var nilIssuer *Issuer
	assert.Nil(t, nilIssuer.AccessCertificateKeyConfig())
	assert.Nil(t, (&Issuer{}).AccessCertificateKeyConfig())
	assert.Nil(t, issuerWithAccessCert(true, nil).AccessCertificateKeyConfig(),
		"validation on, but no separate key: fall back")

	kc := &pki.KeyConfig{PrivateKeyPath: "/etc/vc/wrpac.key"}
	assert.Same(t, kc, issuerWithAccessCert(true, kc).AccessCertificateKeyConfig())
}
