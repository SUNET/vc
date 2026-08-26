package apiv1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/pki"
	"github.com/sirosfoundation/go-trust/pkg/registry/rpcert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeWRPACKeyPair writes a WRPAC-conformant certificate and its key to a
// temporary directory and returns a KeyConfig pointing at them, plus the
// base64 DER of the certificate for comparison against the emitted x5c.
func writeWRPACKeyPair(t *testing.T) (*pki.KeyConfig, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	contact, err := url.Parse("https://issuer.example.com/contact")
	require.NoError(t, err)

	policy, err := x509.ParseOID(rpcert.OIDQCPLegalPerson)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Issuer Access Certificate",
			Organization: []string{"Example Issuer AB"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		// nonRepudiation (contentCommitment) is required by the WRPAC profile.
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		URIs:     []*url.URL{contact},
		DNSNames: []string{"issuer.example.com"},
		Policies: []x509.OID{policy},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "wrpac.key")
	certPath := filepath.Join(dir, "wrpac.pem")

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(keyPath,
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))
	require.NoError(t, os.WriteFile(certPath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644))

	return &pki.KeyConfig{PrivateKeyPath: keyPath, ChainPath: certPath},
		base64.StdEncoding.EncodeToString(der)
}

// TestSignMetadata_UsesAccessCertificate is the point of the split: metadata
// must be signed with the access certificate, not the credential key.
//
// It also carries the x5c assertion that used to live on the now-retired
// CredentialIssuerMetadataParameters.Sign - the chain is what lets a wallet
// establish who the issuer is, since JWKS is self-asserted.
func TestSignMetadata_UsesAccessCertificate(t *testing.T) {
	client := newSignMetadataClient(t)
	credentialSigner := client.signer

	keyConfig, wantX5C := writeWRPACKeyPair(t)
	client.cfg.Issuer.AccessCertificate = &model.IssuerAccessCertificate{
		Validate:  true,
		KeyConfig: keyConfig,
	}
	require.NoError(t, client.initAccessCertificate(t.Context()))

	require.NotSame(t, credentialSigner, client.metadataSigner,
		"metadata must not be signed with the credential key once an access certificate is configured")
	assert.Same(t, credentialSigner, client.signer,
		"credentials keep the credential key")

	reply, err := client.SignMetadata(t.Context(), &apiv1_issuer.SignMetadataRequest{
		MetadataJson: validVCIMetadataJSON(t),
		MetadataType: MetadataTypeVCIIssuer,
		Iss:          testIssuerURL,
	})
	require.NoError(t, err)

	header, _ := decodeJWTParts(t, reply.GetSignedMetadata())
	chain, ok := header["x5c"].([]any)
	require.True(t, ok, "x5c must be present so a wallet can chain the metadata signature")
	require.Len(t, chain, 1)
	assert.Equal(t, wantX5C, chain[0], "x5c must carry the access certificate, not the credential chain")
}

// TestInitAccessCertificate_FallsBackToCredentialKey covers the degraded
// configuration the split deliberately still supports, so an existing
// deployment keeps booting across an upgrade.
func TestInitAccessCertificate_FallsBackToCredentialKey(t *testing.T) {
	client := newSignMetadataClient(t)
	client.cfg.Issuer.AccessCertificate = nil

	require.NoError(t, client.initAccessCertificate(t.Context()))
	assert.Same(t, client.signer, client.metadataSigner)
	assert.Equal(t, client.signerChain, client.metadataChain)
}

// TestInitAccessCertificate_ValidationIsNotVacuousWithoutAKey pins that
// opting into validation without configuring a separate key still checks the
// certificate actually being presented. Otherwise setting validate: true
// would silently assert nothing at all.
func TestInitAccessCertificate_ValidationIsNotVacuousWithoutAKey(t *testing.T) {
	client := newSignMetadataClient(t)
	client.cfg.Issuer.AccessCertificate = &model.IssuerAccessCertificate{
		Validate: true,
	}

	// The test fixture's credential key has no certificate at all, so
	// validation must fail rather than pass by default.
	err := client.initAccessCertificate(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access certificate validation failed")
}

// TestInitAccessCertificate_RejectsNonConformantCertificate covers fail-closed
// startup: a configured certificate that does not meet the WRPAC profile must
// stop the issuer rather than be presented to wallets.
func TestInitAccessCertificate_RejectsNonConformantCertificate(t *testing.T) {
	keyConfig, _ := writeWRPACKeyPair(t)

	// Replace the conformant certificate with one missing nonRepudiation.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Not A WRPAC"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(keyConfig.PrivateKeyPath,
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))
	require.NoError(t, os.WriteFile(keyConfig.ChainPath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644))

	client := newSignMetadataClient(t)
	client.cfg.Issuer.AccessCertificate = &model.IssuerAccessCertificate{
		Validate:  true,
		KeyConfig: keyConfig,
	}

	err = client.initAccessCertificate(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access certificate validation failed")
}

// TestInitAccessCertificate_LoadsWithoutValidation covers a deployment that
// wants the key separation without opting into profile enforcement.
func TestInitAccessCertificate_LoadsWithoutValidation(t *testing.T) {
	client := newSignMetadataClient(t)
	keyConfig, wantX5C := writeWRPACKeyPair(t)
	client.cfg.Issuer.AccessCertificate = &model.IssuerAccessCertificate{
		KeyConfig: keyConfig,
	}

	require.NoError(t, client.initAccessCertificate(t.Context()))
	require.Len(t, client.metadataChain, 1)
	assert.Equal(t, wantX5C, client.metadataChain[0])
}
