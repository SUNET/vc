package model

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/registry/rpcert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeTemp writes content to a file in t.TempDir and returns its path.
func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

// makeJWT builds a compact JWT with the given header and payload. The
// signature is not computed: every code path under test rejects or accepts
// on header typ, x5c chaining and claims, none of which read it.
func makeJWT(t *testing.T, header, payload map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		require.NoError(t, err)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return enc(header) + "." + enc(payload) + "." + base64.RawURLEncoding.EncodeToString([]byte("sig"))
}

// registrarCA mints a self-signed CA plus a leaf signed by it, standing in
// for a national Registrar and the certificate inside a WRPRC's x5c.
type registrarCA struct {
	rootPEM  string
	leafDER  []byte
	leafCert *x509.Certificate
}

func newRegistrarCA(t *testing.T) registrarCA {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Registrar Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Registrar Signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, &leafKey.PublicKey, rootKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	return registrarCA{
		rootPEM:  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})),
		leafDER:  leafDER,
		leafCert: leafCert,
	}
}

// wrprc builds a WRPRC whose x5c chains to this CA, asserting the given
// organisation identifier as its subject.
func (r registrarCA) wrprc(t *testing.T, subjectID string) string {
	t.Helper()
	return makeJWT(t,
		map[string]any{
			"typ": rpcert.WRPRCTyp,
			"alg": "ES256",
			"x5c": []string{base64.StdEncoding.EncodeToString(r.leafDER)},
		},
		map[string]any{
			"sub":          map[string]any{"id": subjectID, "legal_name": "Test RP"},
			"name":         "Test RP",
			"entitlements": []string{rpcert.EntitlementNonQEAAProvider},
		},
	)
}

// accessCertWithOrgID mints an access certificate asserting an organisation
// identifier, which the WRPAC profile reads from the subject serial number.
func accessCertWithOrgID(t *testing.T, orgID string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName:   "verifier.example.com",
			Organization: []string{"Test RP"},
			SerialNumber: orgID,
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func TestLoadRegistrationCertificate_NotConfigured(t *testing.T) {
	t.Run("nil block", func(t *testing.T) {
		v := &Verifier{}
		loaded, err := v.LoadRegistrationCertificate(nil)
		require.NoError(t, err)
		assert.Nil(t, loaded, "a deployment without a registration certificate must be unaffected")
	})

	t.Run("empty file path", func(t *testing.T) {
		v := &Verifier{RegistrationCertificate: &RegistrationCertificate{}}
		loaded, err := v.LoadRegistrationCertificate(nil)
		require.NoError(t, err)
		assert.Nil(t, loaded)
	})
}

// TestLoadRegistrationCertificate_StructuralChecks covers the always-on
// path, which runs without trust anchors and exists to catch a misconfigured
// file at startup instead of handing wallets an unusable attestation.
func TestLoadRegistrationCertificate_StructuralChecks(t *testing.T) {
	valid := makeJWT(t, map[string]any{"typ": rpcert.WRPRCTyp, "alg": "ES256"}, map[string]any{"sub": "x"})

	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{name: "accepts a well-formed WRPRC", content: valid},
		{
			name:    "rejects a PEM file pointed at by mistake",
			content: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
			wantErr: "not a compact JWT",
		},
		{
			name:    "rejects a JWT with the wrong media type",
			content: makeJWT(t, map[string]any{"typ": "JWT", "alg": "ES256"}, map[string]any{"sub": "x"}),
			wantErr: "unexpected JWT typ",
		},
		{
			name:    "rejects an empty file",
			content: "   \n",
			wantErr: "is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTemp(t, "wrprc.jwt", tt.content)
			v := &Verifier{RegistrationCertificate: &RegistrationCertificate{FilePath: path}}

			loaded, err := v.LoadRegistrationCertificate(nil)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, loaded)
			assert.Equal(t, rpcert.WRPRCTyp, loaded.Format, "format defaults to the WRPRC media type")
			assert.Nil(t, loaded.Entitlements,
				"without trusted roots nothing is attested, and a nil here must not read as \"no entitlements\"")
		})
	}
}

func TestLoadRegistrationCertificate_MissingFile(t *testing.T) {
	v := &Verifier{RegistrationCertificate: &RegistrationCertificate{
		FilePath: filepath.Join(t.TempDir(), "absent.jwt"),
	}}

	_, err := v.LoadRegistrationCertificate(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reading registration certificate")
}

func TestLoadRegistrationCertificate_FormatOverride(t *testing.T) {
	path := writeTemp(t, "wrprc.jwt",
		makeJWT(t, map[string]any{"typ": rpcert.WRPRCTyp}, map[string]any{"sub": "x"}))
	v := &Verifier{RegistrationCertificate: &RegistrationCertificate{
		FilePath: path,
		Format:   "ecosystem-profiled-identifier",
	}}

	loaded, err := v.LoadRegistrationCertificate(nil)
	require.NoError(t, err)
	assert.Equal(t, "ecosystem-profiled-identifier", loaded.Format)
}

// TestLoadRegistrationCertificate_FullValidation exercises the path that
// actually chains the WRPRC to a Registrar root, rather than only checking
// the document's shape.
func TestLoadRegistrationCertificate_FullValidation(t *testing.T) {
	ca := newRegistrarCA(t)
	const orgID = "VATSE-123456789"

	newVerifier := func(t *testing.T, jwt string) *Verifier {
		t.Helper()
		dir := t.TempDir()
		jwtPath := filepath.Join(dir, "wrprc.jwt")
		require.NoError(t, os.WriteFile(jwtPath, []byte(jwt), 0o600))
		rootPath := filepath.Join(dir, "roots.pem")
		require.NoError(t, os.WriteFile(rootPath, []byte(ca.rootPEM), 0o600))
		return &Verifier{RegistrationCertificate: &RegistrationCertificate{
			FilePath:         jwtPath,
			TrustedRootsPath: rootPath,
		}}
	}

	t.Run("validates and reports entitlements", func(t *testing.T) {
		v := newVerifier(t, ca.wrprc(t, orgID))

		loaded, err := v.LoadRegistrationCertificate(nil)
		require.NoError(t, err)
		require.NotNil(t, loaded.Entitlements,
			"a validated certificate must report what the Registrar attested")
		assert.Equal(t, orgID, loaded.Entitlements.Subject.ID)
	})

	t.Run("accepts a matching access certificate", func(t *testing.T) {
		v := newVerifier(t, ca.wrprc(t, orgID))

		_, err := v.LoadRegistrationCertificate(accessCertWithOrgID(t, orgID))
		require.NoError(t, err)
	})

	// ARF RPRC_16: a mismatched pair would let a wallet attribute one
	// organisation's entitlements to another.
	t.Run("rejects a mismatched access certificate", func(t *testing.T) {
		v := newVerifier(t, ca.wrprc(t, orgID))

		_, err := v.LoadRegistrationCertificate(accessCertWithOrgID(t, "VATSE-999999999"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not match the access certificate")
	})

	t.Run("rejects a certificate that does not chain to the configured roots", func(t *testing.T) {
		other := newRegistrarCA(t)
		v := newVerifier(t, other.wrprc(t, orgID))

		_, err := v.LoadRegistrationCertificate(nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed validation")
	})

	t.Run("rejects an unreadable roots bundle", func(t *testing.T) {
		dir := t.TempDir()
		jwtPath := filepath.Join(dir, "wrprc.jwt")
		require.NoError(t, os.WriteFile(jwtPath, []byte(ca.wrprc(t, orgID)), 0o600))
		notPEM := filepath.Join(dir, "roots.pem")
		require.NoError(t, os.WriteFile(notPEM, []byte("not a pem file"), 0o600))

		v := &Verifier{RegistrationCertificate: &RegistrationCertificate{
			FilePath:         jwtPath,
			TrustedRootsPath: notPEM,
		}}
		_, err := v.LoadRegistrationCertificate(nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no PEM certificates")
	})
}

// TestLoadedRegistrationCertificate_VerifierInfo pins the OpenID4VP shape
// that actually goes on the wire.
func TestLoadedRegistrationCertificate_VerifierInfo(t *testing.T) {
	t.Run("nil receiver yields nothing", func(t *testing.T) {
		var l *LoadedRegistrationCertificate
		assert.Nil(t, l.VerifierInfo(),
			"an unconfigured deployment must omit verifier_info entirely, not send an empty array")
	})

	t.Run("renders format and data", func(t *testing.T) {
		l := &LoadedRegistrationCertificate{JWT: "a.b.c", Format: rpcert.WRPRCTyp}

		info := l.VerifierInfo()
		require.Len(t, info, 1)
		assert.Equal(t, rpcert.WRPRCTyp, info[0].Format)
		assert.Equal(t, "a.b.c", info[0].Data)
		assert.Empty(t, info[0].CredentialIDS,
			"a registration certificate describes the RP, not one requested credential, so it applies to all")
	})
}
