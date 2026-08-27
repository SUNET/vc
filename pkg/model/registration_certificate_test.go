package model

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirosfoundation/go-trust/pkg/registry/rpcert"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// registrarCA stands in for a national Registrar: a self-signed root plus a
// leaf it issued, and the leaf's key so fixtures can be genuinely signed.
// Real signatures matter here - the loader verifies them, so a fixture with
// a placeholder signature would only ever exercise the failure path.
type registrarCA struct {
	rootPEM string
	leafDER []byte
	leafKey *ecdsa.PrivateKey
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

	return registrarCA{
		rootPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})),
		leafDER: leafDER,
		leafKey: leafKey,
	}
}

// sign produces a genuinely-signed compact JWT with this CA's leaf in x5c.
func (r registrarCA) sign(t *testing.T, typ string, payload map[string]any) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims(payload))
	tok.Header["typ"] = typ
	tok.Header["x5c"] = []string{base64.StdEncoding.EncodeToString(r.leafDER)}
	signed, err := tok.SignedString(r.leafKey)
	require.NoError(t, err)
	return signed
}

// validPayload is a conformant WRPRC payload asserting orgID.
func validPayload(orgID string) map[string]any {
	return map[string]any{
		"sub":          orgID,
		"sub_ln":       "Test RP",
		"name":         "Test RP",
		"country":      "SE",
		"entitlements": []string{rpcert.EntitlementServiceProvider},
		"credentials": []map[string]any{{
			"format": "dc+sd-jwt",
			"claim": []map[string]any{
				{"path": []string{"given_name"}},
				{"path": []string{"family_name"}},
			},
		}},
	}
}

// newVerifierWithCert writes a signed WRPRC plus optional roots and returns a
// configured Verifier.
func newVerifierWithCert(t *testing.T, jwtStr, rootPEM string) *Verifier {
	t.Helper()
	dir := t.TempDir()
	jwtPath := filepath.Join(dir, "wrprc.jwt")
	require.NoError(t, os.WriteFile(jwtPath, []byte(jwtStr), 0o600))
	cfg := &RegistrationCertificate{FilePath: jwtPath}
	if rootPEM != "" {
		rootPath := filepath.Join(dir, "roots.pem")
		require.NoError(t, os.WriteFile(rootPath, []byte(rootPEM), 0o600))
		cfg.TrustedRootsPath = rootPath
	}
	return &Verifier{RegistrationCertificate: cfg}
}

func TestLoadRegistrationCertificate_NotConfigured(t *testing.T) {
	t.Run("nil block", func(t *testing.T) {
		loaded, err := (&Verifier{}).LoadRegistrationCertificate(nil)
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

// TestLoadRegistrationCertificate_Rejects covers every way a configured
// certificate can be unusable, each failing for its own distinct reason.
func TestLoadRegistrationCertificate_Rejects(t *testing.T) {
	ca := newRegistrarCA(t)

	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{
			name:    "a PEM file pointed at by mistake",
			content: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
			wantErr: "not a compact JWT",
		},
		{
			name:    "the wrong media type",
			content: ca.sign(t, "JWT", validPayload("NTRSE-1")),
			wantErr: "unexpected JWT typ",
		},
		{
			name:    "an empty file",
			content: "   \n",
			wantErr: "is empty",
		},
		{
			name: "no entitlements",
			content: ca.sign(t, rpcert.WRPRCTyp, map[string]any{
				"sub": "NTRSE-1", "name": "Test RP",
			}),
			wantErr: "no entitlements",
		},
		{
			name: "no usable sub",
			content: ca.sign(t, rpcert.WRPRCTyp, map[string]any{
				"name": "Test RP", "entitlements": []string{rpcert.EntitlementServiceProvider},
			}),
			wantErr: "no usable sub",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := newVerifierWithCert(t, tt.content, "")
			_, err := v.LoadRegistrationCertificate(nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// TestLoadRegistrationCertificate_RejectsTamperedPayload is the reason
// signature verification belongs to us rather than to go-trust: an altered
// payload still carries a genuine Registrar chain, so chain evaluation alone
// would accept it.
func TestLoadRegistrationCertificate_RejectsTamperedPayload(t *testing.T) {
	ca := newRegistrarCA(t)
	original := ca.sign(t, rpcert.WRPRCTyp, validPayload("NTRSE-1"))

	// Swap the payload for one granting a far broader attribute set, leaving
	// the header and signature untouched.
	head, _, sig := splitJWT(t, original)
	tampered := map[string]any{
		"sub": "NTRSE-1", "sub_ln": "Test RP", "name": "Test RP",
		"entitlements": []string{rpcert.EntitlementServiceProvider},
		"credentials": []map[string]any{{
			"format": "dc+sd-jwt",
			"claim":  []map[string]any{{"path": []string{"personal_administrative_number"}}},
		}},
	}
	body, err := json.Marshal(tampered)
	require.NoError(t, err)
	forged := head + "." + base64.RawURLEncoding.EncodeToString(body) + "." + sig

	v := newVerifierWithCert(t, forged, ca.rootPEM)
	_, err = v.LoadRegistrationCertificate(nil)
	require.Error(t, err, "a payload altered after signing must be rejected")
	assert.Contains(t, err.Error(), "signature verification failed")
}

func splitJWT(t *testing.T, token string) (head, body, sig string) {
	t.Helper()
	var parts []string
	start := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	parts = append(parts, token[start:])
	require.Len(t, parts, 3)
	return parts[0], parts[1], parts[2]
}

func TestLoadRegistrationCertificate_SignedButNoRoots(t *testing.T) {
	ca := newRegistrarCA(t)
	v := newVerifierWithCert(t, ca.sign(t, rpcert.WRPRCTyp, validPayload("NTRSE-1")), "")

	loaded, err := v.LoadRegistrationCertificate(nil)
	require.NoError(t, err)
	assert.False(t, loaded.TrustEvaluated,
		"without roots the document is authentic but its issuer is unvouched")
	require.NotNil(t, loaded.Claims, "claims are extracted regardless of trust evaluation")
	assert.Equal(t, "NTRSE-1", loaded.Claims.SubjectID)
}

func TestLoadRegistrationCertificate_ChainEvaluation(t *testing.T) {
	ca := newRegistrarCA(t)

	t.Run("chains to a configured root", func(t *testing.T) {
		v := newVerifierWithCert(t, ca.sign(t, rpcert.WRPRCTyp, validPayload("NTRSE-1")), ca.rootPEM)
		loaded, err := v.LoadRegistrationCertificate(nil)
		require.NoError(t, err)
		assert.True(t, loaded.TrustEvaluated)
	})

	t.Run("rejects a different Registrar", func(t *testing.T) {
		other := newRegistrarCA(t)
		v := newVerifierWithCert(t, other.sign(t, rpcert.WRPRCTyp, validPayload("NTRSE-1")), ca.rootPEM)
		_, err := v.LoadRegistrationCertificate(nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not lead to a configured Registrar root")
	})

	t.Run("rejects an unreadable roots bundle", func(t *testing.T) {
		v := newVerifierWithCert(t, ca.sign(t, rpcert.WRPRCTyp, validPayload("NTRSE-1")), "not a pem file")
		_, err := v.LoadRegistrationCertificate(nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no PEM certificates")
	})
}

// TestLoadRegistrationCertificate_AccessCertificateBinding covers ARF
// RPRC_16 - the two documents must describe the same organisation.
func TestLoadRegistrationCertificate_AccessCertificateBinding(t *testing.T) {
	ca := newRegistrarCA(t)
	const orgID = "NTRSE-5560000000"
	jwtStr := ca.sign(t, rpcert.WRPRCTyp, validPayload(orgID))

	// The conformant path: EN 319 412-3 clause 4.2.1 puts the identifier in
	// organizationIdentifier (2.5.4.97). This is what a real Access CA
	// issues, and it only resolves from go-trust v0.20.0 onwards - before
	// that the binding refused to enforce itself on exactly these
	// certificates.
	t.Run("matching organisation, conformant certificate", func(t *testing.T) {
		v := newVerifierWithCert(t, jwtStr, ca.rootPEM)
		_, err := v.LoadRegistrationCertificate(accessCertWithOrgID(t, orgID))
		require.NoError(t, err)
	})

	// The fallback: earlier certificates put it in serialNumber (2.5.4.5).
	// Both must resolve, or upgrading go-trust would quietly stop enforcing
	// the binding for deployments still holding one of those.
	t.Run("matching organisation, legacy serialNumber certificate", func(t *testing.T) {
		v := newVerifierWithCert(t, jwtStr, ca.rootPEM)
		_, err := v.LoadRegistrationCertificate(accessCertWithLegacyOrgID(t, orgID))
		require.NoError(t, err)
	})

	// The binding compares two organisation identifiers, so with no access
	// certificate there is nothing to compare and it is skipped - even with
	// trusted roots configured. Pinned because a deployment can set
	// trusted_roots_path, see the chain evaluated, and reasonably assume
	// RPRC_16 is being enforced when it is not.
	t.Run("skipped entirely without an access certificate", func(t *testing.T) {
		v := newVerifierWithCert(t, jwtStr, ca.rootPEM)
		loaded, err := v.LoadRegistrationCertificate(nil)
		require.NoError(t, err)
		require.True(t, loaded.TrustEvaluated, "the chain is still evaluated")
	})

	t.Run("mismatch is caught on the legacy path too", func(t *testing.T) {
		v := newVerifierWithCert(t, jwtStr, ca.rootPEM)
		_, err := v.LoadRegistrationCertificate(accessCertWithLegacyOrgID(t, "NTRSE-9999999999"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not match the access certificate")
	})

	// go-trust's binding check returns nil when either identifier is empty -
	// correct for its WRPRC-only callers, but here an access certificate was
	// supplied and RPRC_16 is meant to be enforced. A certificate that simply
	// omits the field must not slip through looking checked.
	t.Run("access certificate without an organisation identifier", func(t *testing.T) {
		v := newVerifierWithCert(t, jwtStr, ca.rootPEM)
		_, err := v.LoadRegistrationCertificate(accessCertWithOrgID(t, ""))
		require.Error(t, err, "an unbindable access certificate must not pass silently")
		assert.Contains(t, err.Error(), "no organisation identifier")
	})

	t.Run("registration certificate without a sub identifier", func(t *testing.T) {
		// Legal name only: extraction accepts it, but there is no identifier
		// to bind against.
		noSubID := ca.sign(t, rpcert.WRPRCTyp, map[string]any{
			"sub_ln":       "Test RP",
			"name":         "Test RP",
			"entitlements": []string{rpcert.EntitlementServiceProvider},
		})
		v := newVerifierWithCert(t, noSubID, ca.rootPEM)
		_, err := v.LoadRegistrationCertificate(accessCertWithOrgID(t, orgID))
		require.Error(t, err, "a certificate with no sub identifier cannot be bound")
		assert.Contains(t, err.Error(), "no identifier")
	})

	t.Run("mismatched organisation", func(t *testing.T) {
		v := newVerifierWithCert(t, jwtStr, ca.rootPEM)
		_, err := v.LoadRegistrationCertificate(accessCertWithOrgID(t, "NTRSE-9999999999"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not match the access certificate")
	})
}

// oidOrganizationIdentifier is EN 319 412-3 clause 4.2.1's
// organizationIdentifier. Go's pkix.Name has no field for it, so a
// conformant certificate can only carry it through ExtraNames.
var oidOrganizationIdentifier = asn1.ObjectIdentifier{2, 5, 4, 97}

// accessCertWithOrgID mints a conformant access certificate, carrying the
// organisation identifier in organizationIdentifier (2.5.4.97).
//
// This is the primary extraction path. Minting only into serialNumber would
// exercise go-trust's fallback and leave the path real Registrars actually
// use untested - see accessCertWithLegacyOrgID.
func accessCertWithOrgID(t *testing.T, orgID string) *x509.Certificate {
	t.Helper()
	return mintAccessCert(t, pkix.Name{
		CommonName:   "verifier.example.com",
		Organization: []string{"Test RP"},
		ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: oidOrganizationIdentifier, Value: orgID},
		},
	})
}

// accessCertWithLegacyOrgID mints a certificate carrying the identifier in
// serialNumber (2.5.4.5) instead, which earlier certificates and fixtures
// used and go-trust still accepts as a fallback.
func accessCertWithLegacyOrgID(t *testing.T, orgID string) *x509.Certificate {
	t.Helper()
	return mintAccessCert(t, pkix.Name{
		CommonName:   "verifier.example.com",
		Organization: []string{"Test RP"},
		SerialNumber: orgID,
	})
}

func mintAccessCert(t *testing.T, subject pkix.Name) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func TestLoadRegistrationCertificate_FormatOverride(t *testing.T) {
	ca := newRegistrarCA(t)

	t.Run("defaults to the WRPRC media type", func(t *testing.T) {
		v := newVerifierWithCert(t, ca.sign(t, rpcert.WRPRCTyp, validPayload("NTRSE-1")), "")
		loaded, err := v.LoadRegistrationCertificate(nil)
		require.NoError(t, err)
		assert.Equal(t, rpcert.WRPRCTyp, loaded.Format)
	})

	t.Run("honours an ecosystem override", func(t *testing.T) {
		v := newVerifierWithCert(t, ca.sign(t, rpcert.WRPRCTyp, validPayload("NTRSE-1")), "")
		v.RegistrationCertificate.Format = "ecosystem-profiled-identifier"
		loaded, err := v.LoadRegistrationCertificate(nil)
		require.NoError(t, err)
		assert.Equal(t, "ecosystem-profiled-identifier", loaded.Format)
	})
}

// TestLoadRegistrationCertificate_SubClaimShapes pins that both subject
// encodings are accepted. Registrars differ, and the German sandbox uses the
// bare-string form.
func TestLoadRegistrationCertificate_SubClaimShapes(t *testing.T) {
	ca := newRegistrarCA(t)

	t.Run("bare identifier string with sub_ln", func(t *testing.T) {
		v := newVerifierWithCert(t, ca.sign(t, rpcert.WRPRCTyp, map[string]any{
			"sub": "NTRDE-BD7070256AF93987", "sub_ln": "Siros Foundation",
			"entitlements": []string{rpcert.EntitlementServiceProvider},
		}), "")
		loaded, err := v.LoadRegistrationCertificate(nil)
		require.NoError(t, err)
		assert.Equal(t, "NTRDE-BD7070256AF93987", loaded.Claims.SubjectID)
		assert.Equal(t, "Siros Foundation", loaded.Claims.LegalName)
	})

	t.Run("structured object", func(t *testing.T) {
		v := newVerifierWithCert(t, ca.sign(t, rpcert.WRPRCTyp, map[string]any{
			"sub":          map[string]any{"id": "NTRSE-1", "legal_name": "Structured RP"},
			"entitlements": []string{rpcert.EntitlementServiceProvider},
		}), "")
		loaded, err := v.LoadRegistrationCertificate(nil)
		require.NoError(t, err)
		assert.Equal(t, "NTRSE-1", loaded.Claims.SubjectID)
		assert.Equal(t, "Structured RP", loaded.Claims.LegalName)
	})
}

// TestLoadRegistrationCertificate_ClaimListSpellings guards the mismatch that
// would fail silently: reading only one spelling yields an empty allowed
// attribute set, which reads as "may request nothing" and would leave
// over-request detection inert instead of erroring.
func TestLoadRegistrationCertificate_ClaimListSpellings(t *testing.T) {
	ca := newRegistrarCA(t)

	for _, key := range []string{"claim", "claims"} {
		t.Run(key, func(t *testing.T) {
			v := newVerifierWithCert(t, ca.sign(t, rpcert.WRPRCTyp, map[string]any{
				"sub": "NTRSE-1", "entitlements": []string{rpcert.EntitlementServiceProvider},
				"credentials": []map[string]any{{
					"format": "dc+sd-jwt",
					key: []map[string]any{
						{"path": []string{"given_name"}},
						{"path": []string{"family_name"}},
					},
				}},
			}), "")
			loaded, err := v.LoadRegistrationCertificate(nil)
			require.NoError(t, err)
			assert.Equal(t, []string{"given_name", "family_name"}, loaded.Claims.AllowedAttributes,
				"a %q list must yield the attributes this RP may request", key)
		})
	}
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

// TestGermanSandboxRegistrationCertificate runs a real certificate issued by
// the German national wallet sandbox, which is the interop target. Synthetic
// fixtures only prove the code agrees with itself; this proves it agrees with
// what a Registrar actually emits.
func TestGermanSandboxRegistrationCertificate(t *testing.T) {
	// The wire-format assertions are the point of this fixture and must not
	// depend on the clock. Signature verification does not either - the JWT
	// carries no exp and verifyWRPRCSignature disables claim validation - so
	// only the chain evaluation below is time-bounded.
	t.Run("wire format", func(t *testing.T) {
		v := &Verifier{RegistrationCertificate: &RegistrationCertificate{
			FilePath: "testdata/german-sandbox-wrprc.jwt",
		}}

		loaded, err := v.LoadRegistrationCertificate(nil)
		require.NoError(t, err, "the German sandbox certificate must load")
		require.NotNil(t, loaded.Claims)

		c := loaded.Claims
		assert.Equal(t, "NTRDE-BD7070256AF93987", c.SubjectID, "sub arrives as a bare identifier string")
		assert.Equal(t, "Siros Foundation", c.LegalName, "legal name arrives in sub_ln, not inside sub")
		assert.Equal(t, "Siros Foundation", c.TradeName)
		assert.Equal(t, "DE", c.Country)
		assert.Equal(t, []string{rpcert.EntitlementServiceProvider}, c.EntitlementURIs)
		assert.Equal(t, []string{"birth_date", "family_name", "given_name"}, c.AllowedAttributes,
			"the DCQL list is spelled \"claim\" here; missing it would silently permit nothing")
		require.Len(t, c.Purpose, 1)
		assert.Equal(t, "Demo", c.Purpose[0].Value)
		assert.Equal(t, "https://siros.org/privacy-policy", c.PrivacyPolicyURI)

		info := loaded.VerifierInfo()
		require.Len(t, info, 1)
		assert.Equal(t, rpcert.WRPRCTyp, info[0].Format)
	})

	// Chain evaluation calls x509.Certificate.Verify against the current
	// time, so this half stops working when the sandbox material expires.
	// Skipped rather than left to fail as a mystery on some future morning -
	// and kept separate so the conformance assertions above keep running
	// when it does.
	t.Run("chain evaluation against the Registrar root", func(t *testing.T) {
		root := sandboxRegistrarRoot(t)
		if time.Now().After(root.NotAfter) {
			t.Skipf("sandbox Registrar root expired %s - refresh testdata/german-sandbox-*.{jwt,pem} from the sandbox to re-enable this check",
				root.NotAfter.Format("2006-01-02"))
		}

		v := &Verifier{RegistrationCertificate: &RegistrationCertificate{
			FilePath:         "testdata/german-sandbox-wrprc.jwt",
			TrustedRootsPath: "testdata/german-sandbox-registrar-root.pem",
		}}

		loaded, err := v.LoadRegistrationCertificate(nil)
		require.NoError(t, err)
		require.True(t, loaded.TrustEvaluated, "the chain must lead to the configured Registrar root")
	})
}

// sandboxRegistrarRoot parses the pinned Registrar root so its validity can
// be checked before relying on it.
func sandboxRegistrarRoot(t *testing.T) *x509.Certificate {
	t.Helper()
	pemBytes, err := os.ReadFile("testdata/german-sandbox-registrar-root.pem")
	require.NoError(t, err)
	block, _ := pem.Decode(pemBytes)
	require.NotNil(t, block, "sandbox Registrar root must be PEM")
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}
