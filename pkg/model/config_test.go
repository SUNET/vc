package model

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestPKI creates temporary key and certificate files for testing
// Returns paths for RSA key/cert and EC key/cert
func setupTestPKI(t *testing.T) (rsaKeyPath, rsaCertPath, ecKeyPath, ecCertPath string) {
	t.Helper()

	tmpDir := t.TempDir()

	// Generate RSA private key
	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	// Write RSA private key to file in PKCS8 format
	rsaKeyPath = filepath.Join(tmpDir, "test_rsa_key.pem")
	rsaKeyFile, err := os.Create(rsaKeyPath) // #nosec G304
	assert.NoError(t, err)
	defer rsaKeyFile.Close()

	// Marshal RSA key to PKCS8 format
	rsaPrivateKeyPKCS8, err := x509.MarshalPKCS8PrivateKey(rsaPrivateKey)
	assert.NoError(t, err)

	rsaPrivateKeyPEM := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: rsaPrivateKeyPKCS8,
	}
	err = pem.Encode(rsaKeyFile, rsaPrivateKeyPEM)
	assert.NoError(t, err)

	// Generate RSA self-signed certificate
	rsaTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "test-rsa.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	rsaCertDER, err := x509.CreateCertificate(rand.Reader, &rsaTemplate, &rsaTemplate, &rsaPrivateKey.PublicKey, rsaPrivateKey)
	assert.NoError(t, err)

	// Write RSA certificate to file
	rsaCertPath = filepath.Join(tmpDir, "test_rsa_cert.pem")
	rsaCertFile, err := os.Create(rsaCertPath) // #nosec G304
	assert.NoError(t, err)
	defer rsaCertFile.Close()

	rsaCertPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: rsaCertDER,
	}
	err = pem.Encode(rsaCertFile, rsaCertPEM)
	assert.NoError(t, err)

	// Generate EC (P-256) private key
	ecPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	// Write EC private key to file in PKCS8 format
	ecKeyPath = filepath.Join(tmpDir, "test_ec_key.pem")
	ecKeyFile, err := os.Create(ecKeyPath) // #nosec G304
	assert.NoError(t, err)
	defer ecKeyFile.Close()

	// Marshal EC key to PKCS8 format
	ecPrivateKeyPKCS8, err := x509.MarshalPKCS8PrivateKey(ecPrivateKey)
	assert.NoError(t, err)

	ecPrivateKeyPEM := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: ecPrivateKeyPKCS8,
	}
	err = pem.Encode(ecKeyFile, ecPrivateKeyPEM)
	assert.NoError(t, err)

	// Generate EC self-signed certificate
	ecTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "test-ec.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	ecCertDER, err := x509.CreateCertificate(rand.Reader, &ecTemplate, &ecTemplate, &ecPrivateKey.PublicKey, ecPrivateKey)
	assert.NoError(t, err)

	// Write EC certificate to file
	ecCertPath = filepath.Join(tmpDir, "test_ec_cert.pem")
	ecCertFile, err := os.Create(ecCertPath) // #nosec G304
	assert.NoError(t, err)
	defer ecCertFile.Close()

	ecCertPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ecCertDER,
	}
	err = pem.Encode(ecCertFile, ecCertPEM)
	assert.NoError(t, err)

	return rsaKeyPath, rsaCertPath, ecKeyPath, ecCertPath
}

func TestCredentialMetadata(t *testing.T) {
	tests := []struct {
		name        string
		constructor *CredentialMetadata
		scope       string
		expectedVCT string
	}{
		{
			name: "Load PID VCTM",
			constructor: &CredentialMetadata{
				VCTMFilePath: "./testdata/vctm_pid.json",
			},
			scope:       "pid",
			expectedVCT: "urn:eudi:pid:1",
		},
		{
			name: "Load PDA1 VCTM",
			constructor: &CredentialMetadata{
				VCTMFilePath: "./testdata/vctm_pda1.json",
			},
			scope:       "pda1",
			expectedVCT: "urn:eudi:pda1:1",
		},
		{
			name: "Load EHIC VCTM",
			constructor: &CredentialMetadata{
				VCTMFilePath: "./testdata/vctm_ehic.json",
			},
			scope:       "ehic",
			expectedVCT: "urn:eudi:ehic:1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.TODO()

			err := tt.constructor.LoadCredentialSchema(ctx, tt.scope)
			assert.NoError(t, err)

			// Verify VCTM was loaded
			assert.NotNil(t, tt.constructor.VCTM, "VCTM should be loaded")

			// Verify VCT matches expected value
			assert.Equal(t, tt.expectedVCT, tt.constructor.VCTM.VCT, "VCTM.VCT should match expected value")

			// Verify integrity hash was computed
			assert.NotEmpty(t, tt.constructor.Integrity, "Integrity hash should be computed")
			assert.Contains(t, tt.constructor.Integrity, "sha256-", "Integrity should be SRI format")

			// Verify raw bytes are kept for local files
			assert.NotNil(t, tt.constructor.VCTMRaw, "VCTMRaw should be kept for local files")
		})
	}
}

func TestCredentialMetadata_MDDL(t *testing.T) {
	mddlBytes, err := os.ReadFile("./testdata/mddl_pid.json")
	require.NoError(t, err)

	t.Run("local file keeps MDDLRaw", func(t *testing.T) {
		c := &CredentialMetadata{
			Format:       "mso_mdoc",
			MDDLFilePath: "./testdata/mddl_pid.json",
		}
		err := c.LoadCredentialSchema(context.TODO(), "pid_mdoc")
		require.NoError(t, err)
		assert.NotNil(t, c.MDDL, "MDDL schema should be loaded")
		assert.Equal(t, "eu.europa.ec.eudi.pid.1", c.MDDL.DocType)
		assert.Contains(t, c.Integrity, "sha256-")
		// APIGW always sends MDDLRaw inline to the issuer, which validates it
		// as required regardless of whether the schema came from a local
		// file or a URL — so it must be populated here too.
		assert.NotEmpty(t, c.GetMDDLRaw(), "MDDLRaw should be kept for local MDDL schemas")
	})

	t.Run("remote URL also keeps MDDLRaw", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(mddlBytes)
		}))
		defer srv.Close()

		c := &CredentialMetadata{
			Format:  "mso_mdoc",
			MDDLUrl: srv.URL,
		}
		err := c.LoadCredentialSchema(context.TODO(), "pid_mdoc")
		require.NoError(t, err)
		assert.NotNil(t, c.MDDL, "MDDL schema should be loaded")
		// This is the regression this test guards against: previously
		// MDDLRaw was only kept when IsLocalMDDL() was true, so an
		// mddl_url-configured scope would silently fail issuance because
		// the (required) inline MDDL bytes sent to the issuer were empty.
		assert.NotEmpty(t, c.GetMDDLRaw(), "MDDLRaw should also be kept for mddl_url-loaded schemas")
		assert.False(t, c.IsLocalMDDL())
	})
}

func TestLookupCredentialSources(t *testing.T) {
	cfg := &Cfg{
		APIGW: &APIGW{
			DataSources: DataSources{
				Datastore: DatastoreConfig{Scopes: map[string]DatastoreScope{
					"pid": {
						AuthProvider: "openid4vp",
						AuthScopes: map[string]AuthScopeEntry{
							"pid_source": {AuthClaims: []string{"given_name"}},
						},
					},
					"ehic": {
						AuthProvider: "openid4vp",
						AuthScopes: map[string]AuthScopeEntry{
							"pid": {AuthClaims: []string{"given_name"}},
						},
					},
				}},
				Assertion: AssertionConfig{Scopes: map[string]AssertionScope{
					"pid_saml": {AuthProvider: "saml"},
				}},
				ExternalAPI: ExternalAPIConfig{Scopes: map[string]ExternalAPIScope{
					"diploma": {Remote: "ladok", AuthProvider: "saml"},
				}},
			},
		},
	}

	t.Run("datastore", func(t *testing.T) {
		srcs, err := cfg.LookupCredentialSources("pid")
		assert.NoError(t, err)
		assert.Equal(t, DataSourceDatastore, srcs[0].DataSource)
		assert.Equal(t, "openid4vp", srcs[0].AuthProvider)
	})

	t.Run("assertion", func(t *testing.T) {
		srcs, err := cfg.LookupCredentialSources("pid_saml")
		assert.NoError(t, err)
		assert.Equal(t, DataSourceAssertion, srcs[0].DataSource)
		assert.Equal(t, "saml", srcs[0].AuthProvider)
	})

	t.Run("external_api", func(t *testing.T) {
		srcs, err := cfg.LookupCredentialSources("diploma")
		assert.NoError(t, err)
		assert.Equal(t, DataSourceExternalAPI, srcs[0].DataSource)
		assert.Equal(t, "ladok", srcs[0].RemoteName)
	})

	t.Run("not found", func(t *testing.T) {
		_, err := cfg.LookupCredentialSources("unknown")
		assert.Error(t, err)
	})

	t.Run("nil apigw", func(t *testing.T) {
		_, err := (&Cfg{}).LookupCredentialSources("pid")
		assert.Error(t, err)
	})
}

func TestResolveDataSource(t *testing.T) {
	ds := &DataSources{
		Datastore: DatastoreConfig{Scopes: map[string]DatastoreScope{
			"pid": {AuthProvider: AuthProviderOpenID4VP},
		}},
		Assertion: AssertionConfig{Scopes: map[string]AssertionScope{
			"pid":     {AuthProvider: AuthProviderSAML},
			"diploma": {AuthProvider: AuthProviderSAML},
		}},
		ExternalAPI: ExternalAPIConfig{Scopes: map[string]ExternalAPIScope{
			"diploma": {Remote: "ladok", AuthProvider: AuthProviderOIDC},
		}},
	}

	tests := []struct {
		name           string
		credentialType string
		authProvider   string
		wantSource     DataSourceType
		wantRemote     string
		wantErr        bool
	}{
		{
			name:           "pid with openid4vp -> datastore",
			credentialType: "pid",
			authProvider:   AuthProviderOpenID4VP,
			wantSource:     DataSourceDatastore,
		},
		{
			name:           "pid with saml -> assertion",
			credentialType: "pid",
			authProvider:   AuthProviderSAML,
			wantSource:     DataSourceAssertion,
		},
		{
			name:           "diploma with saml -> assertion",
			credentialType: "diploma",
			authProvider:   AuthProviderSAML,
			wantSource:     DataSourceAssertion,
		},
		{
			name:           "diploma with oidc -> external_api with remote",
			credentialType: "diploma",
			authProvider:   AuthProviderOIDC,
			wantSource:     DataSourceExternalAPI,
			wantRemote:     "ladok",
		},
		{
			name:           "unknown credential -> error",
			credentialType: "unknown",
			authProvider:   AuthProviderOpenID4VP,
			wantErr:        true,
		},
		{
			name:           "no matching auth provider -> error",
			credentialType: "pid",
			authProvider:   "nonexistent",
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src, err := ds.ResolveDataSource(tt.credentialType, tt.authProvider)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantSource, src.DataSource)
			if tt.wantRemote != "" {
				assert.Equal(t, tt.wantRemote, src.RemoteName)
			}
		})
	}
}

func TestGetCredentialMetadata(t *testing.T) {
	tests := []struct {
		name  string
		cfg   *Cfg
		scope string
		want  *CredentialMetadata
	}{
		{
			name: "Found by scope key",
			cfg: &Cfg{
				Common: &Common{CredentialMetadata: map[string]*CredentialMetadata{
					"pid": {
						VCTM:         &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"},
						VCTMFilePath: "/path/to/vctm_pid.json",
					},
				}},
			},
			scope: "pid",
			want: &CredentialMetadata{
				VCTM:         &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"},
				VCTMFilePath: "/path/to/vctm_pid.json",
			},
		},
		{
			name: "Not found - returns nil",
			cfg: &Cfg{
				Common: &Common{CredentialMetadata: map[string]*CredentialMetadata{
					"pid": {
						VCTM: &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"},
					},
				}},
			},
			scope: "unknown",
			want:  nil,
		},
		{
			name: "Empty config - returns nil",
			cfg: &Cfg{
				Common: &Common{CredentialMetadata: map[string]*CredentialMetadata{}},
			},
			scope: "pid",
			want:  nil,
		},
		{
			name: "Multiple constructors - scope key lookup",
			cfg: &Cfg{
				Common: &Common{CredentialMetadata: map[string]*CredentialMetadata{
					"pid": {
						VCTM:         &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"},
						VCTMFilePath: "/path/to/vctm_pid.json",
					},
					"ehic": {
						VCTM:         &sdjwtvc.VCTM{VCT: "urn:eudi:ehic:1"},
						VCTMFilePath: "/path/to/vctm_ehic.json",
					},
				}},
			},
			scope: "ehic",
			want: &CredentialMetadata{
				VCTM:         &sdjwtvc.VCTM{VCT: "urn:eudi:ehic:1"},
				VCTMFilePath: "/path/to/vctm_ehic.json",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.GetCredentialMetadata(tt.scope)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestLoadFile(t *testing.T) {
	tests := []struct {
		name        string
		constructor *CredentialMetadata
		wantErr     bool
		errContains string
	}{
		{
			name: "Valid file - success",
			constructor: &CredentialMetadata{
				VCTMFilePath: "./testdata/vctm_pid.json",
			},
			wantErr: false,
		},
		{
			name: "File does not exist - error",
			constructor: &CredentialMetadata{
				VCTMFilePath: "./testdata/nonexistent.json",
			},
			wantErr:     true,
			errContains: "failed to read VCTM file",
		},
		{
			name: "Not JSON - error",
			constructor: &CredentialMetadata{
				VCTMFilePath: "./testdata/vctm_not_json.yaml",
			},
			wantErr:     true,
			errContains: "failed to unmarshal VCTM",
		},
		{
			name: "Missing vct field - ok",
			constructor: &CredentialMetadata{
				VCTMFilePath: "./testdata/vctm_missing_vct.json",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			err := tt.constructor.LoadCredentialSchema(ctx, "test_scope")

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, tt.constructor.VCTM)
				assert.NotEmpty(t, tt.constructor.Integrity)
			}
		})
	}
}

func TestCredentialMetadata_MissingVCTURL(t *testing.T) {
	cfg := &Cfg{
		Common: &Common{
			CredentialMetadata: map[string]*CredentialMetadata{
				"test_scope": {
					// Neither VCTMFilePath nor VCTMUrl set,
					// so VCTURL will remain empty after resolution.
					Format: "dc+sd-jwt",
					VCTM:   &sdjwtvc.VCTM{},
				},
			},
		},
	}
	err := cfg.ResolveVCTUrls("http://localhost:8080")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "VCTURL is empty")
}

func TestResolveVCTUrls_AutoPopulatesVCT(t *testing.T) {
	// When a local VCTM file has no "vct" field, ResolveVCTUrls should
	// auto-populate VCTM.VCT from the serving URL and update VCTMRaw.
	rawBytes := []byte(`{"name":"test","claims":[]}`)
	cfg := &Cfg{
		Common: &Common{
			CredentialMetadata: map[string]*CredentialMetadata{
				"ehic": {
					VCTMFilePath: "/dummy/vctm_ehic.json",
					Format:       "dc+sd-jwt",
					VCTM:         &sdjwtvc.VCTM{Name: "test"},
					VCTMRaw:      rawBytes,
				},
			},
		},
	}

	err := cfg.ResolveVCTUrls("https://apigw.example.com")
	require.NoError(t, err)

	meta := cfg.Common.CredentialMetadata["ehic"]
	assert.Equal(t, "https://apigw.example.com/type-metadata/ehic", meta.VCTM.VCT,
		"VCT should be auto-populated from the serving URL")
	assert.Equal(t, "https://apigw.example.com/type-metadata/ehic", meta.VCTURL)
	assert.Contains(t, string(meta.VCTMRaw), `"vct"`,
		"VCTMRaw should contain the injected vct field")
}

func TestResolveVCTUrls_PreservesExplicitVCT(t *testing.T) {
	// When a VCTM file already has a "vct" field, ResolveVCTUrls should
	// not overwrite it.
	cfg := &Cfg{
		Common: &Common{
			CredentialMetadata: map[string]*CredentialMetadata{
				"pid": {
					VCTMFilePath: "/dummy/vctm_pid.json",
					Format:       "dc+sd-jwt",
					VCTM:         &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"},
					VCTMRaw:      []byte(`{"vct":"urn:eudi:pid:1","name":"PID"}`),
				},
			},
		},
	}

	err := cfg.ResolveVCTUrls("https://apigw.example.com")
	require.NoError(t, err)

	meta := cfg.Common.CredentialMetadata["pid"]
	assert.Equal(t, "urn:eudi:pid:1", meta.VCTM.VCT,
		"Explicit VCT from file should be preserved")
	assert.Equal(t, "https://apigw.example.com/type-metadata/pid", meta.VCTURL)
}

func TestIssuerMetadataLoadAndSign(t *testing.T) {
	tests := []struct {
		name     string
		metadata IssuerMetadata
	}{
		{
			name:     "Valid runtime generation",
			metadata: IssuerMetadata{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			metadata, err := tt.metadata.Generate(ctx, "https://issuer.example.com", nil)
			require.NoError(t, err)
			assert.NotNil(t, metadata)
		})
	}
}

func TestOAuthServerLoadAndSignMetadata(t *testing.T) {
	tests := []struct {
		name      string
		server    OAuthServer
		issuerURL string
	}{
		{
			name: "Runtime-generated metadata",
			server: OAuthServer{ // #nosec G101
				TokenEndpoint: "https://test.oauth.example.com/token",
			},
			issuerURL: "https://test.oauth.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			metadata := tt.server.GenerateMetadata(ctx, tt.issuerURL)

			assert.NotNil(t, metadata)
			assert.Empty(t, metadata.SignedMetadata, "SignedMetadata should be empty before signing")
			// Verify metadata has expected fields
			assert.NotEmpty(t, metadata.Issuer)
			assert.Equal(t, tt.issuerURL, metadata.Issuer)
			assert.NotEmpty(t, metadata.AuthorizationEndpoint)
			assert.NotEmpty(t, metadata.TokenEndpoint)
		})
	}
}
