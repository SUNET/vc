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
	rsaKeyFile, err := os.Create(rsaKeyPath)
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
	rsaCertFile, err := os.Create(rsaCertPath)
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
	ecKeyFile, err := os.Create(ecKeyPath)
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
	ecCertFile, err := os.Create(ecCertPath)
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

func TestCredentialConstructor(t *testing.T) {
	tests := []struct {
		name        string
		constructor *CredentialConstructor
		scope       string
		expectedVCT string
	}{
		{
			name: "Load PID VCTM",
			constructor: &CredentialConstructor{
				VCTMFilePath: "./testdata/vctm_pid.json",
				AuthMethod:   "basic",
			},
			scope:       "pid",
			expectedVCT: "urn:eudi:pid:1",
		},
		{
			name: "Load PDA1 VCTM",
			constructor: &CredentialConstructor{
				VCTMFilePath: "./testdata/vctm_pda1.json",
				AuthMethod:   "openid4vp",
			},
			scope:       "pda1",
			expectedVCT: "urn:eudi:pda1:1",
		},
		{
			name: "Load EHIC VCTM",
			constructor: &CredentialConstructor{
				VCTMFilePath: "./testdata/vctm_ehic.json",
				AuthMethod:   "openid4vp",
			},
			scope:       "ehic",
			expectedVCT: "urn:eudi:ehic:1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.TODO()

			err := tt.constructor.LoadVCTMetadata(ctx, tt.scope)
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

func TestGetCredentialConstructorAuthMethod(t *testing.T) {
	tests := []struct {
		name           string
		cfg            *Cfg
		credentialType string
		want           string
	}{
		{
			name: "Found by scope key - basic auth",
			cfg: &Cfg{
				Common: &Common{CredentialConstructor: map[string]*CredentialConstructor{
					"pid": {
						VCTM:       &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"},
						AuthMethod: "basic",
					},
				}},
			},
			credentialType: "pid",
			want:           "basic",
		},
		{
			name: "Found by scope key - openid4vp",
			cfg: &Cfg{
				Common: &Common{CredentialConstructor: map[string]*CredentialConstructor{
					"ehic": {
						VCTM:       &sdjwtvc.VCTM{VCT: "urn:eudi:ehic:1"},
						AuthMethod: "openid4vp",
					},
				}},
			},
			credentialType: "ehic",
			want:           "openid4vp",
		},
		{
			name: "Not found - returns default basic",
			cfg: &Cfg{
				Common: &Common{CredentialConstructor: map[string]*CredentialConstructor{
					"pid": {
						VCTM:       &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"},
						AuthMethod: "basic",
					},
				}},
			},
			credentialType: "unknown",
			want:           "basic",
		},
		{
			name: "Empty config - returns default basic",
			cfg: &Cfg{
				Common: &Common{CredentialConstructor: map[string]*CredentialConstructor{}},
			},
			credentialType: "pid",
			want:           "basic",
		},
		{
			name: "Multiple constructors - finds correct one",
			cfg: &Cfg{
				Common: &Common{CredentialConstructor: map[string]*CredentialConstructor{
					"pid": {
						VCTM:       &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"},
						AuthMethod: "basic",
					},
					"ehic": {
						VCTM:       &sdjwtvc.VCTM{VCT: "urn:eudi:ehic:1"},
						AuthMethod: "openid4vp",
					},
					"diploma": {
						VCTM:       &sdjwtvc.VCTM{VCT: "urn:eudi:diploma:1"},
						AuthMethod: "openid4vp",
					},
				}},
			},
			credentialType: "ehic",
			want:           "openid4vp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.GetCredentialConstructorAuthMethod(tt.credentialType)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetCredentialConstructor(t *testing.T) {
	tests := []struct {
		name  string
		cfg   *Cfg
		scope string
		want  *CredentialConstructor
	}{
		{
			name: "Found by scope key",
			cfg: &Cfg{
				Common: &Common{CredentialConstructor: map[string]*CredentialConstructor{
					"pid": {
						VCTM:         &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"},
						AuthMethod:   "basic",
						VCTMFilePath: "/path/to/vctm_pid.json",
					},
				}},
			},
			scope: "pid",
			want: &CredentialConstructor{
				VCTM:         &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"},
				AuthMethod:   "basic",
				VCTMFilePath: "/path/to/vctm_pid.json",
			},
		},
		{
			name: "Not found - returns nil",
			cfg: &Cfg{
				Common: &Common{CredentialConstructor: map[string]*CredentialConstructor{
					"pid": {
						VCTM:       &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"},
						AuthMethod: "basic",
					},
				}},
			},
			scope: "unknown",
			want:  nil,
		},
		{
			name: "Empty config - returns nil",
			cfg: &Cfg{
				Common: &Common{CredentialConstructor: map[string]*CredentialConstructor{}},
			},
			scope: "pid",
			want:  nil,
		},
		{
			name: "Multiple constructors - scope key lookup",
			cfg: &Cfg{
				Common: &Common{CredentialConstructor: map[string]*CredentialConstructor{
					"pid": {
						VCTM:         &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"},
						AuthMethod:   "basic",
						VCTMFilePath: "/path/to/vctm_pid.json",
					},
					"ehic": {
						VCTM:         &sdjwtvc.VCTM{VCT: "urn:eudi:ehic:1"},
						AuthMethod:   "openid4vp",
						VCTMFilePath: "/path/to/vctm_ehic.json",
					},
				}},
			},
			scope: "ehic",
			want: &CredentialConstructor{
				VCTM:         &sdjwtvc.VCTM{VCT: "urn:eudi:ehic:1"},
				AuthMethod:   "openid4vp",
				VCTMFilePath: "/path/to/vctm_ehic.json",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.GetCredentialConstructor(tt.scope)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestLoadFile(t *testing.T) {
	tests := []struct {
		name        string
		constructor *CredentialConstructor
		wantErr     bool
		errContains string
	}{
		{
			name: "Valid file - success",
			constructor: &CredentialConstructor{
				VCTMFilePath: "./testdata/vctm_pid.json",
			},
			wantErr: false,
		},
		{
			name: "File does not exist - error",
			constructor: &CredentialConstructor{
				VCTMFilePath: "./testdata/nonexistent.json",
			},
			wantErr:     true,
			errContains: "failed to read VCTM file",
		},
		{
			name: "Not JSON - error",
			constructor: &CredentialConstructor{
				VCTMFilePath: "./testdata/vctm_not_json.yaml",
			},
			wantErr:     true,
			errContains: "failed to unmarshal VCTM",
		},
		{
			name: "Missing vct field - ok",
			constructor: &CredentialConstructor{
				VCTMFilePath: "./testdata/vctm_missing_vct.json",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			err := tt.constructor.LoadVCTMetadata(ctx, "test_scope")

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

func TestCredentialConstructor_MissingVCTURL(t *testing.T) {
	cfg := &Cfg{
		Common: &Common{
			CredentialConstructor: map[string]*CredentialConstructor{
				"test_scope": {
					// Neither VCTMFilePath nor VCTMUrl set,
					// so VCTURL will remain empty after resolution.
					Format:     "dc+sd-jwt",
					AuthMethod: "basic",
					VCTM:       &sdjwtvc.VCTM{},
				},
			},
		},
	}
	err := cfg.ResolveVCTUrls("http://localhost:8080")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "VCTURL is empty")
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
			server: OAuthServer{
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
