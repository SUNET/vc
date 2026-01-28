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
	"slices"
	"testing"
	"time"
	"vc/pkg/pki"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
	"gotest.tools/v3/golden"
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
	tts := []struct {
		name string
		have map[string]*CredentialConstructor
	}{
		{
			name: "Valid Config",
			have: map[string]*CredentialConstructor{
				"pid": {
					VCT:          "urn:eudi:pid:1",
					VCTMFilePath: "./testdata/vctm_pid.json",
					AuthMethod:   "basic",
				},
				"pda1": {
					VCT:          "urn:eudi:pda1:1",
					VCTMFilePath: "./testdata/vctm_pda1.json",
					AuthMethod:   "pid_auth",
				},
				"ehic": {
					VCT:          "urn:eudi:ehic:1",
					VCTMFilePath: "./testdata/vctm_ehic.json",
					AuthMethod:   "pid_auth",
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.TODO()

			for scope, cc := range tt.have {
				err := cc.LoadVCTMetadata(ctx, scope)
				assert.NoError(t, err)

				t.Logf("Loaded VCTM for: %s (VCT: %s)", cc.VCT, scope)
			}
		})
	}
}

func TestCredentialConstructorFormatting(t *testing.T) {
	tts := []struct {
		name     string
		cfgPath  string
		loadVCTM []string
		want     map[string]*CredentialConstructor
	}{
		{
			name:     "Valid Config",
			cfgPath:  "cfg.yaml",
			loadVCTM: []string{"ehic"},
			want: map[string]*CredentialConstructor{
				"diploma": {
					VCT: "urn:eudi:diploma:1",
				},
				"elm": {
					VCT: "urn:eudi:elm:1",
				},
				"micro_credential": {
					VCT: "urn:eudi:micro_credential:1",
				},
				"pid": {
					VCT: "urn:eudi:pid:1",
				},
				"openbadge_basic": {
					VCT: "urn:eudi:openbadge_basic:1",
				},
				"openbadge_complete": {
					VCT: "urn:eudi:openbadge_complete:1",
				},
				"openbadge_endorsements": {
					VCT: "urn:eudi:openbadge_endorsements:1",
				},
				"pda1": {
					VCT: "urn:eudi:pda1:1",
				},
				"ehic": {
					VCT: "urn:eudi:ehic:1",
					Attributes: map[string]map[string][]string{
						"en-US": {
							"Social Security PIN":        {"personal_administrative_number"},
							"Issuing authority":          {"issuing_authority"},
							"Issuing authority id":       {"issuing_authority", "id"},
							"Issuing authority name":     {"issuing_authority", "name"},
							"Issuing country":            {"issuing_country"},
							"Expiry date":                {"date_of_expiry"},
							"Issue date":                 {"date_of_issuance"},
							"Competent institution":      {"authentic_source"},
							"Competent institution id":   {"authentic_source", "id"},
							"Competent institution name": {"authentic_source", "name"},
							"Ending date":                {"ending_date"},
							"Starting date":              {"starting_date"},
							"Document number":            {"document_number"},
						},
					},
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			cfgFile := golden.Get(t, tt.cfgPath)

			cfg := &Cfg{}
			err := yaml.Unmarshal(cfgFile, cfg)
			assert.NoError(t, err)

			for scope, cc := range cfg.CredentialConstructor {
				if slices.Contains(tt.loadVCTM, scope) {
					err := cc.LoadVCTMetadata(ctx, scope)
					assert.NoError(t, err)
					cc.Attributes = cc.VCTM.Attributes()
				}

				cc.VCTMFilePath = ""
				cc.AuthMethod = ""
				cc.VCTM = nil
			}

			assert.Equal(t, tt.want, cfg.CredentialConstructor)
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
				CredentialConstructor: map[string]*CredentialConstructor{
					"pid": {
						VCT:        "urn:eudi:pid:1",
						AuthMethod: "basic",
					},
				},
			},
			credentialType: "pid",
			want:           "basic",
		},
		{
			name: "Found by scope key - pid_auth",
			cfg: &Cfg{
				CredentialConstructor: map[string]*CredentialConstructor{
					"ehic": {
						VCT:        "urn:eudi:ehic:1",
						AuthMethod: "pid_auth",
					},
				},
			},
			credentialType: "ehic",
			want:           "pid_auth",
		},
		{
			name: "Not found - returns default basic",
			cfg: &Cfg{
				CredentialConstructor: map[string]*CredentialConstructor{
					"pid": {
						VCT:        "urn:eudi:pid:1",
						AuthMethod: "basic",
					},
				},
			},
			credentialType: "unknown",
			want:           "basic",
		},
		{
			name: "Empty config - returns default basic",
			cfg: &Cfg{
				CredentialConstructor: map[string]*CredentialConstructor{},
			},
			credentialType: "pid",
			want:           "basic",
		},
		{
			name: "Multiple constructors - finds correct one",
			cfg: &Cfg{
				CredentialConstructor: map[string]*CredentialConstructor{
					"pid": {
						VCT:        "urn:eudi:pid:1",
						AuthMethod: "basic",
					},
					"ehic": {
						VCT:        "urn:eudi:ehic:1",
						AuthMethod: "pid_auth",
					},
					"diploma": {
						VCT:        "urn:eudi:diploma:1",
						AuthMethod: "pid_auth",
					},
				},
			},
			credentialType: "ehic",
			want:           "pid_auth",
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
				CredentialConstructor: map[string]*CredentialConstructor{
					"pid": {
						VCT:          "urn:eudi:pid:1",
						AuthMethod:   "basic",
						VCTMFilePath: "/path/to/vctm_pid.json",
					},
				},
			},
			scope: "pid",
			want: &CredentialConstructor{
				VCT:          "urn:eudi:pid:1",
				AuthMethod:   "basic",
				VCTMFilePath: "/path/to/vctm_pid.json",
			},
		},
		{
			name: "Not found - returns nil",
			cfg: &Cfg{
				CredentialConstructor: map[string]*CredentialConstructor{
					"pid": {
						VCT:        "urn:eudi:pid:1",
						AuthMethod: "basic",
					},
				},
			},
			scope: "unknown",
			want:  nil,
		},
		{
			name: "Empty config - returns nil",
			cfg: &Cfg{
				CredentialConstructor: map[string]*CredentialConstructor{},
			},
			scope: "pid",
			want:  nil,
		},
		{
			name: "Multiple constructors - scope key lookup",
			cfg: &Cfg{
				CredentialConstructor: map[string]*CredentialConstructor{
					"pid": {
						VCT:          "urn:eudi:pid:1",
						AuthMethod:   "basic",
						VCTMFilePath: "/path/to/vctm_pid.json",
					},
					"ehic": {
						VCT:          "urn:eudi:ehic:1",
						AuthMethod:   "pid_auth",
						VCTMFilePath: "/path/to/vctm_ehic.json",
					},
				},
			},
			scope: "ehic",
			want: &CredentialConstructor{
				VCT:          "urn:eudi:ehic:1",
				AuthMethod:   "pid_auth",
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
			name: "Empty VCTMFilePath - error",
			constructor: &CredentialConstructor{
				VCTMFilePath: "",
			},
			wantErr:     true,
			errContains: "vctm_file_path is empty",
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
			name: "Invalid JSON - error",
			constructor: &CredentialConstructor{
				VCTMFilePath: "./testdata/cfg.yaml", // YAML file, not JSON
			},
			wantErr:     true,
			errContains: "invalid character",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			err := tt.constructor.LoadVCTMetadata(ctx, "test_scope")

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, tt.constructor.VCTM)
			}
		})
	}
}

func TestIssuerMetadataLoadAndSign(t *testing.T) {
	// Setup test PKI files
	rsaKeyPath, rsaCertPath, ecKeyPath, ecCertPath := setupTestPKI(t)

	tests := []struct {
		name        string
		metadata    IssuerMetadata
		wantErr     bool
		errContains string
	}{
		{
			name: "Valid runtime generation with RSA keys and chain",
			metadata: IssuerMetadata{
				KeyConfig: &pki.KeyConfig{
					PrivateKeyPath: rsaKeyPath,
					ChainPath:      rsaCertPath,
				},
			},
			wantErr: false,
		},
		{
			name: "Valid runtime generation with EC keys and chain",
			metadata: IssuerMetadata{
				KeyConfig: &pki.KeyConfig{
					PrivateKeyPath: ecKeyPath,
					ChainPath:      ecCertPath,
				},
			},
			wantErr: false,
		},
		{
			name: "Signing key file does not exist",
			metadata: IssuerMetadata{
				KeyConfig: &pki.KeyConfig{
					PrivateKeyPath: "./testdata/nonexistent.pem",
					ChainPath:      rsaCertPath,
				},
			},
			wantErr:     true,
			errContains: "no such file or directory",
		},
		{
			name: "Certificate chain file does not exist",
			metadata: IssuerMetadata{
				KeyConfig: &pki.KeyConfig{
					PrivateKeyPath: rsaKeyPath,
					ChainPath:      "./testdata/nonexistent.crt",
				},
			},
			wantErr:     true,
			errContains: "no such file or directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			metadata, privateKey, cert, chain, err := tt.metadata.LoadAndSign(ctx, "https://issuer.example.com", nil)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Nil(t, metadata)
				assert.Nil(t, privateKey)
				assert.Nil(t, cert)
				assert.Nil(t, chain)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, metadata)
				assert.NotNil(t, privateKey)
				assert.NotNil(t, cert)
				assert.NotEmpty(t, chain)
				assert.NotEmpty(t, metadata.SignedMetadata, "SignedMetadata should be populated with signed JWT")
			}
		})
	}
}

func TestOAuthServerLoadAndSign(t *testing.T) {
	// Setup test PKI files
	rsaKeyPath, rsaCertPath, ecKeyPath, ecCertPath := setupTestPKI(t)

	tests := []struct {
		name        string
		server      OAuthServer
		issuerURL   string
		wantErr     bool
		errContains string
	}{
		{
			name: "Runtime-generated metadata with RSA keys",
			server: OAuthServer{
				TokenEndpoint: "https://test.oauth.example.com/token",
				Metadata: OAuthMetadata{
					KeyConfig: &pki.KeyConfig{
						PrivateKeyPath: rsaKeyPath,
						ChainPath:      rsaCertPath,
					},
				},
			},
			issuerURL: "https://test.oauth.example.com",
			wantErr:   false,
		},
		{
			name: "Runtime-generated metadata with EC keys",
			server: OAuthServer{
				TokenEndpoint: "https://test.oauth.example.com/token",
				Metadata: OAuthMetadata{
					KeyConfig: &pki.KeyConfig{
						PrivateKeyPath: ecKeyPath,
						ChainPath:      ecCertPath,
					},
				},
			},
			issuerURL: "https://test.oauth.example.com",
			wantErr:   false,
		},
		{
			name: "Signing key file does not exist",
			server: OAuthServer{
				TokenEndpoint: "https://test.oauth.example.com/token",
				Metadata: OAuthMetadata{
					KeyConfig: &pki.KeyConfig{
						PrivateKeyPath: "./testdata/nonexistent.pem",
						ChainPath:      rsaCertPath,
					},
				},
			},
			issuerURL:   "https://test.oauth.example.com",
			wantErr:     true,
			errContains: "no such file or directory",
		},
		{
			name: "Certificate chain file does not exist",
			server: OAuthServer{
				TokenEndpoint: "https://test.oauth.example.com/token",
				Metadata: OAuthMetadata{
					KeyConfig: &pki.KeyConfig{
						PrivateKeyPath: rsaKeyPath,
						ChainPath:      "./testdata/nonexistent.crt",
					},
				},
			},
			issuerURL:   "https://test.oauth.example.com",
			wantErr:     true,
			errContains: "no such file or directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			metadata, privateKey, chain, err := tt.server.Metadata.LoadAndSign(ctx, tt.issuerURL, tt.server.TokenEndpoint)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				assert.Nil(t, metadata)
				assert.Nil(t, privateKey)
				assert.Nil(t, chain)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, metadata)
				assert.NotNil(t, privateKey)
				assert.NotEmpty(t, chain)
				assert.NotEmpty(t, metadata.SignedMetadata, "SignedMetadata should be populated after signing")
				// Verify metadata has expected fields
				assert.NotEmpty(t, metadata.Issuer)
				assert.Equal(t, tt.issuerURL, metadata.Issuer)
				assert.NotEmpty(t, metadata.AuthorizationEndpoint)
				assert.NotEmpty(t, metadata.TokenEndpoint)
			}
		})
	}
}
