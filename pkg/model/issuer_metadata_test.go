package model

import (
	"context"
	"testing"
	"vc/pkg/openid4vci"
	"vc/pkg/pki"
	"vc/pkg/sdjwtvc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIssuerMetadataLoadAndSign_CustomFormat(t *testing.T) {
	_, _, ecKeyPath, ecCertPath := setupTestPKI(t)

	cfg := &IssuerMetadata{
		KeyConfig: pki.KeyConfig{PrivateKeyPath: ecKeyPath, ChainPath: ecCertPath},
		
	}

	credentialConstructors := map[string]*CredentialConstructor{
		"test_cred": {
			VCT:        "urn:test:1",
			Format:     "dc+sd-jwt", // Custom format
			AuthMethod: "basic",
		},
	}

	ctx := context.Background()
	metadata, _, _, _, err := cfg.LoadAndSign(ctx, "https://issuer.example.com", credentialConstructors)

	require.NoError(t, err)
	require.NotNil(t, metadata)
	assert.Equal(t, "https://issuer.example.com", metadata.CredentialIssuer)

	credConfig, exists := metadata.CredentialConfigurationsSupported["test_cred"]
	require.True(t, exists)
	assert.Equal(t, "dc+sd-jwt", credConfig.Format)
	assert.Equal(t, "urn:test:1", credConfig.VCT)
}

func TestIssuerMetadataLoadAndSign_CustomDisplay(t *testing.T) {
	_, _, ecKeyPath, ecCertPath := setupTestPKI(t)

	cfg := &IssuerMetadata{
		KeyConfig: pki.KeyConfig{PrivateKeyPath: ecKeyPath, ChainPath: ecCertPath},
		
	}

	// Test that display must come from VCTM, not from constructor
	credentialConstructors := map[string]*CredentialConstructor{
		"test_cred": {
			VCT:        "urn:test:1",
			Format:     "vc+sd-jwt",
			AuthMethod: "basic",
			// Display comes from VCTM, not from constructor
		},
	}

	ctx := context.Background()
	metadata, _, _, _, err := cfg.LoadAndSign(ctx, "https://issuer.example.com", credentialConstructors)

	require.NoError(t, err)
	require.NotNil(t, metadata)

	credConfig, exists := metadata.CredentialConfigurationsSupported["test_cred"]
	require.True(t, exists)
	// Without VCTM loaded, there's no display
	require.Len(t, credConfig.Display, 0)
}

func TestIssuerMetadataLoadAndSign_VCTMDisplay(t *testing.T) {
	_, _, ecKeyPath, ecCertPath := setupTestPKI(t)

	cfg := &IssuerMetadata{
		KeyConfig: pki.KeyConfig{PrivateKeyPath: ecKeyPath, ChainPath: ecCertPath},
		
	}

	// Mock VCTM with display
	mockVCTM := &sdjwtvc.VCTM{
		VCT:         "urn:test:1",
		Name:        "Test VCTM",
		Description: "Test Description",
		Display: []sdjwtvc.VCTMDisplay{
			{
				Lang:        "en-US",
				Name:        "VCTM Display Name",
				Description: "VCTM Description",
			},
		},
	}

	credentialConstructors := map[string]*CredentialConstructor{
		"test_cred": {
			VCT:        "urn:test:1",
			AuthMethod: "basic",
			VCTM:       mockVCTM,
		},
	}

	ctx := context.Background()
	metadata, _, _, _, err := cfg.LoadAndSign(ctx, "https://issuer.example.com", credentialConstructors)

	require.NoError(t, err)
	require.NotNil(t, metadata)

	credConfig, exists := metadata.CredentialConfigurationsSupported["test_cred"]
	require.True(t, exists)
	require.Len(t, credConfig.Display, 1)

	assert.Equal(t, "VCTM Display Name", credConfig.Display[0].Name)
	assert.Equal(t, "en-US", credConfig.Display[0].Locale)
	assert.Equal(t, "VCTM Description", credConfig.Display[0].Description)
}

func TestIssuerMetadataLoadAndSign_CustomCryptoBindingMethods(t *testing.T) {
	_, _, ecKeyPath, ecCertPath := setupTestPKI(t)

	cfg := &IssuerMetadata{
		KeyConfig: pki.KeyConfig{PrivateKeyPath:                     ecKeyPath, ChainPath: ecCertPath},
		
		CryptographicBindingMethodsSupported: []string{"jwk", "did:key"},
	}

	credentialConstructors := map[string]*CredentialConstructor{
		"test_cred": {
			VCT:        "urn:test:1",
			AuthMethod: "basic",
		},
	}

	ctx := context.Background()
	metadata, _, _, _, err := cfg.LoadAndSign(ctx, "https://issuer.example.com", credentialConstructors)

	require.NoError(t, err)

	credConfig := metadata.CredentialConfigurationsSupported["test_cred"]
	assert.Equal(t, []string{"jwk", "did:key"}, credConfig.CryptographicBindingMethodsSupported)
}

func TestIssuerMetadataLoadAndSign_CustomSigningAlgorithms(t *testing.T) {
	_, _, ecKeyPath, ecCertPath := setupTestPKI(t)

	cfg := &IssuerMetadata{
		KeyConfig: pki.KeyConfig{PrivateKeyPath:                    ecKeyPath, ChainPath: ecCertPath},
		
		CredentialSigningAlgValuesSupported: []string{"ES256", "ES512"},
	}

	credentialConstructors := map[string]*CredentialConstructor{
		"test_cred": {
			VCT:        "urn:test:1",
			AuthMethod: "basic",
		},
	}

	ctx := context.Background()
	metadata, _, _, _, err := cfg.LoadAndSign(ctx, "https://issuer.example.com", credentialConstructors)

	require.NoError(t, err)

	credConfig := metadata.CredentialConfigurationsSupported["test_cred"]
	require.Len(t, credConfig.CredentialSigningAlgValuesSupported, 2)
	assert.Equal(t, "ES256", credConfig.CredentialSigningAlgValuesSupported[0])
	assert.Equal(t, "ES512", credConfig.CredentialSigningAlgValuesSupported[1])
}

func TestIssuerMetadataLoadAndSign_CustomProofAlgorithms(t *testing.T) {
	_, _, ecKeyPath, ecCertPath := setupTestPKI(t)

	cfg := &IssuerMetadata{
		KeyConfig: pki.KeyConfig{PrivateKeyPath:               ecKeyPath, ChainPath: ecCertPath},
		
		ProofSigningAlgValuesSupported: []string{"ES256", "RS256"},
	}

	credentialConstructors := map[string]*CredentialConstructor{
		"test_cred": {
			VCT:        "urn:test:1",
			AuthMethod: "basic",
		},
	}

	ctx := context.Background()
	metadata, _, _, _, err := cfg.LoadAndSign(ctx, "https://issuer.example.com", credentialConstructors)

	require.NoError(t, err)

	credConfig := metadata.CredentialConfigurationsSupported["test_cred"]
	jwtProof := credConfig.ProofTypesSupported["jwt"]
	assert.Equal(t, []string{"ES256", "RS256"}, jwtProof.ProofSigningAlgValuesSupported)
}

func TestIssuerMetadataLoadAndSign_OptionalEndpoints(t *testing.T) {
	_, _, ecKeyPath, ecCertPath := setupTestPKI(t)

	cfg := &IssuerMetadata{
		KeyConfig: pki.KeyConfig{PrivateKeyPath:           ecKeyPath, ChainPath: ecCertPath},
		
		AuthorizationServers:       []string{"https://oauth.example.com"},
		DeferredCredentialEndpoint: "https://issuer.example.com/deferred",
		NotificationEndpoint:       "https://issuer.example.com/notification",
	}

	credentialConstructors := map[string]*CredentialConstructor{
		"test_cred": {
			VCT:        "urn:test:1",
			AuthMethod: "basic",
		},
	}

	ctx := context.Background()
	metadata, _, _, _, err := cfg.LoadAndSign(ctx, "https://issuer.example.com", credentialConstructors)

	require.NoError(t, err)
	assert.Equal(t, []string{"https://oauth.example.com"}, metadata.AuthorizationServers)
	assert.Equal(t, "https://issuer.example.com/deferred", metadata.DeferredCredentialEndpoint)
	assert.Equal(t, "https://issuer.example.com/notification", metadata.NotificationEndpoint)
}

func TestIssuerMetadataLoadAndSign_CredentialResponseEncryption(t *testing.T) {
	_, _, ecKeyPath, ecCertPath := setupTestPKI(t)

	cfg := &IssuerMetadata{
		KeyConfig: pki.KeyConfig{PrivateKeyPath: ecKeyPath, ChainPath: ecCertPath},
		
		CredentialResponseEncryption: &openid4vci.MetadataCredentialResponseEncryption{
			AlgValuesSupported: []string{"ECDH-ES", "ECDH-ES+A128KW"},
			EncValuesSupported: []string{"A256GCM", "A128GCM"},
			EncryptionRequired: true,
		},
	}

	credentialConstructors := map[string]*CredentialConstructor{
		"test_cred": {
			VCT:        "urn:test:1",
			AuthMethod: "basic",
		},
	}

	ctx := context.Background()
	metadata, _, _, _, err := cfg.LoadAndSign(ctx, "https://issuer.example.com", credentialConstructors)

	require.NoError(t, err)
	require.NotNil(t, metadata.CredentialResponseEncryption)
	assert.Equal(t, []string{"ECDH-ES", "ECDH-ES+A128KW"}, metadata.CredentialResponseEncryption.AlgValuesSupported)
	assert.Equal(t, []string{"A256GCM", "A128GCM"}, metadata.CredentialResponseEncryption.EncValuesSupported)
	assert.True(t, metadata.CredentialResponseEncryption.EncryptionRequired)
}

func TestIssuerMetadataLoadAndSign_BatchCredentialIssuance(t *testing.T) {
	_, _, ecKeyPath, ecCertPath := setupTestPKI(t)

	cfg := &IssuerMetadata{
		KeyConfig: pki.KeyConfig{PrivateKeyPath: ecKeyPath, ChainPath: ecCertPath},
		
		BatchCredentialIssuance: &openid4vci.BatchCredentialIssuance{
			BatchSize: 10,
		},
	}

	credentialConstructors := map[string]*CredentialConstructor{
		"test_cred": {
			VCT:        "urn:test:1",
			AuthMethod: "basic",
		},
	}

	ctx := context.Background()
	metadata, _, _, _, err := cfg.LoadAndSign(ctx, "https://issuer.example.com", credentialConstructors)

	require.NoError(t, err)
	require.NotNil(t, metadata.BatchCredentialIssuance)
	assert.Equal(t, 10, metadata.BatchCredentialIssuance.BatchSize)
}

func TestIssuerMetadataLoadAndSign_IssuerDisplay(t *testing.T) {
	_, _, ecKeyPath, ecCertPath := setupTestPKI(t)

	cfg := &IssuerMetadata{
		KeyConfig: pki.KeyConfig{PrivateKeyPath: ecKeyPath, ChainPath: ecCertPath},
		
		Display: []openid4vci.MetadataDisplay{
			{
				Name:   "Example Issuer",
				Locale: "en-US",
				Logo: openid4vci.MetadataLogo{
					URI:     "https://example.com/logo.png",
					AltText: "Logo",
				},
			},
		},
	}

	credentialConstructors := map[string]*CredentialConstructor{
		"test_cred": {
			VCT:        "urn:test:1",
			AuthMethod: "basic",
		},
	}

	ctx := context.Background()
	metadata, _, _, _, err := cfg.LoadAndSign(ctx, "https://issuer.example.com", credentialConstructors)

	require.NoError(t, err)
	require.Len(t, metadata.Display, 1)
	assert.Equal(t, "Example Issuer", metadata.Display[0].Name)
	assert.Equal(t, "en-US", metadata.Display[0].Locale)
	assert.Equal(t, "https://example.com/logo.png", metadata.Display[0].Logo.URI)
}

func TestIssuerMetadataLoadAndSign_NilConstructor(t *testing.T) {
	_, _, ecKeyPath, ecCertPath := setupTestPKI(t)

	cfg := &IssuerMetadata{
		KeyConfig: pki.KeyConfig{PrivateKeyPath: ecKeyPath, ChainPath: ecCertPath},
		
	}

	credentialConstructors := map[string]*CredentialConstructor{
		"test_cred": nil, // Nil constructor should be skipped
		"test_cred2": {
			VCT:        "urn:test:2",
			AuthMethod: "basic",
		},
	}

	ctx := context.Background()
	metadata, _, _, _, err := cfg.LoadAndSign(ctx, "https://issuer.example.com", credentialConstructors)

	require.NoError(t, err)

	// Should only have test_cred2
	_, exists1 := metadata.CredentialConfigurationsSupported["test_cred"]
	assert.False(t, exists1, "Nil constructor should be skipped")

	_, exists2 := metadata.CredentialConfigurationsSupported["test_cred2"]
	assert.True(t, exists2, "Valid constructor should be included")
}

func TestIssuerMetadataLoadAndSign_EmptyConstructors(t *testing.T) {
	_, _, ecKeyPath, ecCertPath := setupTestPKI(t)

	cfg := &IssuerMetadata{
		KeyConfig: pki.KeyConfig{PrivateKeyPath: ecKeyPath, ChainPath: ecCertPath},
		
	}

	ctx := context.Background()
	metadata, _, _, _, err := cfg.LoadAndSign(ctx, "https://issuer.example.com", map[string]*CredentialConstructor{})

	require.NoError(t, err)
	assert.Empty(t, metadata.CredentialConfigurationsSupported)
}

func TestIssuerMetadataLoadAndSign_DefaultValues(t *testing.T) {
	_, _, ecKeyPath, ecCertPath := setupTestPKI(t)

	cfg := &IssuerMetadata{
		KeyConfig: pki.KeyConfig{PrivateKeyPath: ecKeyPath, ChainPath: ecCertPath},
		
		// All optional fields omitted to test defaults
	}

	credentialConstructors := map[string]*CredentialConstructor{
		"test_cred": {
			VCT:        "urn:test:1",
			Format:     "vc+sd-jwt",
			AuthMethod: "basic",
			// No custom crypto methods, etc. - testing defaults
		},
	}

	ctx := context.Background()
	metadata, _, _, _, err := cfg.LoadAndSign(ctx, "https://issuer.example.com", credentialConstructors)

	require.NoError(t, err)

	credConfig := metadata.CredentialConfigurationsSupported["test_cred"]

	// Check defaults
	assert.Equal(t, "vc+sd-jwt", credConfig.Format, "Should use default format")
	assert.Equal(t, []string{"jwk"}, credConfig.CryptographicBindingMethodsSupported, "Should use default crypto binding")
	assert.Equal(t, []any{"ES256", "ES384"}, credConfig.CredentialSigningAlgValuesSupported, "Should use default signing algorithms")

	jwtProof := credConfig.ProofTypesSupported["jwt"]
	assert.Equal(t, []string{"ES256", "ES384", "ES512"}, jwtProof.ProofSigningAlgValuesSupported, "Should use default proof algorithms")

	// Check credential definition
	assert.Equal(t, []string{"VerifiableCredential"}, credConfig.CredentialDefinition.Type)
}

func TestIssuerMetadataLoadAndSign_MultipleCredentials(t *testing.T) {
	_, _, ecKeyPath, ecCertPath := setupTestPKI(t)

	cfg := &IssuerMetadata{
		KeyConfig: pki.KeyConfig{PrivateKeyPath: ecKeyPath, ChainPath: ecCertPath},
		
	}

	credentialConstructors := map[string]*CredentialConstructor{
		"pid": {
			VCT:        "urn:eudi:pid:1",
			AuthMethod: "basic",
			Format:     "dc+sd-jwt",
		},
		"ehic": {
			VCT:        "urn:eudi:ehic:1",
			AuthMethod: "pid_auth",
			Format:     "vc+sd-jwt",
		},
		"diploma": {
			VCT:        "urn:eudi:diploma:1",
			AuthMethod: "basic",
			Format:     "vc+sd-jwt",
		},
	}

	ctx := context.Background()
	metadata, _, _, _, err := cfg.LoadAndSign(ctx, "https://issuer.example.com", credentialConstructors)

	require.NoError(t, err)
	assert.Len(t, metadata.CredentialConfigurationsSupported, 3)

	// Verify each credential
	pidConfig := metadata.CredentialConfigurationsSupported["pid"]
	assert.Equal(t, "dc+sd-jwt", pidConfig.Format)
	assert.Equal(t, "urn:eudi:pid:1", pidConfig.VCT)
	assert.Equal(t, "pid", pidConfig.Scope)

	ehicConfig := metadata.CredentialConfigurationsSupported["ehic"]
	assert.Equal(t, "vc+sd-jwt", ehicConfig.Format)
	assert.Equal(t, "urn:eudi:ehic:1", ehicConfig.VCT)

	diplomaConfig := metadata.CredentialConfigurationsSupported["diploma"]
	assert.Equal(t, "vc+sd-jwt", diplomaConfig.Format) // default
	assert.Equal(t, "urn:eudi:diploma:1", diplomaConfig.VCT)
}
