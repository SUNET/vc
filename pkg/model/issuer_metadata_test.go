package model

import (
	"context"
	"testing"
	"vc/pkg/openid4vci"
	"vc/pkg/sdjwtvc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIssuerMetadata_Generate_CustomFormat(t *testing.T) {
	cfg := &IssuerMetadata{}

	credentialConstructors := map[string]*CredentialConstructor{
		"test_cred": {
			VCTM:       &sdjwtvc.VCTM{VCT: "urn:test:1"},
			VCTURL:     "https://issuer.example.com/type-metadata/test_cred",
			Format:     "dc+sd-jwt", // Custom format
			AuthMethod: "basic",
		},
	}

	ctx := context.Background()
	metadata, err := cfg.Generate(ctx, "https://issuer.example.com", credentialConstructors)
	require.NoError(t, err)
	require.NotNil(t, metadata)
	assert.Equal(t, "https://issuer.example.com", metadata.CredentialIssuer)

	credConfig, exists := metadata.CredentialConfigurationsSupported["test_cred"]
	require.True(t, exists)
	assert.Equal(t, "dc+sd-jwt", credConfig.Format)
	assert.Equal(t, "https://issuer.example.com/type-metadata/test_cred", credConfig.VCT)
}

func TestIssuerMetadata_Generate_CustomDisplay(t *testing.T) {
	cfg := &IssuerMetadata{}

	// Test that display must come from VCTM, not from constructor
	credentialConstructors := map[string]*CredentialConstructor{
		"test_cred": {
			VCTM:       &sdjwtvc.VCTM{VCT: "urn:test:1"},
			Format:     "vc+sd-jwt",
			AuthMethod: "basic",
			// Display comes from VCTM, not from constructor
		},
	}

	ctx := context.Background()
	metadata, err := cfg.Generate(ctx, "https://issuer.example.com", credentialConstructors)
	require.NoError(t, err)
	require.NotNil(t, metadata)

	credConfig, exists := metadata.CredentialConfigurationsSupported["test_cred"]
	require.True(t, exists)
	// Without VCTM loaded, there's no display
	require.Nil(t, credConfig.CredentialMetadata)
}

func TestIssuerMetadata_Generate_VCTMDisplay(t *testing.T) {
	cfg := &IssuerMetadata{}

	// Mock VCTM with display
	mockVCTM := &sdjwtvc.VCTM{
		VCT:         "urn:test:1",
		Name:        "Test VCTM",
		Description: "Test Description",
		Display: []sdjwtvc.VCTMDisplay{
			{
				Locale:      "en-US",
				Name:        "VCTM Display Name",
				Description: "VCTM Description",
			},
		},
	}

	credentialConstructors := map[string]*CredentialConstructor{
		"test_cred": {
			AuthMethod: "basic",
			VCTM:       mockVCTM,
		},
	}

	ctx := context.Background()
	metadata, err := cfg.Generate(ctx, "https://issuer.example.com", credentialConstructors)
	require.NoError(t, err)
	require.NotNil(t, metadata)

	credConfig, exists := metadata.CredentialConfigurationsSupported["test_cred"]
	require.True(t, exists)
	require.NotNil(t, credConfig.CredentialMetadata)
	require.Len(t, credConfig.CredentialMetadata.Display, 1)

	assert.Equal(t, "VCTM Display Name", credConfig.CredentialMetadata.Display[0].Name)
	assert.Equal(t, "en-US", credConfig.CredentialMetadata.Display[0].Locale)
	assert.Equal(t, "VCTM Description", credConfig.CredentialMetadata.Display[0].Description)
}

func TestIssuerMetadata_Generate_CustomCryptoBindingMethods(t *testing.T) {
	cfg := &IssuerMetadata{
		CryptographicBindingMethodsSupported: []string{"jwk", "did:key"},
	}

	credentialConstructors := map[string]*CredentialConstructor{
		"test_cred": {
			VCTM:       &sdjwtvc.VCTM{VCT: "urn:test:1"},
			AuthMethod: "basic",
		},
	}

	ctx := context.Background()
	metadata, err := cfg.Generate(ctx, "https://issuer.example.com", credentialConstructors)
	require.NoError(t, err)

	credConfig := metadata.CredentialConfigurationsSupported["test_cred"]
	assert.Equal(t, []string{"jwk", "did:key"}, credConfig.CryptographicBindingMethodsSupported)
}

func TestIssuerMetadata_Generate_CustomSigningAlgorithms(t *testing.T) {
	cfg := &IssuerMetadata{
		CredentialSigningAlgValuesSupported: []string{"ES256", "ES512"},
	}

	credentialConstructors := map[string]*CredentialConstructor{
		"test_cred": {
			VCTM:       &sdjwtvc.VCTM{VCT: "urn:test:1"},
			AuthMethod: "basic",
		},
	}

	ctx := context.Background()
	metadata, err := cfg.Generate(ctx, "https://issuer.example.com", credentialConstructors)
	require.NoError(t, err)

	credConfig := metadata.CredentialConfigurationsSupported["test_cred"]
	require.Len(t, credConfig.CredentialSigningAlgValuesSupported, 2)
	assert.Equal(t, "ES256", credConfig.CredentialSigningAlgValuesSupported[0])
	assert.Equal(t, "ES512", credConfig.CredentialSigningAlgValuesSupported[1])
}

func TestIssuerMetadata_Generate_CustomProofAlgorithms(t *testing.T) {
	cfg := &IssuerMetadata{
		ProofSigningAlgValuesSupported: []string{"ES256", "RS256"},
	}

	credentialConstructors := map[string]*CredentialConstructor{
		"test_cred": {
			VCTM:       &sdjwtvc.VCTM{VCT: "urn:test:1"},
			AuthMethod: "basic",
		},
	}

	ctx := context.Background()
	metadata, err := cfg.Generate(ctx, "https://issuer.example.com", credentialConstructors)
	require.NoError(t, err)

	credConfig := metadata.CredentialConfigurationsSupported["test_cred"]
	jwtProof := credConfig.ProofTypesSupported["jwt"]
	assert.Equal(t, []string{"ES256", "RS256"}, jwtProof.ProofSigningAlgValuesSupported)
}

func TestIssuerMetadata_Generate_OptionalEndpoints(t *testing.T) {
	cfg := &IssuerMetadata{
		AuthorizationServers:       []string{"https://oauth.example.com"},
		DeferredCredentialEndpoint: "https://issuer.example.com/deferred",
		NotificationEndpoint:       "https://issuer.example.com/notification",
	}

	credentialConstructors := map[string]*CredentialConstructor{
		"test_cred": {
			VCTM:       &sdjwtvc.VCTM{VCT: "urn:test:1"},
			AuthMethod: "basic",
		},
	}

	ctx := context.Background()
	metadata, err := cfg.Generate(ctx, "https://issuer.example.com", credentialConstructors)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://oauth.example.com"}, metadata.AuthorizationServers)
	assert.Equal(t, "https://issuer.example.com/deferred", metadata.DeferredCredentialEndpoint)
	assert.Equal(t, "https://issuer.example.com/notification", metadata.NotificationEndpoint)
}

func TestIssuerMetadata_Generate_CredentialResponseEncryption(t *testing.T) {
	cfg := &IssuerMetadata{
		CredentialResponseEncryption: &openid4vci.MetadataCredentialResponseEncryption{
			AlgValuesSupported: []string{"ECDH-ES", "ECDH-ES+A128KW"},
			EncValuesSupported: []string{"A256GCM", "A128GCM"},
			EncryptionRequired: true,
		},
	}

	credentialConstructors := map[string]*CredentialConstructor{
		"test_cred": {
			VCTM:       &sdjwtvc.VCTM{VCT: "urn:test:1"},
			AuthMethod: "basic",
		},
	}

	ctx := context.Background()
	metadata, err := cfg.Generate(ctx, "https://issuer.example.com", credentialConstructors)
	require.NoError(t, err)
	require.NotNil(t, metadata.CredentialResponseEncryption)
	assert.Equal(t, []string{"ECDH-ES", "ECDH-ES+A128KW"}, metadata.CredentialResponseEncryption.AlgValuesSupported)
	assert.Equal(t, []string{"A256GCM", "A128GCM"}, metadata.CredentialResponseEncryption.EncValuesSupported)
	assert.True(t, metadata.CredentialResponseEncryption.EncryptionRequired)
}

func TestIssuerMetadata_Generate_BatchCredentialIssuance(t *testing.T) {
	cfg := &IssuerMetadata{
		BatchCredentialIssuance: &openid4vci.BatchCredentialIssuance{
			BatchSize: 10,
		},
	}

	credentialConstructors := map[string]*CredentialConstructor{
		"test_cred": {
			VCTM:       &sdjwtvc.VCTM{VCT: "urn:test:1"},
			AuthMethod: "basic",
		},
	}

	ctx := context.Background()
	metadata, err := cfg.Generate(ctx, "https://issuer.example.com", credentialConstructors)
	require.NoError(t, err)
	require.NotNil(t, metadata.BatchCredentialIssuance)
	assert.Equal(t, 10, metadata.BatchCredentialIssuance.BatchSize)
}

func TestIssuerMetadata_Generate_IssuerDisplay(t *testing.T) {
	cfg := &IssuerMetadata{
		Display: []openid4vci.MetadataDisplay{
			{
				Name:   "Example Issuer",
				Locale: "en-US",
				Logo: &openid4vci.MetadataLogo{
					URI:     "https://example.com/logo.png",
					AltText: "Logo",
				},
			},
		},
	}

	credentialConstructors := map[string]*CredentialConstructor{
		"test_cred": {
			VCTM:       &sdjwtvc.VCTM{VCT: "urn:test:1"},
			AuthMethod: "basic",
		},
	}

	ctx := context.Background()
	metadata, err := cfg.Generate(ctx, "https://issuer.example.com", credentialConstructors)
	require.NoError(t, err)
	require.Len(t, metadata.Display, 1)
	assert.Equal(t, "Example Issuer", metadata.Display[0].Name)
	assert.Equal(t, "en-US", metadata.Display[0].Locale)
	require.NotNil(t, metadata.Display[0].Logo)
	assert.Equal(t, "https://example.com/logo.png", metadata.Display[0].Logo.URI)
}

func TestIssuerMetadata_Generate_NilConstructor(t *testing.T) {
	cfg := &IssuerMetadata{}

	credentialConstructors := map[string]*CredentialConstructor{
		"test_cred": nil, // Nil constructor should be skipped
		"test_cred2": {
			VCTM:       &sdjwtvc.VCTM{VCT: "urn:test:2"},
			AuthMethod: "basic",
		},
	}

	ctx := context.Background()
	metadata, err := cfg.Generate(ctx, "https://issuer.example.com", credentialConstructors)
	require.NoError(t, err)

	// Should only have test_cred2
	_, exists1 := metadata.CredentialConfigurationsSupported["test_cred"]
	assert.False(t, exists1, "Nil constructor should be skipped")

	_, exists2 := metadata.CredentialConfigurationsSupported["test_cred2"]
	assert.True(t, exists2, "Valid constructor should be included")
}

func TestIssuerMetadata_Generate_EmptyConstructors(t *testing.T) {
	cfg := &IssuerMetadata{}

	ctx := context.Background()
	metadata, err := cfg.Generate(ctx, "https://issuer.example.com", map[string]*CredentialConstructor{})
	require.NoError(t, err)
	assert.Empty(t, metadata.CredentialConfigurationsSupported)
}

func TestIssuerMetadata_Generate_DefaultValues(t *testing.T) {
	cfg := &IssuerMetadata{
		// All optional fields omitted to test defaults
	}

	credentialConstructors := map[string]*CredentialConstructor{
		"test_cred": {
			VCTM:       &sdjwtvc.VCTM{VCT: "urn:test:1"},
			Format:     "vc+sd-jwt",
			AuthMethod: "basic",
			// No custom crypto methods, etc. - testing defaults
		},
	}

	ctx := context.Background()
	metadata, err := cfg.Generate(ctx, "https://issuer.example.com", credentialConstructors)
	require.NoError(t, err)

	credConfig := metadata.CredentialConfigurationsSupported["test_cred"]

	// Check defaults
	assert.Equal(t, "vc+sd-jwt", credConfig.Format, "Should use default format")
	assert.Equal(t, []string{"jwk"}, credConfig.CryptographicBindingMethodsSupported, "Should use default crypto binding")
	assert.Equal(t, []any{"ES256", "ES384", "RS256"}, credConfig.CredentialSigningAlgValuesSupported, "Should use default signing algorithms")

	jwtProof := credConfig.ProofTypesSupported["jwt"]
	assert.Equal(t, []string{"ES256", "ES384", "ES512", "RS256", "RS384", "RS512"}, jwtProof.ProofSigningAlgValuesSupported, "Should use default proof algorithms")

	// Check credential definition (vc+sd-jwt is not a W3C VC format, so no credential_definition)
	assert.Nil(t, credConfig.CredentialDefinition, "vc+sd-jwt should not have credential_definition")
}

func TestIssuerMetadata_Generate_MultipleCredentials(t *testing.T) {
	cfg := &IssuerMetadata{}

	baseURL := "https://issuer.example.com"
	credentialConstructors := map[string]*CredentialConstructor{
		"pid": {
			VCTM:       &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"},
			VCTURL:     baseURL + "/type-metadata/pid",
			AuthMethod: "basic",
			Format:     "dc+sd-jwt",
		},
		"ehic": {
			VCTM:       &sdjwtvc.VCTM{VCT: "urn:eudi:ehic:1"},
			VCTURL:     baseURL + "/type-metadata/ehic",
			AuthMethod: "openid4vp",
			Format:     "vc+sd-jwt",
		},
		"diploma": {
			VCTM:       &sdjwtvc.VCTM{VCT: "urn:eudi:diploma:1"},
			VCTURL:     baseURL + "/type-metadata/diploma",
			AuthMethod: "basic",
			Format:     "vc+sd-jwt",
		},
	}

	ctx := context.Background()
	metadata, err := cfg.Generate(ctx, baseURL, credentialConstructors)
	require.NoError(t, err)
	assert.Len(t, metadata.CredentialConfigurationsSupported, 3)

	// Verify each credential
	pidConfig := metadata.CredentialConfigurationsSupported["pid"]
	assert.Equal(t, "dc+sd-jwt", pidConfig.Format)
	assert.Equal(t, baseURL+"/type-metadata/pid", pidConfig.VCT)
	assert.Equal(t, "pid", pidConfig.Scope)

	ehicConfig := metadata.CredentialConfigurationsSupported["ehic"]
	assert.Equal(t, "vc+sd-jwt", ehicConfig.Format)
	assert.Equal(t, baseURL+"/type-metadata/ehic", ehicConfig.VCT)

	diplomaConfig := metadata.CredentialConfigurationsSupported["diploma"]
	assert.Equal(t, "vc+sd-jwt", diplomaConfig.Format) // default
	assert.Equal(t, baseURL+"/type-metadata/diploma", diplomaConfig.VCT)
}
