package model

import (
	"context"
	"testing"

	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIssuerMetadata_Generate_CustomFormat(t *testing.T) {
	cfg := &IssuerMetadata{}

	credMeta := map[string]*CredentialMetadata{
		"test_cred": {
			VCTM:   &sdjwtvc.VCTM{VCT: "https://issuer.sunet.se/type-metadata/test_cred"},
			VCTURL: "https://issuer.sunet.se/type-metadata/test_cred",
			Format: "dc+sd-jwt", // Custom format
		},
	}

	ctx := context.Background()
	metadata, err := cfg.Generate(ctx, "https://issuer.sunet.se", credMeta)
	require.NoError(t, err)
	require.NotNil(t, metadata)
	assert.Equal(t, "https://issuer.sunet.se", metadata.CredentialIssuer)

	credConfig, exists := metadata.CredentialConfigurationsSupported["test_cred"]
	require.True(t, exists)
	assert.Equal(t, "dc+sd-jwt", credConfig.Format)
	assert.Equal(t, "https://issuer.sunet.se/type-metadata/test_cred", credConfig.VCT)
}

func TestIssuerMetadata_Generate_CustomDisplay(t *testing.T) {
	cfg := &IssuerMetadata{}

	// Test that display must come from VCTM, not from constructor
	credMeta := map[string]*CredentialMetadata{
		"test_cred": {
			VCTM:   &sdjwtvc.VCTM{VCT: "https://issuer.sunet.se/type-metadata/test_cred"},
			Format: "vc+sd-jwt",
			// Display comes from VCTM, not from constructor
		},
	}

	ctx := context.Background()
	metadata, err := cfg.Generate(ctx, "https://issuer.sunet.se", credMeta)
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
		VCT:         "https://issuer.sunet.se/type-metadata/test_cred",
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

	credMeta := map[string]*CredentialMetadata{
		"test_cred": {
			VCTM: mockVCTM,
		},
	}

	ctx := context.Background()
	metadata, err := cfg.Generate(ctx, "https://issuer.sunet.se", credMeta)
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

func TestIssuerMetadata_Generate_VCTMDisplay_PartialRendering(t *testing.T) {
	tests := []struct {
		name            string
		rendering       *sdjwtvc.Rendering
		wantBgColor     string
		wantTextColor   string
		wantLogoNil     bool
	}{
		{
			name: "simple rendering without logo",
			rendering: &sdjwtvc.Rendering{
				Simple: &sdjwtvc.SimpleRendering{
					BackgroundColor: "#1a365d",
					TextColor:       "#ffffff",
				},
			},
			wantBgColor:   "#1a365d",
			wantTextColor: "#ffffff",
			wantLogoNil:   true,
		},
		{
			name: "nil simple with svg_templates only",
			rendering: &sdjwtvc.Rendering{
				SVGTemplates: []sdjwtvc.SVGTemplates{
					{URI: "data:image/svg+xml;base64,abc"},
				},
			},
			wantBgColor:   "",
			wantTextColor: "",
			wantLogoNil:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &IssuerMetadata{}
			mockVCTM := &sdjwtvc.VCTM{
				VCT:  "urn:demo:1",
				Name: "Demo",
				Display: []sdjwtvc.VCTMDisplay{
					{
						Locale:    "en-US",
						Name:      "Demo",
						Rendering: tt.rendering,
					},
				},
			}
			credMeta := map[string]*CredentialMetadata{
				"demo": {VCTM: mockVCTM},
			}
			ctx := context.Background()
			metadata, err := cfg.Generate(ctx, "https://issuer.example.com", credMeta)
			require.NoError(t, err)
			require.NotNil(t, metadata)

			credConfig, exists := metadata.CredentialConfigurationsSupported["demo"]
			require.True(t, exists)
			require.NotNil(t, credConfig.CredentialMetadata)
			require.Len(t, credConfig.CredentialMetadata.Display, 1)
			assert.Equal(t, tt.wantBgColor, credConfig.CredentialMetadata.Display[0].BackgroundColor)
			assert.Equal(t, tt.wantTextColor, credConfig.CredentialMetadata.Display[0].TextColor)
			if tt.wantLogoNil {
				assert.Nil(t, credConfig.CredentialMetadata.Display[0].Logo)
			}
		})
	}
}

func TestIssuerMetadata_Generate_CustomCryptoBindingMethods(t *testing.T) {
	cfg := &IssuerMetadata{
		CryptographicBindingMethodsSupported: []string{"jwk", "did:key"},
	}

	credMeta := map[string]*CredentialMetadata{
		"test_cred": {
			VCTM: &sdjwtvc.VCTM{VCT: "https://issuer.sunet.se/type-metadata/test_cred"},
		},
	}

	ctx := context.Background()
	metadata, err := cfg.Generate(ctx, "https://issuer.sunet.se", credMeta)
	require.NoError(t, err)

	credConfig := metadata.CredentialConfigurationsSupported["test_cred"]
	assert.Equal(t, []string{"jwk", "did:key"}, credConfig.CryptographicBindingMethodsSupported)
}

func TestIssuerMetadata_Generate_CustomSigningAlgorithms(t *testing.T) {
	cfg := &IssuerMetadata{
		CredentialSigningAlgValuesSupported: []string{"ES256", "ES512"},
	}

	credMeta := map[string]*CredentialMetadata{
		"test_cred": {
			VCTM: &sdjwtvc.VCTM{VCT: "urn:example:test:1"},
		},
	}

	ctx := context.Background()
	metadata, err := cfg.Generate(ctx, "https://issuer.sunet.se", credMeta)
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

	credMeta := map[string]*CredentialMetadata{
		"test_cred": {
			VCTM: &sdjwtvc.VCTM{VCT: "urn:example:test:1"},
		},
	}

	ctx := context.Background()
	metadata, err := cfg.Generate(ctx, "https://issuer.sunet.se", credMeta)
	require.NoError(t, err)

	credConfig := metadata.CredentialConfigurationsSupported["test_cred"]
	jwtProof := credConfig.ProofTypesSupported["jwt"]
	assert.Equal(t, []string{"ES256", "RS256"}, jwtProof.ProofSigningAlgValuesSupported)
}

func TestIssuerMetadata_Generate_OptionalEndpoints(t *testing.T) {
	cfg := &IssuerMetadata{ // #nosec G101
		AuthorizationServers:       []string{"https://oauth.sunet.se"},
		DeferredCredentialEndpoint: "https://issuer.sunet.se/deferred",
		NotificationEndpoint:       "https://issuer.sunet.se/notification",
	}

	credMeta := map[string]*CredentialMetadata{
		"test_cred": {
			VCTM: &sdjwtvc.VCTM{VCT: "https://issuer.sunet.se/type-metadata/test_cred"},
		},
	}

	ctx := context.Background()
	metadata, err := cfg.Generate(ctx, "https://issuer.sunet.se", credMeta)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://oauth.sunet.se"}, metadata.AuthorizationServers)
	assert.Equal(t, "https://issuer.sunet.se/deferred", metadata.DeferredCredentialEndpoint)
	assert.Equal(t, "https://issuer.sunet.se/notification", metadata.NotificationEndpoint)
}

func TestIssuerMetadata_Generate_CredentialResponseEncryption(t *testing.T) {
	cfg := &IssuerMetadata{
		CredentialResponseEncryption: &openid4vci.MetadataCredentialResponseEncryption{
			AlgValuesSupported: []string{"ECDH-ES", "ECDH-ES+A128KW"},
			EncValuesSupported: []string{"A256GCM", "A128GCM"},
			EncryptionRequired: true,
		},
	}

	credMeta := map[string]*CredentialMetadata{
		"test_cred": {
			VCTM: &sdjwtvc.VCTM{VCT: "urn:example:test:1"},
		},
	}

	ctx := context.Background()
	metadata, err := cfg.Generate(ctx, "https://issuer.sunet.se", credMeta)
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

	credMeta := map[string]*CredentialMetadata{
		"test_cred": {
			VCTM: &sdjwtvc.VCTM{VCT: "https://issuer.sunet.se/type-metadata/test_cred"},
		},
	}

	ctx := context.Background()
	metadata, err := cfg.Generate(ctx, "https://issuer.sunet.se", credMeta)
	require.NoError(t, err)
	require.NotNil(t, metadata.BatchCredentialIssuance)
	assert.Equal(t, 10, metadata.BatchCredentialIssuance.BatchSize)
}

func TestIssuerMetadata_Generate_IssuerDisplay(t *testing.T) {
	cfg := &IssuerMetadata{
		Display: []openid4vci.MetadataDisplay{
			{
				Name:   "SUNET Issuer",
				Locale: "en-US",
				Logo: &openid4vci.MetadataLogo{
					URI:     "https://issuer.sunet.se/logo.png",
					AltText: "Logo",
				},
			},
		},
	}

	credMeta := map[string]*CredentialMetadata{
		"test_cred": {
			VCTM: &sdjwtvc.VCTM{VCT: "urn:example:test:1"},
		},
	}

	ctx := context.Background()
	metadata, err := cfg.Generate(ctx, "https://issuer.sunet.se", credMeta)
	require.NoError(t, err)
	require.Len(t, metadata.Display, 1)
	assert.Equal(t, "SUNET Issuer", metadata.Display[0].Name)
	assert.Equal(t, "en-US", metadata.Display[0].Locale)
	require.NotNil(t, metadata.Display[0].Logo)
	assert.Equal(t, "https://issuer.sunet.se/logo.png", metadata.Display[0].Logo.URI)
}

func TestIssuerMetadata_Generate_NilConstructor(t *testing.T) {
	cfg := &IssuerMetadata{}

	credMeta := map[string]*CredentialMetadata{
		"test_cred": nil, // Nil constructor should be skipped
		"test_cred2": {
			VCTM: &sdjwtvc.VCTM{VCT: "https://issuer.sunet.se/type-metadata/test_cred2"},
		},
	}

	ctx := context.Background()
	metadata, err := cfg.Generate(ctx, "https://issuer.sunet.se", credMeta)
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
	metadata, err := cfg.Generate(ctx, "https://issuer.sunet.se", map[string]*CredentialMetadata{})
	require.NoError(t, err)
	assert.Empty(t, metadata.CredentialConfigurationsSupported)
}

func TestIssuerMetadata_Generate_DefaultValues(t *testing.T) {
	cfg := &IssuerMetadata{
		// All optional fields omitted to test defaults
	}

	credMeta := map[string]*CredentialMetadata{
		"test_cred": {
			VCTM:   &sdjwtvc.VCTM{VCT: "https://issuer.sunet.se/type-metadata/test_cred"},
			Format: "vc+sd-jwt",
			// No custom crypto methods, etc. - testing defaults
		},
	}

	ctx := context.Background()
	metadata, err := cfg.Generate(ctx, "https://issuer.sunet.se", credMeta)
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

	baseURL := "https://issuer.sunet.se"
	credMeta := map[string]*CredentialMetadata{
		"pid": {
			VCTM:   &sdjwtvc.VCTM{VCT: "https://issuer.sunet.se/type-metadata/pid"},
			VCTURL: baseURL + "/type-metadata/pid",
			Format: "dc+sd-jwt",
		},
		"ehic": {
			VCTM:   &sdjwtvc.VCTM{VCT: "urn:eudi:ehic:1"},
			VCTURL: baseURL + "/type-metadata/ehic",
			Format: "vc+sd-jwt",
		},
		"diploma": {
			VCTM:   &sdjwtvc.VCTM{VCT: "urn:eudi:diploma:1"},
			VCTURL: baseURL + "/type-metadata/diploma",
			Format: "vc+sd-jwt",
		},
	}

	ctx := context.Background()
	metadata, err := cfg.Generate(ctx, baseURL, credMeta)
	require.NoError(t, err)
	assert.Len(t, metadata.CredentialConfigurationsSupported, 3)

	// Verify each credential - keys are scope names
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

func TestIssuerMetadata_Generate_DisclosurePolicy(t *testing.T) {
	cfg := &IssuerMetadata{}
	baseURL := "https://issuer.sunet.se"

	tests := []struct {
		name           string
		policy         *openid4vci.EmbeddedDisclosurePolicy
		expectPolicy   bool
		expectType     string
		expectRPs      []string
		expectRoots    []string
	}{
		{
			name:         "no policy configured defaults to none",
			policy:       nil,
			expectPolicy: true,
			expectType:   "none",
		},
		{
			name: "none policy",
			policy: &openid4vci.EmbeddedDisclosurePolicy{
				PolicyType: "none",
			},
			expectPolicy: true,
			expectType:   "none",
		},
		{
			name: "authorized_relying_parties policy",
			policy: &openid4vci.EmbeddedDisclosurePolicy{
				PolicyType:               "authorized_relying_parties",
				AuthorizedRelyingParties: []string{"RP-ID-123", "RP-ID-456"},
			},
			expectPolicy: true,
			expectType:   "authorized_relying_parties",
			expectRPs:    []string{"RP-ID-123", "RP-ID-456"},
		},
		{
			name: "specific_root_of_trust policy",
			policy: &openid4vci.EmbeddedDisclosurePolicy{
				PolicyType:   "specific_root_of_trust",
				TrustedRoots: []string{"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"},
			},
			expectPolicy: true,
			expectType:   "specific_root_of_trust",
			expectRoots:  []string{"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credMeta := map[string]*CredentialMetadata{
				"test_cred": {
					VCTM:             &sdjwtvc.VCTM{VCT: baseURL + "/type-metadata/test_cred"},
					VCTURL:           baseURL + "/type-metadata/test_cred",
					Format:           "dc+sd-jwt",
					DisclosurePolicy: tt.policy,
				},
			}

			ctx := context.Background()
			metadata, err := cfg.Generate(ctx, baseURL, credMeta)
			require.NoError(t, err)

			credConfig := metadata.CredentialConfigurationsSupported["test_cred"]

			if !tt.expectPolicy {
				assert.Nil(t, credConfig.DisclosurePolicy)
				return
			}

			require.NotNil(t, credConfig.DisclosurePolicy)
			assert.Equal(t, tt.expectType, credConfig.DisclosurePolicy.PolicyType)

			if tt.expectRPs != nil {
				assert.Equal(t, tt.expectRPs, credConfig.DisclosurePolicy.AuthorizedRelyingParties)
			}
			if tt.expectRoots != nil {
				assert.Equal(t, tt.expectRoots, credConfig.DisclosurePolicy.TrustedRoots)
			}
		})
	}
}
