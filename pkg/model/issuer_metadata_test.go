package model

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/SUNET/vc/pkg/mdoc"
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

func TestIssuerMetadata_Generate_MDDLDisplay_SVGTemplates(t *testing.T) {
	cfg := &IssuerMetadata{}

	mockMDDL := &mdoc.MDDLSchema{
		Format:  "mso_mdoc",
		DocType: "org.iso.18013.5.1.mDL",
		Display: []mdoc.DisplayProperties{
			{
				Locale: "en-US",
				Name:   "Mobile Driving Licence",
				Rendering: &mdoc.Rendering{
					SVGTemplates: []mdoc.SVGTemplate{
						{
							URI: "https://issuer.example.com/mdl.svg",
							Properties: &mdoc.SVGTemplateProperties{
								Orientation: "landscape",
								ColorScheme: "light",
								Contrast:    "normal",
							},
						},
					},
				},
			},
		},
		Claims: map[string]mdoc.NamespaceClaims{
			"org.iso.18013.5.1": {
				"family_name": {Mandatory: true, ValueType: "tstr"},
			},
		},
	}

	credMeta := map[string]*CredentialMetadata{
		"test_mdl": {
			Format: "mso_mdoc",
			MDDL:   mockMDDL,
		},
	}

	ctx := context.Background()
	metadata, err := cfg.Generate(ctx, "https://issuer.sunet.se", credMeta)
	require.NoError(t, err)
	require.NotNil(t, metadata)

	credConfig, exists := metadata.CredentialConfigurationsSupported["test_mdl"]
	require.True(t, exists)
	require.NotNil(t, credConfig.CredentialMetadata)
	require.Len(t, credConfig.CredentialMetadata.Display, 1)

	display := credConfig.CredentialMetadata.Display[0]
	require.NotNil(t, display.Rendering, "mso_mdoc display with svg_templates must produce a Rendering block, mirroring the dc+sd-jwt/VCTM path")
	require.Len(t, display.Rendering.SvgTemplates, 1)
	assert.Equal(t, "https://issuer.example.com/mdl.svg", display.Rendering.SvgTemplates[0].URI)
	require.NotNil(t, display.Rendering.SvgTemplates[0].Properties)
	assert.Equal(t, "landscape", display.Rendering.SvgTemplates[0].Properties.Orientation)
	assert.Equal(t, "light", display.Rendering.SvgTemplates[0].Properties.ColorScheme)
	assert.Equal(t, "normal", display.Rendering.SvgTemplates[0].Properties.Contrast)

	// No explicit logo was set — the svg_templates fallback must populate
	// Logo.URI from the first template, for wallets that render from
	// logo.uri instead of understanding svg_templates.
	require.NotNil(t, display.Logo)
	assert.Equal(t, "https://issuer.example.com/mdl.svg", display.Logo.URI)
}

// TestIssuerMetadata_Generate_MDDLClaims_DisplayAndSVGID is a regression test
// for a bug found in live testing (PR #584): the mso_mdoc claims-building
// loop only set Path/Mandatory on each ClaimDescription, silently dropping
// SVGID and Display -- breaking svg_id placeholder substitution (no value
// ever bound) and the wallet's claims list (its isDisplayClaim check needs
// display[].locale/label, so every claim's display was empty).
func TestIssuerMetadata_Generate_MDDLClaims_DisplayAndSVGID(t *testing.T) {
	cfg := &IssuerMetadata{}

	mockMDDL := &mdoc.MDDLSchema{
		Format:  "mso_mdoc",
		DocType: "org.iso.18013.5.1.mDL",
		Claims: map[string]mdoc.NamespaceClaims{
			"org.iso.18013.5.1": {
				// SVGID + Display with an explicit Label distinct from Name.
				"family_name": {
					Mandatory: true,
					ValueType: "tstr",
					SVGID:     "family_name",
					Display: []mdoc.ClaimDisplay{
						{Locale: "en-US", Name: "family_name", Label: "Family Name"},
					},
				},
				// SVGID + Display with no Label set -- must fall back to Name.
				"given_name": {
					ValueType: "tstr",
					SVGID:     "given_name",
					Display: []mdoc.ClaimDisplay{
						{Locale: "en-US", Name: "Given Name"},
					},
				},
				// No Display at all -- Claim.Display must stay empty, not panic.
				"portrait": {
					ValueType: "bstr",
				},
			},
		},
	}

	credMeta := map[string]*CredentialMetadata{
		"test_mdl": {Format: "mso_mdoc", MDDL: mockMDDL},
	}

	metadata, err := cfg.Generate(context.Background(), "https://issuer.sunet.se", credMeta)
	require.NoError(t, err)
	require.NotNil(t, metadata)

	credConfig, exists := metadata.CredentialConfigurationsSupported["test_mdl"]
	require.True(t, exists)
	require.NotNil(t, credConfig.CredentialMetadata)
	require.Len(t, credConfig.CredentialMetadata.Claims, 3)

	byElementID := map[string]openid4vci.ClaimDescription{}
	for _, c := range credConfig.CredentialMetadata.Claims {
		require.Len(t, c.Path, 2)
		require.NotNil(t, c.Path[1])
		byElementID[*c.Path[1]] = c
	}

	familyName := byElementID["family_name"]
	assert.Equal(t, "family_name", familyName.SVGID)
	require.Len(t, familyName.Display, 1)
	assert.Equal(t, "Family Name", familyName.Display[0].Label, "an explicit Label must win over Name")
	assert.Equal(t, "en-US", familyName.Display[0].Locale)

	givenName := byElementID["given_name"]
	assert.Equal(t, "given_name", givenName.SVGID)
	require.Len(t, givenName.Display, 1)
	assert.Equal(t, "Given Name", givenName.Display[0].Label, "Label must fall back to Name when unset")

	portrait := byElementID["portrait"]
	assert.Empty(t, portrait.SVGID)
	assert.Empty(t, portrait.Display)
}

func TestIssuerMetadata_Generate_VCTMDisplay_PartialRendering(t *testing.T) {
	tests := []struct {
		name          string
		rendering     *sdjwtvc.Rendering
		wantBgColor   string
		wantTextColor string
		wantLogoNil   bool
		wantLogoURI   string
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
			wantLogoNil:   false,
			wantLogoURI:   "data:image/svg+xml;base64,abc",
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
			} else {
				require.NotNil(t, credConfig.CredentialMetadata.Display[0].Logo)
				assert.Equal(t, tt.wantLogoURI, credConfig.CredentialMetadata.Display[0].Logo.URI)
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

// TestIssuerMetadata_Generate_PreservesEmbeddedVCT pins the Generate stage's
// contract: credConfig.VCT is always VCTM.VCT verbatim, with a defensive
// fallback to VCTURL only when VCTM.VCT is empty. The upstream ResolveVCTUrls
// stage preserves the file's own vct for both local and external sources and
// only back-fills VCTM.VCT from the hosting URL when the local file left it
// empty -- covered by TestIssuerMetadata_Generate_PreservesEmbeddedVCT_LocalFile
// and _ExternalURL below.
func TestIssuerMetadata_Generate_PreservesEmbeddedVCT(t *testing.T) {
	const baseURL = "https://issuer.sunet.se"
	const vctURL = baseURL + "/type-metadata/test_cred"

	tests := []struct {
		name    string
		vctmVCT string
		format  string
		wantVCT string
	}{
		{name: "dc+sd-jwt with URN VCT", vctmVCT: "urn:eudi:pid:1", format: "dc+sd-jwt", wantVCT: "urn:eudi:pid:1"},
		{name: "vc+sd-jwt with URN VCT", vctmVCT: "urn:eudi:ehic:1", format: "vc+sd-jwt", wantVCT: "urn:eudi:ehic:1"},
		{name: "dc+sd-jwt with foreign URL VCT", vctmVCT: "https://registry.siros.org/sirosfoundation/demo_pid_rb_1_5.vctm.json", format: "dc+sd-jwt", wantVCT: "https://registry.siros.org/sirosfoundation/demo_pid_rb_1_5.vctm.json"},
		{name: "jwt_vc_json with URN VCT", vctmVCT: "urn:example:diploma:1", format: "jwt_vc_json", wantVCT: "urn:example:diploma:1"},
		{name: "dc+sd-jwt with empty VCT falls back to VCTURL", vctmVCT: "", format: "dc+sd-jwt", wantVCT: vctURL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &IssuerMetadata{}
			credMeta := map[string]*CredentialMetadata{
				"test_cred": {
					VCTM:   &sdjwtvc.VCTM{VCT: tt.vctmVCT},
					VCTURL: vctURL,
					Format: tt.format,
				},
			}
			metadata, err := cfg.Generate(context.Background(), baseURL, credMeta)
			require.NoError(t, err)
			credConfig, exists := metadata.CredentialConfigurationsSupported["test_cred"]
			require.True(t, exists)
			assert.Equal(t, tt.wantVCT, credConfig.VCT)
		})
	}
}

// TestIssuerMetadata_Generate_PreservesEmbeddedVCT_LocalFile pins the
// end-to-end contract for a scope configured with vctm_file_path -- apigw
// hosts the VCTM under /type-metadata/<scope>, and VCTURL is always the
// hosting URL. VCTM.VCT keeps whatever the file declared (URN or foreign
// registry URL); only an empty file vct is back-filled from the hosting URL.
// credConfig.VCT and the served VCTMRaw's vct always match VCTM.VCT, so the
// credential body (BuildCredentialWithSigner stamps body["vct"] = vctm.VCT),
// DCQL vct_values, and the wallet's stored tag all reference the same value.
func TestIssuerMetadata_Generate_PreservesEmbeddedVCT_LocalFile(t *testing.T) {
	const baseURL = "https://demo-1.issuer.id.siros.org"
	const scope = "demo_pid_rb_1_5"
	hostingURL := baseURL + "/type-metadata/" + scope

	tests := []struct {
		name    string
		fileVCT string
		wantVCT string
	}{
		{name: "file's foreign registry URL vct is preserved", fileVCT: "https://registry.siros.org/sirosfoundation/demo_pid_rb_1_5.vctm.json", wantVCT: "https://registry.siros.org/sirosfoundation/demo_pid_rb_1_5.vctm.json"},
		{name: "file's URN vct is preserved", fileVCT: "urn:eudi:pid:1", wantVCT: "urn:eudi:pid:1"},
		{name: "file with no vct is back-filled from the hosting URL", fileVCT: "", wantVCT: hostingURL},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := json.Marshal(map[string]any{
				"vct":  tt.fileVCT,
				"name": "Demo PID",
			})
			require.NoError(t, err)

			cfg := &Cfg{
				Common: &Common{
					CredentialMetadata: map[string]*CredentialMetadata{
						scope: {
							Format:       "dc+sd-jwt",
							VCTMFilePath: "/vctms/" + scope + ".json",
							VCTM:         &sdjwtvc.VCTM{VCT: tt.fileVCT, Name: "Demo PID"},
							VCTMRaw:      raw,
						},
					},
				},
			}

			require.NoError(t, cfg.ResolveVCTUrls(baseURL))

			constructor := cfg.Common.CredentialMetadata[scope]
			assert.Equal(t, hostingURL, constructor.VCTURL, "VCTURL for a local file is always the hosting URL")
			assert.Equal(t, tt.wantVCT, constructor.VCTM.VCT)

			var doc map[string]any
			require.NoError(t, json.Unmarshal(constructor.VCTMRaw, &doc))
			assert.Equal(t, tt.wantVCT, doc["vct"], "served VCTM document must carry the same vct as VCTM.VCT")

			metadata, err := (&IssuerMetadata{}).Generate(context.Background(), baseURL, cfg.Common.CredentialMetadata)
			require.NoError(t, err)
			credConfig, exists := metadata.CredentialConfigurationsSupported[scope]
			require.True(t, exists)
			assert.Equal(t, tt.wantVCT, credConfig.VCT)
		})
	}
}

// TestIssuerMetadata_Generate_PreservesEmbeddedVCT_ExternalURL pins the
// external-source contract: when the VCTM is loaded via vctm_url, apigw is
// NOT the registry -- the external source is authoritative. ResolveVCTUrls
// must leave VCTM.VCT and VCTMRaw untouched, VCTURL is set to the external
// URL, and credConfig.VCT advertises the file's own vct verbatim (URN or
// foreign URL). This must stay stable regardless of what the local case
// rewrites.
func TestIssuerMetadata_Generate_PreservesEmbeddedVCT_ExternalURL(t *testing.T) {
	const baseURL = "https://demo-1.issuer.id.siros.org"
	const scope = "demo_pid_rb_1_5"
	const vctmURL = "https://registry.siros.org/sirosfoundation/demo_pid_rb_1_5.vctm.json"

	tests := []struct {
		name    string
		fileVCT string
	}{
		{name: "external URL vct is preserved verbatim", fileVCT: vctmURL},
		{name: "external URN vct is preserved verbatim", fileVCT: "urn:eudi:pid:1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := json.Marshal(map[string]any{
				"vct":  tt.fileVCT,
				"name": "Demo PID",
			})
			require.NoError(t, err)

			cfg := &Cfg{
				Common: &Common{
					CredentialMetadata: map[string]*CredentialMetadata{
						scope: {
							Format:  "dc+sd-jwt",
							VCTMUrl: vctmURL,
							VCTM:    &sdjwtvc.VCTM{VCT: tt.fileVCT, Name: "Demo PID"},
							VCTMRaw: raw,
						},
					},
				},
			}

			require.NoError(t, cfg.ResolveVCTUrls(baseURL))

			constructor := cfg.Common.CredentialMetadata[scope]
			assert.Equal(t, vctmURL, constructor.VCTURL, "VCTURL for an external VCTM is the vctm_url")
			assert.Equal(t, tt.fileVCT, constructor.VCTM.VCT, "external VCTM.VCT must be preserved verbatim")

			var doc map[string]any
			require.NoError(t, json.Unmarshal(constructor.VCTMRaw, &doc))
			assert.Equal(t, tt.fileVCT, doc["vct"], "external VCTMRaw must not be rewritten")

			metadata, err := (&IssuerMetadata{}).Generate(context.Background(), baseURL, cfg.Common.CredentialMetadata)
			require.NoError(t, err)
			credConfig, exists := metadata.CredentialConfigurationsSupported[scope]
			require.True(t, exists)
			assert.Equal(t, tt.fileVCT, credConfig.VCT)
		})
	}
}

// TestIssuerMetadata_Generate_ServedMetadata_MixedSources exercises the exact
// startup wiring apigw's Client.New runs -- ResolveVCTUrls then
// IssuerMetadata.Generate against cfg.Common.CredentialMetadata -- with a
// locally-published (vctm_file_path) scope with its own URN, a local scope
// with no vct at all, and an external (vctm_url) scope side by side. It
// then marshals the result to JSON (what /.well-known/openid-credential-issuer
// serves). Each scope must carry its own vct with zero cross-contamination:
//
//   - local_pid_urn: keeps the URN from the file ("urn:eudi:pid:1"); apigw
//     hosts the metadata under /type-metadata/local_pid_urn but that URL is
//     never advertised as vct.
//   - local_pid_nofile: had no vct, so ResolveVCTUrls back-fills the hosting
//     URL and the served vct is /type-metadata/local_pid_nofile.
//   - external_pid: source is authoritative; keeps the file's URN and the
//     apigw's /type-metadata/external_pid URL never appears in it.
func TestIssuerMetadata_Generate_ServedMetadata_MixedSources(t *testing.T) {
	const baseURL = "https://demo-1.issuer.id.siros.org"
	const localURNScope = "local_pid_urn"
	const localNoFileVCTScope = "local_pid_nofile"
	const externalScope = "external_pid"
	const localURN = "urn:eudi:pid:1"
	const externalVCT = "urn:eudi:pid:1"
	const externalVCTMUrl = "https://registry.siros.org/sirosfoundation/external_pid.vctm.json"

	localURNHostingURL := baseURL + "/type-metadata/" + localURNScope
	localNoFileHostingURL := baseURL + "/type-metadata/" + localNoFileVCTScope
	externalHostingURL := baseURL + "/type-metadata/" + externalScope

	localURNRaw, err := json.Marshal(map[string]any{
		"vct":  localURN,
		"name": "Local PID (URN)",
	})
	require.NoError(t, err)
	localNoFileRaw, err := json.Marshal(map[string]any{
		"name": "Local PID (no vct)",
	})
	require.NoError(t, err)
	externalRaw, err := json.Marshal(map[string]any{
		"vct":  externalVCT,
		"name": "External PID",
	})
	require.NoError(t, err)

	cfg := &Cfg{
		Common: &Common{
			CredentialMetadata: map[string]*CredentialMetadata{
				localURNScope: {
					Format:       "dc+sd-jwt",
					VCTMFilePath: "/vctms/" + localURNScope + ".json",
					VCTM:         &sdjwtvc.VCTM{VCT: localURN, Name: "Local PID (URN)"},
					VCTMRaw:      localURNRaw,
				},
				localNoFileVCTScope: {
					Format:       "dc+sd-jwt",
					VCTMFilePath: "/vctms/" + localNoFileVCTScope + ".json",
					VCTM:         &sdjwtvc.VCTM{Name: "Local PID (no vct)"},
					VCTMRaw:      localNoFileRaw,
				},
				externalScope: {
					Format:  "dc+sd-jwt",
					VCTMUrl: externalVCTMUrl,
					VCTM:    &sdjwtvc.VCTM{VCT: externalVCT, Name: "External PID"},
					VCTMRaw: externalRaw,
				},
			},
		},
	}

	require.NoError(t, cfg.ResolveVCTUrls(baseURL))

	metadata, err := (&IssuerMetadata{}).Generate(context.Background(), baseURL, cfg.Common.CredentialMetadata)
	require.NoError(t, err)

	served, err := json.Marshal(metadata)
	require.NoError(t, err)

	var doc struct {
		CredentialConfigurationsSupported map[string]struct {
			VCT string `json:"vct"`
		} `json:"credential_configurations_supported"`
	}
	require.NoError(t, json.Unmarshal(served, &doc))

	assert.Equal(t, localURN, doc.CredentialConfigurationsSupported[localURNScope].VCT,
		"local scope with an explicit URN: served vct must keep the URN")
	assert.Equal(t, localNoFileHostingURL, doc.CredentialConfigurationsSupported[localNoFileVCTScope].VCT,
		"local scope without a file vct: served vct must be the hosting URL")
	assert.Equal(t, externalVCT, doc.CredentialConfigurationsSupported[externalScope].VCT,
		"external scope: served vct must be the file's own vct")

	// The local URN scope's hosting URL must not sneak in as its advertised vct.
	assert.NotContains(t, string(served), fmt.Sprintf(`%q:%q`, "vct", localURNHostingURL),
		"the local URN scope must not advertise its apigw hosting URL as vct")
	assert.NotContains(t, string(served), fmt.Sprintf(`%q:%q`, "vct", externalHostingURL),
		"the external scope must not advertise the apigw hosting URL as its vct")
}

// TestIssuerMetadata_Generate_MDDLDoctype_Preserved locks in the mso_mdoc
// branch's already-correct behavior: MDDL.DocType is copied verbatim into
// credConfig.Doctype, no hosting URL rewrites (regression guard alongside
// TestIssuerMetadata_Generate_PreservesEmbeddedVCT).
func TestIssuerMetadata_Generate_MDDLDoctype_Preserved(t *testing.T) {
	cfg := &IssuerMetadata{}
	credMeta := map[string]*CredentialMetadata{
		"test_mdl": {
			Format: "mso_mdoc",
			MDDL: &mdoc.MDDLSchema{
				Format:  "mso_mdoc",
				DocType: "org.iso.18013.5.1.mDL",
			},
		},
	}
	metadata, err := cfg.Generate(context.Background(), "https://issuer.sunet.se", credMeta)
	require.NoError(t, err)
	credConfig, exists := metadata.CredentialConfigurationsSupported["test_mdl"]
	require.True(t, exists)
	assert.Equal(t, "org.iso.18013.5.1.mDL", credConfig.Doctype)
	assert.Empty(t, credConfig.VCT, "mso_mdoc scopes must not set VCT")
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
	assert.Equal(t, "urn:eudi:ehic:1", ehicConfig.VCT)

	diplomaConfig := metadata.CredentialConfigurationsSupported["diploma"]
	assert.Equal(t, "vc+sd-jwt", diplomaConfig.Format) // default
	assert.Equal(t, "urn:eudi:diploma:1", diplomaConfig.VCT)
}

func TestIssuerMetadata_Generate_DisclosurePolicy(t *testing.T) {
	cfg := &IssuerMetadata{}
	baseURL := "https://issuer.sunet.se"

	tests := []struct {
		name         string
		policy       *openid4vci.EmbeddedDisclosurePolicy
		expectPolicy bool
		expectType   string
		expectRPs    []string
		expectRoots  []string
	}{
		{
			name:         "no policy configured omits field",
			policy:       nil,
			expectPolicy: false,
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

	// Both the VCTM/SD-JWT and mso_mdoc/MDDL branches of Generate must honor
	// the opt-in contract: an unset policy is omitted, and a set policy is
	// propagated verbatim.
	formats := []struct {
		name  string
		build func(policy *openid4vci.EmbeddedDisclosurePolicy) *CredentialMetadata
	}{
		{
			name: "dc+sd-jwt",
			build: func(policy *openid4vci.EmbeddedDisclosurePolicy) *CredentialMetadata {
				return &CredentialMetadata{
					VCTM:             &sdjwtvc.VCTM{VCT: baseURL + "/type-metadata/test_cred"},
					VCTURL:           baseURL + "/type-metadata/test_cred",
					Format:           "dc+sd-jwt",
					DisclosurePolicy: policy,
				}
			},
		},
		{
			name: "mso_mdoc",
			build: func(policy *openid4vci.EmbeddedDisclosurePolicy) *CredentialMetadata {
				return &CredentialMetadata{
					Format: "mso_mdoc",
					MDDL: &mdoc.MDDLSchema{
						Format:  "mso_mdoc",
						DocType: "org.iso.18013.5.1.mDL",
					},
					DisclosurePolicy: policy,
				}
			},
		},
	}

	for _, f := range formats {
		t.Run(f.name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					credMeta := map[string]*CredentialMetadata{
						"test_cred": f.build(tt.policy),
					}

					ctx := context.Background()
					metadata, err := cfg.Generate(ctx, baseURL, credMeta)
					require.NoError(t, err)

					credConfig := metadata.CredentialConfigurationsSupported["test_cred"]

					if !tt.expectPolicy {
						assert.Nil(t, credConfig.DisclosurePolicy)
						// omitempty must keep the field out of the marshalled metadata too
						js, err := json.Marshal(credConfig)
						require.NoError(t, err)
						assert.NotContains(t, string(js), "disclosure_policy")
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
		})
	}
}
