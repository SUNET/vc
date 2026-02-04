package openid4vci

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"vc/pkg/pki"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
	"gotest.tools/v3/golden"
)

var mockIssuerMetadata = &CredentialIssuerMetadataParameters{
	CredentialIssuer:   "http://vc_dev_apigw:8080",
	CredentialEndpoint: "http://vc_dev_apigw:8080/credential",
	Display: []MetadataDisplay{
		{
			Name:   "SUNET wwWallet Issuer",
			Locale: "en-US",
		},
	},
	CredentialConfigurationsSupported: map[string]CredentialConfigurationsSupported{
		"urn:eudi:pid:1": {
			VCT:                                  "urn:eudi:pid:1",
			Format:                               "vc+sd-jwt",
			Scope:                                "pid:sd_jwt_vc",
			CryptographicBindingMethodsSupported: []string{"jwk"},
			CredentialSigningAlgValuesSupported:  []any{"ES256"},
			ProofTypesSupported: map[string]ProofsTypesSupported{
				"jwt": {
					ProofSigningAlgValuesSupported: []string{"ES256"},
				},
			},
			Display: []CredentialMetadataDisplay{
				{
					Name:            "PID SD-JWT VC",
					Locale:          "en-US",
					Description:     "Person Identification Data",
					BackgroundColor: "#1b263b",
					BackgroundImage: MetadataBackgroundImage{
						URI: "http://vc_dev_apigw:8080/images/background-image.png",
					},
					TextColor: "#FFFFFF",
				},
			},
		},
		"eu.europa.ec.eudi.pid.1": {
			Format:                               "mso_mdoc",
			Scope:                                "pid:mso_mdoc",
			Doctype:                              "eu.europa.ec.eudi.pid.1",
			CryptographicBindingMethodsSupported: []string{"cose_key"},
			CredentialSigningAlgValuesSupported:  []any{float64(-7)},
			ProofTypesSupported: map[string]ProofsTypesSupported{
				"jwt": {
					ProofSigningAlgValuesSupported: []string{"ES256"},
				},
			},
			Display: []CredentialMetadataDisplay{
				{
					Name:            "PID - MDOC",
					Locale:          "en-US",
					Description:     "Person Identification Data",
					BackgroundColor: "#4CC3DD",
					BackgroundImage: MetadataBackgroundImage{
						URI: "http://vc_dev_apigw:8080/images/background-image.png",
					},
					TextColor: "#000000",
				},
			},
		},
		"urn:credential:diploma": {
			VCT:                                  "urn:credential:diploma",
			Format:                               "vc+sd-jwt",
			Scope:                                "diploma",
			CryptographicBindingMethodsSupported: []string{"jwk"},
			CredentialSigningAlgValuesSupported:  []any{"ES256"},
			ProofTypesSupported: map[string]ProofsTypesSupported{
				"jwt": {
					ProofSigningAlgValuesSupported: []string{"ES256"},
				},
			},
			Display: []CredentialMetadataDisplay{
				{
					Name:   "Bachelor Diploma - SD-JWT VC",
					Locale: "en-US",
					Logo: MetadataLogo{
						URI: "http://vc_dev_apigw:8080/images/diploma-logo.png",
					},
					BackgroundColor: "#b1d3ff",
					BackgroundImage: MetadataBackgroundImage{
						URI: "http://vc_dev_apigw:8080/images/background-image.png",
					},
					TextColor: "#ffffff",
				},
			},
		},
		"urn:credential:ehic": {
			VCT:                                  "urn:credential:ehic",
			Format:                               "vc+sd-jwt",
			Scope:                                "ehic",
			CryptographicBindingMethodsSupported: []string{"jwk"},
			CredentialSigningAlgValuesSupported:  []any{"ES256"},
			ProofTypesSupported: map[string]ProofsTypesSupported{
				"jwt": {
					ProofSigningAlgValuesSupported: []string{"ES256"},
				},
			},
			Display: []CredentialMetadataDisplay{
				{
					Name:            "EHIC - SD-JWT VC",
					Locale:          "en-US",
					Description:     "European Health Insurance Card",
					BackgroundColor: "#1b263b",
					BackgroundImage: MetadataBackgroundImage{
						URI: "http://vc_dev_apigw:8080/images/background-image.png",
					},
					TextColor: "#FFFFFF",
				},
			},
		},
		"urn:eu.europa.ec.eudi:por:1": {
			VCT:                                  "urn:eu.europa.ec.eudi:por:1",
			Format:                               "vc+sd-jwt",
			Scope:                                "por:sd_jwt_vc",
			CryptographicBindingMethodsSupported: []string{"jwk"},
			CredentialSigningAlgValuesSupported:  []any{"ES256"},
			ProofTypesSupported: map[string]ProofsTypesSupported{
				"jwt": {
					ProofSigningAlgValuesSupported: []string{"ES256"},
				},
			},
			Display: []CredentialMetadataDisplay{
				{
					Name:            "POR - SD-JWT VC",
					Locale:          "en-US",
					Description:     "Power of Representation",
					BackgroundColor: "#c3b25d",
					BackgroundImage: MetadataBackgroundImage{
						URI: "http://vc_dev_apigw:8080/images/background-image.png",
					},
					TextColor: "#363531",
				},
			},
		},
	},
}

func TestValidateMetadata(t *testing.T) {
	tts := []struct {
		name           string
		goldenFileName string
		want           error
	}{
		{
			name:           "test",
			goldenFileName: "metadata_response.golden",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			fileByte := golden.Get(t, tt.goldenFileName)

			metadata := &CredentialIssuerMetadataParameters{}
			err := json.Unmarshal(fileByte, metadata)
			assert.NoError(t, err)

			if got := CheckSimple(metadata); got != nil {
				t.Log(got)
				t.FailNow()
			}
		})
	}
}

func TestMarshalMetadata(t *testing.T) {
	tts := []struct {
		name           string
		goldenFileName string
		want           *CredentialIssuerMetadataParameters
	}{
		{
			name:           "test",
			goldenFileName: "issuer_metadata_json.golden",
			want:           mockIssuerMetadata,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			fileByte := golden.Get(t, tt.goldenFileName)

			got := &CredentialIssuerMetadataParameters{}
			err := json.Unmarshal(fileByte, got)
			assert.NoError(t, err)

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSignIssuerMetadata(t *testing.T) {
	tts := []struct {
		name           string
		issuerMetadata *CredentialIssuerMetadataParameters
	}{
		{
			name:           "test",
			issuerMetadata: mockIssuerMetadata,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			metadata := tt.issuerMetadata

			signingKey, cert := mockGenerateECDSAKey(t)
			pubKey := signingKey.Public()

			// Create pki.Signer
			signer, err := pki.NewSoftwareSigner(signingKey, "test-key-id")
			require.NoError(t, err)

			metadataWithSignature, err := metadata.Sign(context.Background(), signer, []string{cert})
			assert.NoError(t, err)

			assert.NotEmpty(t, metadataWithSignature)

			claims := jwt.MapClaims{}

			token, err := jwt.ParseWithClaims(metadataWithSignature.SignedMetadata, claims, func(token *jwt.Token) (any, error) {
				return pubKey.(*ecdsa.PublicKey), nil
			})
			assert.NoError(t, err)

			assert.True(t, token.Valid)

			// ensure the singed claim does not have signed_metadata in it self
			assert.Empty(t, claims["signed_metadata"])

			assert.Len(t, token.Header["x5c"], 1)
		})
	}
}

func TestMarshal(t *testing.T) {
	want := &CredentialIssuerMetadataParameters{
		CredentialIssuer:           "http://vc_dev_apigw:8080",
		CredentialEndpoint:         "http://vc_dev_apigw:8080/credential",
		AuthorizationServers:       []string{"http://vc_dev_apigw:8080"},
		DeferredCredentialEndpoint: "http://vc_dev_apigw:8080/deferred_credential",
		NotificationEndpoint:       "http://vc_dev_apigw:8080/notification",
		CredentialResponseEncryption: &MetadataCredentialResponseEncryption{
			AlgValuesSupported: []string{"ECDH-ES"},
			EncValuesSupported: []string{"A128GCM"},
			EncryptionRequired: false,
		},
		SignedMetadata: "",
		Display: []MetadataDisplay{
			{
				Name:   "European Health Insurance Card",
				Locale: "en-US",
				Logo:   MetadataLogo{},
			},
			{
				Name:   "Carte européenne d'assurance maladie",
				Locale: "fr-FR",
				Logo:   MetadataLogo{},
			},
		},
		CredentialConfigurationsSupported: map[string]CredentialConfigurationsSupported{
			"EHICCredential": {
				VCT:                                  "EHICCredential",
				Format:                               "vc+sd-jwt",
				Scope:                                "EHIC",
				CryptographicBindingMethodsSupported: []string{"did:example"},
				CredentialSigningAlgValuesSupported:  []any{"ES256"},
				CredentialDefinition: CredentialDefinition{
					Type: []string{"VerifiableCredential", "EHICCredential"},
				},
				Display: []CredentialMetadataDisplay{
					{
						Name:   "European Health Insurance Card Credential",
						Locale: "en-US",
						Logo: MetadataLogo{
							URI:     "https://example.edu/public/logo.png",
							AltText: "a square logo of a EHIC card",
						},
						Description:     "",
						BackgroundColor: "#12107c",
						BackgroundImage: MetadataBackgroundImage{
							URI: "https://example.edu/public/background.png",
						},
						TextColor: "#FFFFFF",
					},
				},
			},
		},
	}

	t.Run("yaml", func(t *testing.T) {
		fileByte := golden.Get(t, "metadata_issuing_ehic_yaml.golden")

		metadata := &CredentialIssuerMetadataParameters{}
		err := yaml.Unmarshal(fileByte, metadata)
		assert.NoError(t, err)

		assert.Equal(t, want, metadata)
	})

	t.Run("json", func(t *testing.T) {
		fileByte := golden.Get(t, "metadata_issuing_ehic_json.golden")

		metadata := &CredentialIssuerMetadataParameters{}
		err := json.Unmarshal(fileByte, metadata)
		assert.NoError(t, err)

		assert.Equal(t, want, metadata)
	})

}

func TestCredentialIssuerMetadataParameters_UnmarshalFromFile(t *testing.T) {
	// Read the actual issuer_metadata.json file
	metadataPath := filepath.Join("..", "..", "metadata", "issuer_metadata.json")
	data, err := os.ReadFile(metadataPath)
	require.NoError(t, err, "Failed to read issuer_metadata.json")

	// Unmarshal into our Go struct
	var metadata CredentialIssuerMetadataParameters
	err = json.Unmarshal(data, &metadata)
	require.NoError(t, err, "Failed to unmarshal issuer_metadata.json into CredentialIssuerMetadataParameters")

	// Validate required fields
	t.Run("Required Fields", func(t *testing.T) {
		assert.NotEmpty(t, metadata.CredentialIssuer, "credential_issuer is required")
		assert.Equal(t, "http://vc_dev_apigw:8080", metadata.CredentialIssuer)

		assert.NotEmpty(t, metadata.CredentialEndpoint, "credential_endpoint is required")
		assert.Equal(t, "http://vc_dev_apigw:8080/credential", metadata.CredentialEndpoint)

		assert.NotEmpty(t, metadata.CredentialConfigurationsSupported, "credential_configurations_supported is required")
		assert.Len(t, metadata.CredentialConfigurationsSupported, 6, "Expected 6 credential configurations")
	})

	// Validate display properties
	t.Run("Display Properties", func(t *testing.T) {
		assert.Len(t, metadata.Display, 1, "Expected 1 display entry")
		assert.Equal(t, "SUNET dev Issuer (vc project)", metadata.Display[0].Name)
		assert.Equal(t, "en-US", metadata.Display[0].Locale)
	})

	// Validate credential configurations
	t.Run("Credential Configurations", func(t *testing.T) {
		expectedConfigs := []string{
			"diploma",
			"pid_1_5",
			"pid_1_5_mdoc",
			"pid_1_8",
			"ehic",
			"pda1",
		}

		for _, configID := range expectedConfigs {
			t.Run(configID, func(t *testing.T) {
				config, exists := metadata.CredentialConfigurationsSupported[configID]
				require.True(t, exists, "Configuration %s should exist", configID)

				// Validate format
				assert.Contains(t, []string{"dc+sd-jwt", "mso_mdoc"}, config.Format,
					"Credential should use a valid format (dc+sd-jwt or mso_mdoc)")

				// Validate scope
				assert.NotEmpty(t, config.Scope, "Scope should not be empty")

				// For SD-JWT format, validate VCT; for mdoc, validate doctype
				if config.Format == "dc+sd-jwt" {
					assert.NotEmpty(t, config.VCT, "VCT should not be empty for SD-JWT format")
				} else if config.Format == "mso_mdoc" {
					assert.NotEmpty(t, config.Doctype, "Doctype should not be empty for mso_mdoc format")
				}

				// Validate cryptographic binding methods
				if config.Format == "dc+sd-jwt" {
					assert.Contains(t, config.CryptographicBindingMethodsSupported, "jwk",
						"SD-JWT should support jwk binding method")
				} else if config.Format == "mso_mdoc" {
					assert.Contains(t, config.CryptographicBindingMethodsSupported, "cose_key",
						"mso_mdoc should support cose_key binding method")
				}

				// Validate signing algorithms
				assert.NotEmpty(t, config.CredentialSigningAlgValuesSupported,
					"Should have credential signing algorithms")

				// Validate proof types
				assert.NotEmpty(t, config.ProofTypesSupported, "Proof types should not be empty")
				jwtProof, hasJWT := config.ProofTypesSupported["jwt"]
				require.True(t, hasJWT, "Should support jwt proof type")
				assert.Contains(t, jwtProof.ProofSigningAlgValuesSupported, "ES256",
					"JWT proof should support ES256")

				// Validate display
				assert.NotEmpty(t, config.Display, "Display should not be empty")
				assert.NotEmpty(t, config.Display[0].Name, "Display name should not be empty")
				assert.NotEmpty(t, config.Display[0].Locale, "Display locale should not be empty")
			})
		}
	})

	// Validate specific credential configurations
	t.Run("Diploma Configuration", func(t *testing.T) {
		diploma, exists := metadata.CredentialConfigurationsSupported["diploma"]
		require.True(t, exists)

		assert.Equal(t, "diploma", diploma.Scope)
		assert.Equal(t, "urn:eudi:diploma:1", diploma.VCT)
		assert.Equal(t, "Bachelor Diploma - SD-JWT VC", diploma.Display[0].Name)
		assert.NotEmpty(t, diploma.Display[0].Logo.URI)
		assert.Equal(t, "#b1d3ff", diploma.Display[0].BackgroundColor)
		assert.Equal(t, "#ffffff", diploma.Display[0].TextColor)
	})

	t.Run("PID Configuration", func(t *testing.T) {
		pid, exists := metadata.CredentialConfigurationsSupported["pid_1_5"]
		require.True(t, exists)

		assert.Equal(t, "pid_1_5", pid.Scope)
		assert.Equal(t, "urn:eudi:pid:arf-1.5:1", pid.VCT)
		assert.Equal(t, "PID SD-JWT VC ARF 1.5", pid.Display[0].Name)
		assert.Equal(t, "Person Identification Data", pid.Display[0].Description)
		assert.NotEmpty(t, pid.Display[0].BackgroundImage.URI)
		assert.Equal(t, "#1b263b", pid.Display[0].BackgroundColor)
		assert.Equal(t, "#FFFFFF", pid.Display[0].TextColor)
	})

	t.Run("EHIC Configuration", func(t *testing.T) {
		ehic, exists := metadata.CredentialConfigurationsSupported["ehic"]
		require.True(t, exists)

		assert.Equal(t, "ehic", ehic.Scope)
		assert.Equal(t, "urn:eudi:ehic:1", ehic.VCT)
		assert.Equal(t, "EHIC - SD-JWT VC", ehic.Display[0].Name)
		assert.Equal(t, "European Health Insurance Card", ehic.Display[0].Description)
	})

	t.Run("PDA1 Configuration", func(t *testing.T) {
		pda1, exists := metadata.CredentialConfigurationsSupported["pda1"]
		require.True(t, exists)

		assert.Equal(t, "pda1", pda1.Scope)
		assert.Equal(t, "urn:eudi:pda1:1", pda1.VCT)
		assert.Equal(t, "PDA1 - SD-JWT VC", pda1.Display[0].Name)
		assert.Equal(t, "European Portable Document Application", pda1.Display[0].Description)
	})

	t.Run("PID 1.5 mDoc Configuration", func(t *testing.T) {
		pidMdoc, exists := metadata.CredentialConfigurationsSupported["pid_1_5_mdoc"]
		require.True(t, exists, "pid_1_5_mdoc configuration should exist")

		// Format should be mso_mdoc
		assert.Equal(t, "mso_mdoc", pidMdoc.Format)

		// Should have doctype instead of VCT
		assert.Equal(t, "eu.europa.ec.eudi.pid.1", pidMdoc.Doctype)
		assert.Empty(t, pidMdoc.VCT, "mso_mdoc format should not have vct")

		// Scope can be shared with SD-JWT version
		assert.Equal(t, "pid_1_5", pidMdoc.Scope)

		// Binding method should be cose_key for mso_mdoc
		assert.Contains(t, pidMdoc.CryptographicBindingMethodsSupported, "cose_key")

		// Display properties
		assert.Equal(t, "PID mDoc ARF 1.5", pidMdoc.Display[0].Name)
		assert.Equal(t, "Person Identification Data (ISO 18013-5 mdoc)", pidMdoc.Display[0].Description)
		assert.Equal(t, "#1b263b", pidMdoc.Display[0].BackgroundColor)
		assert.Equal(t, "#FFFFFF", pidMdoc.Display[0].TextColor)
	})
}

func TestCredentialIssuerMetadataParameters_MarshalRoundTrip(t *testing.T) {
	// Read original JSON
	metadataPath := filepath.Join("..", "..", "metadata", "issuer_metadata.json")
	originalData, err := os.ReadFile(metadataPath)
	require.NoError(t, err)

	// Unmarshal into struct
	var metadata CredentialIssuerMetadataParameters
	err = json.Unmarshal(originalData, &metadata)
	require.NoError(t, err)

	// Marshal back to JSON
	marshaledData, err := json.Marshal(&metadata)
	require.NoError(t, err)

	// Unmarshal both to maps for comparison (to ignore field ordering)
	var originalMap map[string]any
	var marshaledMap map[string]any

	err = json.Unmarshal(originalData, &originalMap)
	require.NoError(t, err)

	err = json.Unmarshal(marshaledData, &marshaledMap)
	require.NoError(t, err)

	// Compare key fields
	assert.Equal(t, originalMap["credential_issuer"], marshaledMap["credential_issuer"])
	assert.Equal(t, originalMap["credential_endpoint"], marshaledMap["credential_endpoint"])

	// Verify credential configurations are preserved
	originalConfigs := originalMap["credential_configurations_supported"].(map[string]any)
	marshaledConfigs := marshaledMap["credential_configurations_supported"].(map[string]any)
	assert.Equal(t, len(originalConfigs), len(marshaledConfigs), "Should have same number of configurations")
}

func TestCredentialIssuerMetadataParameters_OpenID4VCI_Compliance(t *testing.T) {
	metadataPath := filepath.Join("..", "..", "metadata", "issuer_metadata.json")
	data, err := os.ReadFile(metadataPath)
	require.NoError(t, err)

	var metadata CredentialIssuerMetadataParameters
	err = json.Unmarshal(data, &metadata)
	require.NoError(t, err)

	t.Run("Section 12.2.4 - Required Parameters", func(t *testing.T) {
		// credential_issuer: REQUIRED
		assert.NotEmpty(t, metadata.CredentialIssuer,
			"credential_issuer is REQUIRED per Section 12.2.4")

		// credential_endpoint: REQUIRED
		assert.NotEmpty(t, metadata.CredentialEndpoint,
			"credential_endpoint is REQUIRED per Section 12.2.4")

		// credential_configurations_supported: REQUIRED
		assert.NotEmpty(t, metadata.CredentialConfigurationsSupported,
			"credential_configurations_supported is REQUIRED per Section 12.2.4")
	})

	t.Run("Section 12.2.4 - Optional Parameters", func(t *testing.T) {
		// These should be allowed to be empty/nil since they're OPTIONAL
		// Just verify the fields exist and can be accessed
		_ = metadata.AuthorizationServers
		_ = metadata.DeferredCredentialEndpoint
		_ = metadata.NotificationEndpoint
		_ = metadata.CredentialResponseEncryption
		_ = metadata.BatchCredentialIssuance
		_ = metadata.SignedMetadata
		_ = metadata.Display
	})

	t.Run("Credential Format - SD-JWT VC", func(t *testing.T) {
		// Count credentials by format
		sdJwtCount := 0
		mdocCount := 0
		for _, config := range metadata.CredentialConfigurationsSupported {
			switch config.Format {
			case "dc+sd-jwt":
				sdJwtCount++
				// For SD-JWT VC format, vct parameter should be present
				assert.NotEmpty(t, config.VCT,
					"vct should be present for dc+sd-jwt format")
			case "mso_mdoc":
				mdocCount++
				// For mso_mdoc format, doctype parameter should be present
				assert.NotEmpty(t, config.Doctype,
					"doctype should be present for mso_mdoc format")
			}
		}
		assert.Equal(t, 5, sdJwtCount, "Should have 5 SD-JWT VC credentials")
		assert.Equal(t, 1, mdocCount, "Should have 1 mso_mdoc credential")
	})

	t.Run("Cryptographic Binding Methods", func(t *testing.T) {
		for configID, config := range metadata.CredentialConfigurationsSupported {
			assert.NotEmpty(t, config.CryptographicBindingMethodsSupported,
				"Configuration %s should specify cryptographic binding methods", configID)

			// Validate that binding methods are recognized values
			for _, method := range config.CryptographicBindingMethodsSupported {
				assert.Contains(t, []string{"jwk", "cose_key"}, method,
					"Configuration %s has unrecognized binding method: %s", configID, method)
			}
		}
	})

	t.Run("Proof Types", func(t *testing.T) {
		for configID, config := range metadata.CredentialConfigurationsSupported {
			assert.NotEmpty(t, config.ProofTypesSupported,
				"Configuration %s should specify proof types", configID)

			// Validate proof_signing_alg_values_supported is present for each proof type
			for proofType, proofSpec := range config.ProofTypesSupported {
				assert.NotEmpty(t, proofSpec.ProofSigningAlgValuesSupported,
					"Configuration %s proof type %s should have proof_signing_alg_values_supported",
					configID, proofType)
			}
		}
	})

	t.Run("Display Properties", func(t *testing.T) {
		// Issuer-level display
		if len(metadata.Display) > 0 {
			for _, display := range metadata.Display {
				if display.Locale != "" {
					// Locale should be BCP47 compliant (basic check)
					assert.Regexp(t, `^[a-z]{2}(-[A-Z]{2})?$`, display.Locale,
						"Locale should be BCP47 compliant")
				}
			}
		}

		// Credential-level display
		for configID, config := range metadata.CredentialConfigurationsSupported {
			if len(config.Display) > 0 {
				assert.NotEmpty(t, config.Display[0].Name,
					"Configuration %s display should have a name", configID)

				if config.Display[0].Locale != "" {
					assert.Regexp(t, `^[a-z]{2}(-[A-Z]{2})?$`, config.Display[0].Locale,
						"Configuration %s display locale should be BCP47 compliant", configID)
				}
			}
		}
	})

	t.Run("Appendix A.2 - ISO mdoc Format", func(t *testing.T) {
		// Find all mso_mdoc configurations
		mdocConfigs := make(map[string]CredentialConfigurationsSupported)
		for configID, config := range metadata.CredentialConfigurationsSupported {
			if config.Format == "mso_mdoc" {
				mdocConfigs[configID] = config
			}
		}

		require.NotEmpty(t, mdocConfigs, "Should have at least one mso_mdoc configuration")

		for configID, config := range mdocConfigs {
			t.Run(configID, func(t *testing.T) {
				// doctype: REQUIRED for mso_mdoc format (Appendix A.2.1)
				assert.NotEmpty(t, config.Doctype,
					"mso_mdoc format requires doctype parameter per Appendix A.2.1")

				// VCT should NOT be present for mso_mdoc (that's for SD-JWT)
				assert.Empty(t, config.VCT,
					"mso_mdoc format should not have vct parameter")

				// Cryptographic binding: should use cose_key
				assert.Contains(t, config.CryptographicBindingMethodsSupported, "cose_key",
					"mso_mdoc format should support cose_key binding method")

				// Credential signing algorithms should use COSE algorithm identifiers
				// -7 = ES256 in COSE
				assert.NotEmpty(t, config.CredentialSigningAlgValuesSupported,
					"Should have credential signing algorithms")

				// Validate display properties
				assert.NotEmpty(t, config.Display, "Should have display properties")
				assert.NotEmpty(t, config.Display[0].Name, "Display should have a name")
			})
		}
	})
}

func TestCredentialConfigurationsSupported_StructureCompliance(t *testing.T) {
	metadataPath := filepath.Join("..", "..", "metadata", "issuer_metadata.json")
	data, err := os.ReadFile(metadataPath)
	require.NoError(t, err)

	var metadata CredentialIssuerMetadataParameters
	err = json.Unmarshal(data, &metadata)
	require.NoError(t, err)

	for configID, config := range metadata.CredentialConfigurationsSupported {
		t.Run(configID, func(t *testing.T) {
			// format: REQUIRED
			assert.NotEmpty(t, config.Format, "format is REQUIRED")

			// Format-specific requirements
			switch config.Format {
			case "dc+sd-jwt":
				// vct should be present (Appendix A.3.2)
				assert.NotEmpty(t, config.VCT, "vct should be present for dc+sd-jwt format")
			case "mso_mdoc":
				// doctype should be present (Appendix A.2.1)
				assert.NotEmpty(t, config.Doctype, "doctype should be present for mso_mdoc format")
			default:
				t.Errorf("Unknown format: %s", config.Format)
			}

			// scope: OPTIONAL but present in our metadata
			if config.Scope != "" {
				assert.NotEmpty(t, config.Scope, "scope should not be empty string")
			}

			// cryptographic_binding_methods_supported: OPTIONAL
			// credential_signing_alg_values_supported: OPTIONAL
			// proof_types_supported: OPTIONAL but should be present if cryptographic binding is used

			// If cryptographic binding is specified, proof types should be too
			if len(config.CryptographicBindingMethodsSupported) > 0 {
				assert.NotEmpty(t, config.ProofTypesSupported,
					"proof_types_supported should be present when cryptographic binding is used")
			}
		})
	}
}
