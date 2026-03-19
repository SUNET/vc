package openid4vci

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
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
			CredentialMetadata: &CredentialMetadata{
				Display: []CredentialMetadataDisplay{
					{
						Name:            "PID SD-JWT VC",
						Locale:          "en-US",
						Description:     "Person Identification Data",
						BackgroundColor: "#1b263b",
						BackgroundImage: &MetadataBackgroundImage{
							URI: "http://vc_dev_apigw:8080/images/background-image.png",
						},
						TextColor: "#FFFFFF",
					},
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
			CredentialMetadata: &CredentialMetadata{
				Display: []CredentialMetadataDisplay{
					{
						Name:            "PID - MDOC",
						Locale:          "en-US",
						Description:     "Person Identification Data",
						BackgroundColor: "#4CC3DD",
						BackgroundImage: &MetadataBackgroundImage{
							URI: "http://vc_dev_apigw:8080/images/background-image.png",
						},
						TextColor: "#000000",
					},
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
			CredentialMetadata: &CredentialMetadata{
				Display: []CredentialMetadataDisplay{
					{
						Name:   "Bachelor Diploma - SD-JWT VC",
						Locale: "en-US",
						Logo: &MetadataLogo{
							URI: "http://vc_dev_apigw:8080/images/diploma-logo.png",
						},
						BackgroundColor: "#b1d3ff",
						BackgroundImage: &MetadataBackgroundImage{
							URI: "http://vc_dev_apigw:8080/images/background-image.png",
						},
						TextColor: "#ffffff",
					},
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
			CredentialMetadata: &CredentialMetadata{
				Display: []CredentialMetadataDisplay{
					{
						Name:            "EHIC - SD-JWT VC",
						Locale:          "en-US",
						Description:     "European Health Insurance Card",
						BackgroundColor: "#1b263b",
						BackgroundImage: &MetadataBackgroundImage{
							URI: "http://vc_dev_apigw:8080/images/background-image.png",
						},
						TextColor: "#FFFFFF",
					},
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
			CredentialMetadata: &CredentialMetadata{
				Display: []CredentialMetadataDisplay{
					{
						Name:            "POR - SD-JWT VC",
						Locale:          "en-US",
						Description:     "Power of Representation",
						BackgroundColor: "#c3b25d",
						BackgroundImage: &MetadataBackgroundImage{
							URI: "http://vc_dev_apigw:8080/images/background-image.png",
						},
						TextColor: "#363531",
					},
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

			// ensure the signed claim does not have signed_metadata in it self
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
		Display: []MetadataDisplay{
			{
				Name:   "European Health Insurance Card",
				Locale: "en-US",
				Logo:   nil,
			},
			{
				Name:   "Carte européenne d'assurance maladie",
				Locale: "fr-FR",
				Logo:   nil,
			},
		},
		CredentialConfigurationsSupported: map[string]CredentialConfigurationsSupported{
			"EHICCredential": {
				VCT:                                  "EHICCredential",
				Format:                               "vc+sd-jwt",
				Scope:                                "EHIC",
				CryptographicBindingMethodsSupported: []string{"did:example"},
				CredentialSigningAlgValuesSupported:  []any{"ES256"},
				CredentialDefinition: &CredentialDefinition{
					Type: []string{"VerifiableCredential", "EHICCredential"},
				},
				CredentialMetadata: &CredentialMetadata{
					Display: []CredentialMetadataDisplay{
						{
							Name:   "European Health Insurance Card Credential",
							Locale: "en-US",
							Logo: &MetadataLogo{
								URI:     "https://example.edu/public/logo.png",
								AltText: "a square logo of a EHIC card",
							},
							Description:     "",
							BackgroundColor: "#12107c",
							BackgroundImage: &MetadataBackgroundImage{
								URI: "https://example.edu/public/background.png",
							},
							TextColor: "#FFFFFF",
						},
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

func TestCredentialIssuerMetadataParameters_MarshalRoundTrip(t *testing.T) {
	// Marshal mockIssuerMetadata to JSON
	marshaledData, err := json.Marshal(mockIssuerMetadata)
	require.NoError(t, err)

	// Unmarshal back into struct
	var roundTripped CredentialIssuerMetadataParameters
	err = json.Unmarshal(marshaledData, &roundTripped)
	require.NoError(t, err)

	// Verify key fields survived the round trip
	assert.Equal(t, mockIssuerMetadata.CredentialIssuer, roundTripped.CredentialIssuer)
	assert.Equal(t, mockIssuerMetadata.CredentialEndpoint, roundTripped.CredentialEndpoint)
	assert.Len(t, roundTripped.CredentialConfigurationsSupported, len(mockIssuerMetadata.CredentialConfigurationsSupported))

	for configID, origConfig := range mockIssuerMetadata.CredentialConfigurationsSupported {
		rtConfig, exists := roundTripped.CredentialConfigurationsSupported[configID]
		require.True(t, exists, "Configuration %s should survive round trip", configID)
		assert.Equal(t, origConfig.Format, rtConfig.Format, "%s: format mismatch", configID)
		assert.Equal(t, origConfig.Scope, rtConfig.Scope, "%s: scope mismatch", configID)
		assert.Equal(t, origConfig.VCT, rtConfig.VCT, "%s: vct mismatch", configID)
		assert.Equal(t, origConfig.Doctype, rtConfig.Doctype, "%s: doctype mismatch", configID)
	}
}

func TestCredentialIssuerMetadataParameters_OpenID4VCI_Compliance(t *testing.T) {
	metadata := mockIssuerMetadata

	t.Run("Section 12.2.4 - Required Parameters", func(t *testing.T) {
		assert.NotEmpty(t, metadata.CredentialIssuer,
			"credential_issuer is REQUIRED per Section 12.2.4")
		assert.NotEmpty(t, metadata.CredentialEndpoint,
			"credential_endpoint is REQUIRED per Section 12.2.4")
		assert.NotEmpty(t, metadata.CredentialConfigurationsSupported,
			"credential_configurations_supported is REQUIRED per Section 12.2.4")
	})

	t.Run("Section 12.2.4 - Optional Parameters", func(t *testing.T) {
		_ = metadata.AuthorizationServers
		_ = metadata.DeferredCredentialEndpoint
		_ = metadata.NotificationEndpoint
		_ = metadata.CredentialResponseEncryption
		_ = metadata.BatchCredentialIssuance
		_ = metadata.Display
	})

	t.Run("Credential Format Invariants", func(t *testing.T) {
		for configID, config := range metadata.CredentialConfigurationsSupported {
			switch config.Format {
			case "dc+sd-jwt", "vc+sd-jwt":
				assert.NotEmpty(t, config.VCT,
					"%s: vct should be present for SD-JWT format", configID)
			case "mso_mdoc":
				assert.NotEmpty(t, config.Doctype,
					"%s: doctype should be present for mso_mdoc format", configID)
				assert.Empty(t, config.VCT,
					"%s: mso_mdoc format should not have vct parameter", configID)
			}
		}
	})

	t.Run("Cryptographic Binding Methods", func(t *testing.T) {
		for configID, config := range metadata.CredentialConfigurationsSupported {
			assert.NotEmpty(t, config.CryptographicBindingMethodsSupported,
				"Configuration %s should specify cryptographic binding methods", configID)
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
			for proofType, proofSpec := range config.ProofTypesSupported {
				assert.NotEmpty(t, proofSpec.ProofSigningAlgValuesSupported,
					"Configuration %s proof type %s should have proof_signing_alg_values_supported",
					configID, proofType)
			}
		}
	})

	t.Run("Display Properties", func(t *testing.T) {
		if len(metadata.Display) > 0 {
			for _, display := range metadata.Display {
				if display.Locale != "" {
					assert.Regexp(t, `^[a-z]{2}(-[A-Z]{2})?$`, display.Locale,
						"Locale should be BCP47 compliant")
				}
			}
		}
		for configID, config := range metadata.CredentialConfigurationsSupported {
			if config.CredentialMetadata != nil && len(config.CredentialMetadata.Display) > 0 {
				assert.NotEmpty(t, config.CredentialMetadata.Display[0].Name,
					"Configuration %s display should have a name", configID)
				if config.CredentialMetadata.Display[0].Locale != "" {
					assert.Regexp(t, `^[a-z]{2}(-[A-Z]{2})?$`, config.CredentialMetadata.Display[0].Locale,
						"Configuration %s display locale should be BCP47 compliant", configID)
				}
			}
		}
	})

	t.Run("Appendix A.2 - ISO mdoc Format", func(t *testing.T) {
		for configID, config := range metadata.CredentialConfigurationsSupported {
			if config.Format != "mso_mdoc" {
				continue
			}
			t.Run(configID, func(t *testing.T) {
				assert.NotEmpty(t, config.Doctype,
					"mso_mdoc format requires doctype parameter per Appendix A.2.1")
				assert.Empty(t, config.VCT,
					"mso_mdoc format should not have vct parameter")
				assert.Contains(t, config.CryptographicBindingMethodsSupported, "cose_key",
					"mso_mdoc format should support cose_key binding method")
				assert.NotEmpty(t, config.CredentialSigningAlgValuesSupported,
					"Should have credential signing algorithms")
				require.NotNil(t, config.CredentialMetadata, "credential_metadata should not be nil")
				assert.NotEmpty(t, config.CredentialMetadata.Display, "Should have display properties")
				assert.NotEmpty(t, config.CredentialMetadata.Display[0].Name, "Display should have a name")
			})
		}
	})
}

func TestCredentialConfigurationsSupported_StructureCompliance(t *testing.T) {
	for configID, config := range mockIssuerMetadata.CredentialConfigurationsSupported {
		t.Run(configID, func(t *testing.T) {
			assert.NotEmpty(t, config.Format, "format is REQUIRED")

			switch config.Format {
			case "dc+sd-jwt", "vc+sd-jwt":
				assert.NotEmpty(t, config.VCT, "vct should be present for SD-JWT format")
			case "mso_mdoc":
				assert.NotEmpty(t, config.Doctype, "doctype should be present for mso_mdoc format")
			default:
				t.Errorf("Unknown format: %s", config.Format)
			}

			if len(config.CryptographicBindingMethodsSupported) > 0 {
				assert.NotEmpty(t, config.ProofTypesSupported,
					"proof_types_supported should be present when cryptographic binding is used")
			}
		})
	}
}
