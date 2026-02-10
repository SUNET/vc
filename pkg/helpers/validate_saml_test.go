package helpers

import (
	"testing"
	"vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateSAMLConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      model.SAMLConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "disabled config is valid",
			config: model.SAMLConfig{
				Enabled: false,
			},
			expectError: false,
		},
		{
			name: "valid MDQ configuration",
			config: model.SAMLConfig{
				Enabled:            true,
				EntityID:           "https://sp.example.com",
				MDQServer:          "https://md.example.org/entities/",
				CertificatePath:    "/pki/saml.crt",
				PrivateKeyPath:     "/pki/saml.key",
				ACSEndpoint:        "https://sp.example.com/acs",
				CredentialMappings: map[string]model.CredentialMapping{"pid": {}},
			},
			expectError: false,
		},
		{
			name: "valid static IdP with path",
			config: model.SAMLConfig{
				Enabled: true,
				StaticIDPMetadata: &model.StaticIDPConfig{
					EntityID:     "https://idp.example.com",
					MetadataPath: "/path/to/metadata.xml",
				},
				EntityID:           "https://sp.example.com",
				CertificatePath:    "/pki/saml.crt",
				PrivateKeyPath:     "/pki/saml.key",
				ACSEndpoint:        "https://sp.example.com/acs",
				CredentialMappings: map[string]model.CredentialMapping{"pid": {}},
			},
			expectError: false,
		},
		{
			name: "valid static IdP with URL",
			config: model.SAMLConfig{
				Enabled: true,
				StaticIDPMetadata: &model.StaticIDPConfig{
					EntityID:    "https://idp.example.com",
					MetadataURL: "https://idp.example.com/metadata",
				},
				EntityID:           "https://sp.example.com",
				CertificatePath:    "/pki/saml.crt",
				PrivateKeyPath:     "/pki/saml.key",
				ACSEndpoint:        "https://sp.example.com/acs",
				CredentialMappings: map[string]model.CredentialMapping{"pid": {}},
			},
			expectError: false,
		},
		{
			name: "enabled but no MDQ or static IdP",
			config: model.SAMLConfig{
				Enabled: true,
			},
			expectError: true,
			errorMsg:    "saml_metadata_source_required",
		},
		{
			name: "both MDQ and static IdP configured",
			config: model.SAMLConfig{
				Enabled:   true,
				MDQServer: "https://md.example.org/entities/",
				StaticIDPMetadata: &model.StaticIDPConfig{
					EntityID:     "https://idp.example.com",
					MetadataPath: "/path/to/metadata.xml",
				},
			},
			expectError: true,
			errorMsg:    "saml_metadata_source_exclusive",
		},
		{
			name: "static IdP without entityID",
			config: model.SAMLConfig{
				Enabled: true,
				StaticIDPMetadata: &model.StaticIDPConfig{
					MetadataPath: "/path/to/metadata.xml",
				},
			},
			expectError: true,
			errorMsg:    "required",
		},
		{
			name: "static IdP without metadata source",
			config: model.SAMLConfig{
				Enabled: true,
				StaticIDPMetadata: &model.StaticIDPConfig{
					EntityID: "https://idp.example.com",
				},
			},
			expectError: true,
			errorMsg:    "required_without",
		},
		{
			name: "static IdP with both path and URL",
			config: model.SAMLConfig{
				Enabled: true,
				StaticIDPMetadata: &model.StaticIDPConfig{
					EntityID:     "https://idp.example.com",
					MetadataPath: "/path/to/metadata.xml",
					MetadataURL:  "https://idp.example.com/metadata",
				},
			},
			expectError: true,
			errorMsg:    "excluded_with",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckSimple(tt.config)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
