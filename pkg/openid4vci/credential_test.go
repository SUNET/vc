package openid4vci

import (
	"testing"

	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"

	"github.com/stretchr/testify/assert"
)

var mockProofJWT ProofJWTToken = "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9wZW5pZDR2Y2ktcHJvb2Yrand0IiwiandrIjp7ImNydiI6IlAtMjU2IiwiZXh0Ijp0cnVlLCJrZXlfb3BzIjpbInZlcmlmeSJdLCJrdHkiOiJFQyIsIngiOiJ1aGZ3M3pyOWJBWTlERDV0QkN0RVVfOVdNaFdvTWFlYVVSNGY3U2dKQzlvIiwieSI6ImJZR2JlV2xWYlJrNktxT1hRX0VUeWxaZ3NKMDR0Nld5UTZiZFhYMHUxV0UifX0.eyJub25jZSI6IiIsImF1ZCI6Imh0dHBzOi8vdmMtaW50ZXJvcC0zLnN1bmV0LnNlIiwiaXNzIjoiMTAwMyIsImlhdCI6MTc1MTM2ODI1NX0.ri7zfnClkmVYFPRxV5IWiatmXHjmDNcd9FGJJNngUFjvDkVIfeYKr-bb_aUXU0DgkesIi8XvyKM149tlP-e6gA"

func TestCredentialValidation(t *testing.T) {
	tts := []struct {
		name                 string
		credentialRequest    *CredentialRequest
		authorizationDetails []AuthorizationDetailsParameter
		wantErr              bool
		errContains          string
	}{
		{
			name: "scope-based flow with credential_configuration_id",
			credentialRequest: &CredentialRequest{
				CredentialConfigurationID: "vc+ldp",
			},
			authorizationDetails: nil,
			wantErr:              false,
		},
		{
			name: "authorization_details flow with valid credential_identifier",
			credentialRequest: &CredentialRequest{
				CredentialIdentifier: "cred-id-1",
			},
			authorizationDetails: []AuthorizationDetailsParameter{
				{
					Type:                      "openid_credential",
					CredentialConfigurationID: "vc+ldp",
					CredentialIdentifiers:     []string{"cred-id-1"},
				},
			},
			wantErr: false,
		},
		{
			name: "authorization_details flow with unknown credential_identifier",
			credentialRequest: &CredentialRequest{
				CredentialIdentifier: "unknown-id",
			},
			authorizationDetails: []AuthorizationDetailsParameter{
				{
					Type:                      "openid_credential",
					CredentialConfigurationID: "vc+ldp",
					CredentialIdentifiers:     []string{"cred-id-1"},
				},
			},
			wantErr:     true,
			errContains: "not found in Token Response",
		},
		{
			name: "authorization_details flow without credential_identifier",
			credentialRequest: &CredentialRequest{
				CredentialConfigurationID: "vc+ldp",
			},
			authorizationDetails: []AuthorizationDetailsParameter{
				{
					Type:                      "openid_credential",
					CredentialConfigurationID: "vc+ldp",
					CredentialIdentifiers:     []string{"cred-id-1"},
				},
			},
			wantErr:     true,
			errContains: "credential_identifier is required",
		},
		{
			name: "authorization_details flow with both identifier and configuration_id",
			credentialRequest: &CredentialRequest{
				CredentialIdentifier:      "cred-id-1",
				CredentialConfigurationID: "vc+ldp",
			},
			authorizationDetails: []AuthorizationDetailsParameter{
				{
					Type:                      "openid_credential",
					CredentialConfigurationID: "vc+ldp",
					CredentialIdentifiers:     []string{"cred-id-1"},
				},
			},
			wantErr:     true,
			errContains: "credential_configuration_id must not be present",
		},
		{
			name: "scope-based flow without credential_configuration_id",
			credentialRequest: &CredentialRequest{
				CredentialIdentifier: "some-id",
			},
			authorizationDetails: nil,
			wantErr:              true,
			errContains:          "credential_configuration_id is required",
		},
		{
			name: "scope-based flow with both identifier and configuration_id",
			credentialRequest: &CredentialRequest{
				CredentialConfigurationID: "vc+ldp",
				CredentialIdentifier:      "some-id",
			},
			authorizationDetails: nil,
			wantErr:              true,
			errContains:          "credential_identifier must not be present",
		},
		{
			name: "credential_identifier matches second authorization_details entry",
			credentialRequest: &CredentialRequest{ // #nosec G101
				CredentialIdentifier: "cred-id-2",
			},
			authorizationDetails: []AuthorizationDetailsParameter{
				{
					Type:                      "openid_credential",
					CredentialConfigurationID: "config-a",
					CredentialIdentifiers:     []string{"cred-id-1"},
				},
				{
					Type:                      "openid_credential",
					CredentialConfigurationID: "config-b",
					CredentialIdentifiers:     []string{"cred-id-2", "cred-id-3"},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			err := tt.credentialRequest.Validate(ctx, tt.authorizationDetails)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHashAuthorizeToken(t *testing.T) {
	tts := []struct {
		name     string
		request  CredentialRequest
		expected string
	}{
		{
			name: "test",
			request: CredentialRequest{
				Authorization: "DPoP yRPOM7mz7sPllePuy3oka7k1uJtdy1q97zjxaT4y11I=",
			},
			expected: "dHN_VHc7eNSICfPTvtw4gr_8XIH7g91jo8_Bq2bmAcc",
		},
	}
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.request.HashAuthorizeToken()
			assert.Equal(t, tt.expected, got, "HashAuthorizeToken should return expected value")
		})
	}
}

func TestExtractJWK(t *testing.T) {
	tts := []struct {
		name string
		have *Proofs
		want *apiv1_issuer.Jwk
	}{
		{
			name: "test",
			have: &Proofs{
				JWT: []ProofJWTToken{mockProofJWT},
			},
			want: &apiv1_issuer.Jwk{
				Crv:    "P-256",
				Kty:    "EC",
				X:      "uhfw3zr9bAY9DD5tBCtEU_9WMhWoMaeaUR4f7SgJC9o",
				Y:      "bYGbeWlVbRk6KqOXQ_ETylZgsJ04t6WyQ6bdXX0u1WE",
				KeyOps: []string{"verify"},
				Ext:    true,
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.have.ExtractJWK()
			assert.NoError(t, err, "ExtractJWK should not return an error")
			assert.NotNil(t, got, "JWK should not be nil")
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestResolveCredentialFormat(t *testing.T) {
	tests := []struct {
		name        string
		request     *CredentialRequest
		metadata    *CredentialIssuerMetadataParameters
		authDetails []AuthorizationDetailsParameter
		wantFormat  string
		wantErr     bool
		errContains string
	}{
		{
			name: "resolve by credential_configuration_id",
			request: &CredentialRequest{ // #nosec G101
				CredentialConfigurationID: "pid_config",
			},
			metadata: &CredentialIssuerMetadataParameters{
				CredentialConfigurationsSupported: map[string]CredentialConfigurationsSupported{
					"pid_config": {
						Format: "dc+sd-jwt",
					},
				},
			},
			wantFormat: "dc+sd-jwt",
			wantErr:    false,
		},
		{
			name: "resolve by credential_identifier",
			request: &CredentialRequest{ // #nosec G101
				CredentialIdentifier: "ehic_identifier",
			},
			metadata: &CredentialIssuerMetadataParameters{
				CredentialConfigurationsSupported: map[string]CredentialConfigurationsSupported{
					"ehic_identifier": {
						Format: "mso_mdoc",
					},
				},
			},
			wantFormat: "mso_mdoc",
			wantErr:    false,
		},
		{
			name: "resolve credential_identifier via authorization_details mapping",
			request: &CredentialRequest{ // #nosec G101
				CredentialIdentifier: "f08b0aa2-d7aa-4334-8ab0-d6845a972e19",
			},
			metadata: &CredentialIssuerMetadataParameters{
				CredentialConfigurationsSupported: map[string]CredentialConfigurationsSupported{
					"pid_config": {
						Format: "dc+sd-jwt",
					},
				},
			},
			authDetails: []AuthorizationDetailsParameter{
				{
					Type:                      "openid_credential",
					CredentialConfigurationID: "pid_config",
					CredentialIdentifiers:     []string{"f08b0aa2-d7aa-4334-8ab0-d6845a972e19"},
				},
			},
			wantFormat: "dc+sd-jwt",
			wantErr:    false,
		},
		{
			name: "error for unknown credential_identifier",
			request: &CredentialRequest{
				CredentialIdentifier: "unknown_identifier",
			},
			metadata: &CredentialIssuerMetadataParameters{
				CredentialConfigurationsSupported: map[string]CredentialConfigurationsSupported{
					"pid_config": {
						Format: "dc+sd-jwt",
					},
				},
			},
			wantErr:     true,
			errContains: "could not resolve credential_identifier",
		},
		{
			name: "error when metadata is nil",
			request: &CredentialRequest{ // #nosec G101
				CredentialConfigurationID: "pid_config",
			},
			metadata:    nil,
			wantErr:     true,
			errContains: "metadata is required",
		},
		{
			name: "error when credential_configuration_id not found",
			request: &CredentialRequest{
				CredentialConfigurationID: "unknown_config",
			},
			metadata: &CredentialIssuerMetadataParameters{
				CredentialConfigurationsSupported: map[string]CredentialConfigurationsSupported{
					"pid_config": {
						Format: "dc+sd-jwt",
					},
				},
			},
			wantErr:     true,
			errContains: "unknown credential_configuration_id",
		},
		{
			name:    "error when neither credential_configuration_id nor credential_identifier provided",
			request: &CredentialRequest{
				// Both fields empty
			},
			metadata: &CredentialIssuerMetadataParameters{
				CredentialConfigurationsSupported: map[string]CredentialConfigurationsSupported{
					"pid_config": {
						Format: "dc+sd-jwt",
					},
				},
			},
			wantErr:     true,
			errContains: "either credential_configuration_id or credential_identifier must be provided",
		},
		{
			name: "resolve vc+sd-jwt format",
			request: &CredentialRequest{ // #nosec G101
				CredentialConfigurationID: "vc_config",
			},
			metadata: &CredentialIssuerMetadataParameters{
				CredentialConfigurationsSupported: map[string]CredentialConfigurationsSupported{
					"vc_config": {
						Format: "vc+sd-jwt",
					},
				},
			},
			wantFormat: "vc+sd-jwt",
			wantErr:    false,
		},
		{
			name: "resolve ldp_vc format",
			request: &CredentialRequest{ // #nosec G101
				CredentialConfigurationID: "ldp_config",
			},
			metadata: &CredentialIssuerMetadataParameters{
				CredentialConfigurationsSupported: map[string]CredentialConfigurationsSupported{
					"ldp_config": {
						Format: "ldp_vc",
					},
				},
			},
			wantFormat: "ldp_vc",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			format, err := tt.request.ResolveCredentialFormat(tt.metadata, tt.authDetails...)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantFormat, format)
			}
		})
	}
}
