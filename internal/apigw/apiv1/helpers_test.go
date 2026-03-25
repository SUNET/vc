package apiv1

import (
	"encoding/json"
	"testing"
	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeriveVPFormatsFromMetadata(t *testing.T) {
	tests := []struct {
		name     string
		metadata *openid4vci.CredentialIssuerMetadataParameters
		expected *openid4vp.VPFormatsSupported
	}{
		{
			name:     "nil metadata",
			metadata: nil,
			expected: &openid4vp.VPFormatsSupported{},
		},
		{
			name: "nil credential configurations",
			metadata: &openid4vci.CredentialIssuerMetadataParameters{
				CredentialConfigurationsSupported: nil,
			},
			expected: &openid4vp.VPFormatsSupported{},
		},
		{
			name: "empty credential configurations",
			metadata: &openid4vci.CredentialIssuerMetadataParameters{
				CredentialConfigurationsSupported: map[string]openid4vci.CredentialConfigurationsSupported{},
			},
			expected: &openid4vp.VPFormatsSupported{},
		},
		{
			name: "dc+sd-jwt format with algorithms",
			metadata: &openid4vci.CredentialIssuerMetadataParameters{
				CredentialConfigurationsSupported: map[string]openid4vci.CredentialConfigurationsSupported{
					"diploma": {
						Format:                              "dc+sd-jwt",
						CredentialSigningAlgValuesSupported: []any{"ES256", "ES384"},
						ProofTypesSupported: map[string]openid4vci.ProofsTypesSupported{
							"jwt": {
								ProofSigningAlgValuesSupported: []string{"ES256", "ES384"},
							},
						},
					},
				},
			},
			expected: &openid4vp.VPFormatsSupported{
				SDJWT: &openid4vp.SDJWTVCFormat{
					SDJWTAlgValues: []string{"ES256", "ES384"},
					KBJWTAlgValues: []string{"ES256", "ES384"},
				},
			},
		},
		{
			name: "vc+sd-jwt format with algorithms",
			metadata: &openid4vci.CredentialIssuerMetadataParameters{
				CredentialConfigurationsSupported: map[string]openid4vci.CredentialConfigurationsSupported{
					"credential": {
						Format:                              "vc+sd-jwt",
						CredentialSigningAlgValuesSupported: []any{"ES256"},
						ProofTypesSupported: map[string]openid4vci.ProofsTypesSupported{
							"jwt": {
								ProofSigningAlgValuesSupported: []string{"ES256"},
							},
						},
					},
				},
			},
			expected: &openid4vp.VPFormatsSupported{
				SDJWT: &openid4vp.SDJWTVCFormat{
					SDJWTAlgValues: []string{"ES256"},
					KBJWTAlgValues: []string{"ES256"},
				},
			},
		},
		{
			name: "mso_mdoc format with COSE algorithms",
			metadata: &openid4vci.CredentialIssuerMetadataParameters{
				CredentialConfigurationsSupported: map[string]openid4vci.CredentialConfigurationsSupported{
					"pid_mdoc": {
						Format:                              "mso_mdoc",
						CredentialSigningAlgValuesSupported: []any{float64(-7), float64(-35)},
					},
				},
			},
			expected: &openid4vp.VPFormatsSupported{
				MsoMdoc: &openid4vp.MsoMdocFormat{
					IssuerAuthAlgValues: []int{-7, -35},
					DeviceAuthAlgValues: []int{-7, -35},
				},
			},
		},
		{
			name: "multiple formats combined",
			metadata: &openid4vci.CredentialIssuerMetadataParameters{
				CredentialConfigurationsSupported: map[string]openid4vci.CredentialConfigurationsSupported{
					"diploma": {
						Format:                              "dc+sd-jwt",
						CredentialSigningAlgValuesSupported: []any{"ES256"},
						ProofTypesSupported: map[string]openid4vci.ProofsTypesSupported{
							"jwt": {
								ProofSigningAlgValuesSupported: []string{"ES256"},
							},
						},
					},
					"pid_mdoc": {
						Format:                              "mso_mdoc",
						CredentialSigningAlgValuesSupported: []any{float64(-7)},
					},
				},
			},
			expected: &openid4vp.VPFormatsSupported{
				SDJWT: &openid4vp.SDJWTVCFormat{
					SDJWTAlgValues: []string{"ES256"},
					KBJWTAlgValues: []string{"ES256"},
				},
				MsoMdoc: &openid4vp.MsoMdocFormat{
					IssuerAuthAlgValues: []int{-7},
					DeviceAuthAlgValues: []int{-7},
				},
			},
		},
		{
			name: "sd-jwt without proof_types_supported",
			metadata: &openid4vci.CredentialIssuerMetadataParameters{
				CredentialConfigurationsSupported: map[string]openid4vci.CredentialConfigurationsSupported{
					"diploma": {
						Format:                              "dc+sd-jwt",
						CredentialSigningAlgValuesSupported: []any{"ES256"},
						ProofTypesSupported:                 map[string]openid4vci.ProofsTypesSupported{},
					},
				},
			},
			expected: &openid4vp.VPFormatsSupported{
				SDJWT: &openid4vp.SDJWTVCFormat{
					SDJWTAlgValues: []string{"ES256"},
				},
			},
		},
		{
			name: "empty format string",
			metadata: &openid4vci.CredentialIssuerMetadataParameters{
				CredentialConfigurationsSupported: map[string]openid4vci.CredentialConfigurationsSupported{
					"unknown": {
						Format:                              "",
						CredentialSigningAlgValuesSupported: []any{"ES256"},
					},
				},
			},
			expected: &openid4vp.VPFormatsSupported{},
		},
		{
			name: "unsupported format",
			metadata: &openid4vci.CredentialIssuerMetadataParameters{
				CredentialConfigurationsSupported: map[string]openid4vci.CredentialConfigurationsSupported{
					"jwt_vc": {
						Format:                              "jwt_vc_json",
						CredentialSigningAlgValuesSupported: []any{"ES256"},
					},
				},
			},
			expected: &openid4vp.VPFormatsSupported{},
		},
		{
			name: "duplicate algorithms across credentials",
			metadata: &openid4vci.CredentialIssuerMetadataParameters{
				CredentialConfigurationsSupported: map[string]openid4vci.CredentialConfigurationsSupported{
					"diploma": {
						Format:                              "dc+sd-jwt",
						CredentialSigningAlgValuesSupported: []any{"ES256"},
						ProofTypesSupported: map[string]openid4vci.ProofsTypesSupported{
							"jwt": {
								ProofSigningAlgValuesSupported: []string{"ES256"},
							},
						},
					},
					"pid": {
						Format:                              "dc+sd-jwt",
						CredentialSigningAlgValuesSupported: []any{"ES256"},
						ProofTypesSupported: map[string]openid4vci.ProofsTypesSupported{
							"jwt": {
								ProofSigningAlgValuesSupported: []string{"ES256"},
							},
						},
					},
				},
			},
			expected: &openid4vp.VPFormatsSupported{
				SDJWT: &openid4vp.SDJWTVCFormat{
					SDJWTAlgValues: []string{"ES256"},
					KBJWTAlgValues: []string{"ES256"},
				},
			},
		},
		{
			name: "non-string algorithm in sd-jwt",
			metadata: &openid4vci.CredentialIssuerMetadataParameters{
				CredentialConfigurationsSupported: map[string]openid4vci.CredentialConfigurationsSupported{
					"diploma": {
						Format:                              "dc+sd-jwt",
						CredentialSigningAlgValuesSupported: []any{"ES256", 123, "ES384"},
						ProofTypesSupported: map[string]openid4vci.ProofsTypesSupported{
							"jwt": {
								ProofSigningAlgValuesSupported: []string{"ES256"},
							},
						},
					},
				},
			},
			expected: &openid4vp.VPFormatsSupported{
				SDJWT: &openid4vp.SDJWTVCFormat{
					SDJWTAlgValues: []string{"ES256", "ES384"},
					KBJWTAlgValues: []string{"ES256"},
				},
			},
		},
		{
			name: "non-number algorithm in mso_mdoc",
			metadata: &openid4vci.CredentialIssuerMetadataParameters{
				CredentialConfigurationsSupported: map[string]openid4vci.CredentialConfigurationsSupported{
					"pid_mdoc": {
						Format:                              "mso_mdoc",
						CredentialSigningAlgValuesSupported: []any{float64(-7), "ES256", float64(-35)},
					},
				},
			},
			expected: &openid4vp.VPFormatsSupported{
				MsoMdoc: &openid4vp.MsoMdocFormat{
					IssuerAuthAlgValues: []int{-7, -35},
					DeviceAuthAlgValues: []int{-7, -35},
				},
			},
		},
		{
			name: "mso_mdoc with int algorithm IDs",
			metadata: &openid4vci.CredentialIssuerMetadataParameters{
				CredentialConfigurationsSupported: map[string]openid4vci.CredentialConfigurationsSupported{
					"pid_mdoc": {
						Format:                              "mso_mdoc",
						CredentialSigningAlgValuesSupported: []any{int(-7), int(-35)},
					},
				},
			},
			expected: &openid4vp.VPFormatsSupported{
				MsoMdoc: &openid4vp.MsoMdocFormat{
					IssuerAuthAlgValues: []int{-7, -35},
					DeviceAuthAlgValues: []int{-7, -35},
				},
			},
		},
		{
			name: "mso_mdoc with int64 algorithm IDs",
			metadata: &openid4vci.CredentialIssuerMetadataParameters{
				CredentialConfigurationsSupported: map[string]openid4vci.CredentialConfigurationsSupported{
					"pid_mdoc": {
						Format:                              "mso_mdoc",
						CredentialSigningAlgValuesSupported: []any{int64(-7), int64(-35)},
					},
				},
			},
			expected: &openid4vp.VPFormatsSupported{
				MsoMdoc: &openid4vp.MsoMdocFormat{
					IssuerAuthAlgValues: []int{-7, -35},
					DeviceAuthAlgValues: []int{-7, -35},
				},
			},
		},
		{
			name: "mso_mdoc with json.Number algorithm IDs",
			metadata: &openid4vci.CredentialIssuerMetadataParameters{
				CredentialConfigurationsSupported: map[string]openid4vci.CredentialConfigurationsSupported{
					"pid_mdoc": {
						Format:                              "mso_mdoc",
						CredentialSigningAlgValuesSupported: []any{json.Number("-7"), json.Number("-35")},
					},
				},
			},
			expected: &openid4vp.VPFormatsSupported{
				MsoMdoc: &openid4vp.MsoMdocFormat{
					IssuerAuthAlgValues: []int{-7, -35},
					DeviceAuthAlgValues: []int{-7, -35},
				},
			},
		},
		{
			name: "mso_mdoc with mixed numeric types",
			metadata: &openid4vci.CredentialIssuerMetadataParameters{
				CredentialConfigurationsSupported: map[string]openid4vci.CredentialConfigurationsSupported{
					"pid_mdoc": {
						Format:                              "mso_mdoc",
						CredentialSigningAlgValuesSupported: []any{float64(-7), int(-35), int64(-37), json.Number("-8")},
					},
				},
			},
			expected: &openid4vp.VPFormatsSupported{
				MsoMdoc: &openid4vp.MsoMdocFormat{
					IssuerAuthAlgValues: []int{-37, -35, -8, -7},
					DeviceAuthAlgValues: []int{-37, -35, -8, -7},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := deriveVPFormatsFromMetadata(tt.metadata)
			require.NotNil(t, result)

			// Check SDJWT
			if tt.expected.SDJWT == nil {
				assert.Nil(t, result.SDJWT)
			} else {
				require.NotNil(t, result.SDJWT)
				assert.ElementsMatch(t, tt.expected.SDJWT.SDJWTAlgValues, result.SDJWT.SDJWTAlgValues)
				assert.ElementsMatch(t, tt.expected.SDJWT.KBJWTAlgValues, result.SDJWT.KBJWTAlgValues)
			}

			// Check MsoMdoc
			if tt.expected.MsoMdoc == nil {
				assert.Nil(t, result.MsoMdoc)
			} else {
				require.NotNil(t, result.MsoMdoc)
				assert.ElementsMatch(t, tt.expected.MsoMdoc.IssuerAuthAlgValues, result.MsoMdoc.IssuerAuthAlgValues)
				assert.ElementsMatch(t, tt.expected.MsoMdoc.DeviceAuthAlgValues, result.MsoMdoc.DeviceAuthAlgValues)
			}

			// Check LDPVC and JWTVCJson are nil (not supported yet)
			assert.Nil(t, result.LDPVC)
			assert.Nil(t, result.JWTVCJson)
		})
	}
}
