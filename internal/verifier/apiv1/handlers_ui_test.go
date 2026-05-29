package apiv1

import (
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUIMetadata tests the UIMetadata handler
func TestUIMetadata(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name              string
		credentials       map[string]*model.CredentialMetadata
		supportedWallets  map[string]string
		expectCredentials int
		expectWallets     int
	}{
		{
			name: "with credentials and wallets",
			credentials: map[string]*model.CredentialMetadata{
				"pid": {
					VCTMFilePath: "/path/to/vctm",
					VCTM:         &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"},
					Attributes: map[string]map[string][]string{
						"en-US": {"given_name": {"given_name"}},
					},
				},
				"diploma": {
					VCTMFilePath: "/path/to/diploma_vctm",
					VCTM:         &sdjwtvc.VCTM{VCT: "urn:eudi:diploma:1"},
				},
			},
			supportedWallets: map[string]string{
				"eudiw":    "https://eudiw.example.com",
				"wwwallet": "https://wwwallet.example.com",
			},
			expectCredentials: 2,
			expectWallets:     2,
		},
		{
			name:              "empty credentials and wallets",
			credentials:       nil,
			supportedWallets:  nil,
			expectCredentials: 0,
			expectWallets:     0,
		},
		{
			name: "credentials only",
			credentials: map[string]*model.CredentialMetadata{
				"ehic": {
					VCTM: &sdjwtvc.VCTM{VCT: "urn:eudi:ehic:1"},
				},
			},
			supportedWallets:  nil,
			expectCredentials: 1,
			expectWallets:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &model.Cfg{
				Common: &model.Common{
					CredentialMetadata: tt.credentials,
				},
				Verifier: &model.Verifier{
					SupportedWallets: tt.supportedWallets,
				},
			}

			client, _ := CreateTestClientWithMock(cfg)
			// Override cfg with our test config
			client.cfg = cfg

			reply, err := client.UIMetadata(ctx)

			assert.NoError(t, err)
			require.NotNil(t, reply)

			if tt.expectCredentials == 0 {
				assert.Len(t, reply.Credentials, 0)
			} else {
				assert.Len(t, reply.Credentials, tt.expectCredentials)
				for scope, cred := range reply.Credentials {
					srcCred := tt.credentials[scope]
					if srcCred != nil && srcCred.VCTM != nil {
						assert.Equal(t, srcCred.VCTM.VCT, cred.VCT, "VCT should be populated from VCTM")
					}
				}
			}

			if tt.expectWallets == 0 {
				assert.Len(t, reply.SupportedWallets, 0)
			} else {
				assert.Len(t, reply.SupportedWallets, tt.expectWallets)
			}
		})
	}
}
