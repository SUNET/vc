package apiv1

import (
	"testing"
	"vc/pkg/model"
	"vc/pkg/sdjwtvc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUIMetadata tests the UIMetadata handler
func TestUIMetadata(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name              string
		credentials       map[string]*model.CredentialConstructor
		supportedWallets  map[string]string
		expectCredentials int
		expectWallets     int
	}{
		{
			name: "with credentials and wallets",
			credentials: map[string]*model.CredentialConstructor{
				"pid": {
					AuthMethod:   "client_secret",
					VCTMFilePath: "/path/to/vctm",
					VCTM:         &sdjwtvc.VCTM{},
				},
				"diploma": {
					AuthMethod:   "client_secret",
					VCTMFilePath: "/path/to/diploma_vctm",
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
			credentials: map[string]*model.CredentialConstructor{
				"ehic": {
					AuthMethod: "bearer_token",
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
				CredentialConstructor: tt.credentials,
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
				// Verify sensitive fields are cleared
				for _, cred := range reply.Credentials {
					assert.Empty(t, cred.AuthMethod, "AuthMethod should be cleared")
					assert.Empty(t, cred.VCTMFilePath, "VCTMFilePath should be cleared")
					assert.Nil(t, cred.VCTM, "VCTM should be cleared")
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
