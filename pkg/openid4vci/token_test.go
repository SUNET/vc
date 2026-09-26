package openid4vci

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenRequestValidationCredentialOfferRequest(t *testing.T) {
	tts := []struct {
		name string
		cop  *CredentialOfferParameters
		tr   *TokenRequest
		want error
	}{
		{
			name: "pre-authorized_code",
			cop: &CredentialOfferParameters{
				CredentialIssuer:           "",
				CredentialConfigurationIDs: []string{},
				Grants: map[string]any{
					"ietf:params:oauth:grant-type:pre-authorized_code": GrantPreAuthorizedCode{
						PreAuthorizedCode: "",
						TXCode: &TXCode{
							InputMode:   "numeric",
							Length:      1234,
							Description: "Pincode for the transaction",
						},
						AuthorizationServer: "",
					},
				},
			},
			tr:   &TokenRequest{},
			want: nil,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			//got := tt.tr.Validate(tt.cop)
			//if tt.want != nil {
			//	if got != nil {
			//		t.Errorf("got: %v, want: %v", got, tt.want)
			//	}
			//}
		})
	}
}

func TestTokenRequest_TXCodeValidation(t *testing.T) {
	v, err := NewValidator()
	require.NoError(t, err)

	base := TokenRequest{GrantType: "urn:ietf:params:oauth:grant-type:pre-authorized_code", PreAuthorizedCode: "abc"}

	t.Run("empty tx_code is valid", func(t *testing.T) {
		req := base
		assert.NoError(t, v.Struct(&req))
	})

	t.Run("short numeric tx_code is valid", func(t *testing.T) {
		req := base
		req.TXCode = "123456"
		assert.NoError(t, v.Struct(&req))
	})

	t.Run("tx_code at max length is valid", func(t *testing.T) {
		req := base
		req.TXCode = strings.Repeat("9", 64)
		assert.NoError(t, v.Struct(&req))
	})

	t.Run("tx_code exceeding max length is rejected", func(t *testing.T) {
		req := base
		req.TXCode = strings.Repeat("9", 65)
		assert.Error(t, v.Struct(&req))
	})

	t.Run("non-ascii tx_code is rejected", func(t *testing.T) {
		req := base
		req.TXCode = "12345\u00e9" // 'é'
		assert.Error(t, v.Struct(&req))
	})
}
