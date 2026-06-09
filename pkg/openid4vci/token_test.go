package openid4vci

import "testing"

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
