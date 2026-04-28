package openid4vci

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	mockEscapedAuthorizationDetails = "%5B%7B%22type%22%3A%22openid_credential%22%2C%22credential_configuration_id%22%3A%22TestCredential%22%7D%2C%7B%22type%22%3A%22openid_credential%22%2C%22format%22%3A%22vc%2Bsd-jwt%22%2C%22vct%22%3A%22SD_JWT_VC_example_in_OpenID4VCI%22%7D%5D"
)

func TestMockAuthorizationDetails(t *testing.T) {
	tts := []struct {
		name string
		have []AuthorizationDetailsParameter
	}{
		{
			name: "credentialIdentifier",
			have: []AuthorizationDetailsParameter{
				{ // #nosec G101
					Type:                      "openid_credential",
					CredentialConfigurationID: "TestCredential",
				},
				{
					Type:   "openid_credential",
					Format: "vc+sd-jwt",
					VCT:    "SD_JWT_VC_example_in_OpenID4VCI",
				},
			},
		},
		{
			name: "format",
			have: []AuthorizationDetailsParameter{
				{
					Type:   "openid_credential",
					Format: "vc+sd-jwt",
					VCT:    "SD_JWT_VC_example_in_OpenID4VCI",
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			for _, p := range tt.have {
				if err := CheckSimple(p); err != nil {
					t.Log(err)
					t.FailNow()
				}
			}

			authorizationDetailsParameters, err := json.Marshal(tt.have)
			assert.NoError(t, err)

			escaped := url.QueryEscape(string(authorizationDetailsParameters))
			fmt.Println("escaped", escaped)
		})
	}
}

func TestURLDecode(t *testing.T) {
	tts := []struct {
		name string
		have string
		want string
	}{
		{
			name: "test",
			have: mockEscapedAuthorizationDetails,
			want: "[{\"type\":\"openid_credential\",\"credential_configuration_id\":\"TestCredential\"},{\"type\":\"openid_credential\",\"format\":\"vc+sd-jwt\",\"vct\":\"SD_JWT_VC_example_in_OpenID4VCI\"}]",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got, err := url.QueryUnescape(tt.have)
			assert.NoError(t, err)

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAuthParse(t *testing.T) {
	tts := []struct {
		name string
		have string
	}{
		{
			name: "test",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			//got, err := tt.have.AuthRedirectURL(tt.redirectURL)
			//assert.NoError(t, err)

			//assert.Equal(t, tt.want, got)
		})
	}
}

func TestAuthorizeBinding(t *testing.T) {
	tts := []struct {
		name string
		want *PARRequest
		have map[string]any
	}{
		{
			name: "with authorization details",
			want: &PARRequest{
				ResponseType: "code",
				AuthorizationDetails: []AuthorizationDetailsParameter{
					{ // #nosec G101
						Type:                      "openid_credential",
						CredentialConfigurationID: "TestCredential",
					},
					{
						Type:   "openid_credential",
						Format: "vc+sd-jwt",
						VCT:    "SD_JWT_VC_example_in_OpenID4VCI",
					},
				},
			},
			have: map[string]any{
				"authorization_details": mockEscapedAuthorizationDetails,
				"response_type":         "code",
			},
		},
		{
			name: "without authorization details",
			want: &PARRequest{
				ResponseType: "code",
			},
			have: map[string]any{
				"response_type": "code",
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			b, err := json.Marshal(tt.have)
			assert.NoError(t, err)

			body := io.NopCloser(bytes.NewBuffer(b))

			got, err := BindAuthorizationRequest(body)
			assert.NoError(t, err)

			assert.Equal(t, tt.want, got)
		})
	}
}
