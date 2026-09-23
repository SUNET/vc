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

func TestParseAuthorizationDetails(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr bool
		wantLen int
	}{
		{
			name:    "valid array with credential_configuration_id",
			raw:     `[{"type":"openid_credential","credential_configuration_id":"TestCredential"}]`,
			wantLen: 1,
		},
		{
			name:    "valid array with format+vct",
			raw:     `[{"type":"openid_credential","format":"vc+sd-jwt","vct":"SD_JWT_VC_example_in_OpenID4VCI"}]`,
			wantLen: 1,
		},
		{
			name:    "empty array is accepted",
			raw:     `[]`,
			wantLen: 0,
		},
		{
			name:    "null value rejected",
			raw:     `null`,
			wantErr: true,
		},
		{
			name:    "object (non-array) rejected",
			raw:     `{"type":"openid_credential","credential_configuration_id":"TestCredential"}`,
			wantErr: true,
		},
		{
			name:    "entry missing type",
			raw:     `[{"credential_configuration_id":"TestCredential"}]`,
			wantErr: true,
		},
		{
			name:    "entry with wrong type value",
			raw:     `[{"type":"unknown","credential_configuration_id":"TestCredential"}]`,
			wantErr: true,
		},
		{
			name:    "entry missing both credential_configuration_id and format",
			raw:     `[{"type":"openid_credential"}]`,
			wantErr: true,
		},
		{
			name:    "entry with format but no vct",
			raw:     `[{"type":"openid_credential","format":"vc+sd-jwt"}]`,
			wantErr: true,
		},
		{
			name:    "empty input is a no-op",
			raw:     "",
			wantLen: 0,
		},
		{
			name:    "malformed json rejected",
			raw:     `[not json`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &PARRequest{AuthorizationDetailsRaw: tt.raw}
			err := r.ParseAuthorizationDetails()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Len(t, r.AuthorizationDetails, tt.wantLen)
			assert.Empty(t, r.AuthorizationDetailsRaw, "raw should be cleared after successful parse")
		})
	}
}

func TestParseAuthorizationDetails_ValidatesJSONBinderInput(t *testing.T) {
	tests := []struct {
		name    string
		details []AuthorizationDetailsParameter
		wantErr bool
	}{
		{
			name: "prepopulated valid entry accepted",
			details: []AuthorizationDetailsParameter{
				{Type: "openid_credential", CredentialConfigurationID: "TestCredential"},
			},
		},
		{
			name: "prepopulated entry with wrong type rejected",
			details: []AuthorizationDetailsParameter{
				{Type: "unknown", CredentialConfigurationID: "TestCredential"},
			},
			wantErr: true,
		},
		{
			name: "prepopulated entry missing type rejected",
			details: []AuthorizationDetailsParameter{
				{CredentialConfigurationID: "TestCredential"},
			},
			wantErr: true,
		},
		{
			name: "prepopulated entry missing credential id and format rejected",
			details: []AuthorizationDetailsParameter{
				{Type: "openid_credential"},
			},
			wantErr: true,
		},
		{
			name: "prepopulated entry with format but no vct rejected",
			details: []AuthorizationDetailsParameter{
				{Type: "openid_credential", Format: "vc+sd-jwt"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &PARRequest{AuthorizationDetails: tt.details}
			err := r.ParseAuthorizationDetails()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}
