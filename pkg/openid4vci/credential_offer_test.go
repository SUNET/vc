package openid4vci

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestCredentialOffer(t *testing.T) {
	tts := []struct {
		name       string
		parameters *CredentialOfferParameters
		want       string
	}{
		{
			name: "authorization_code",
			parameters: &CredentialOfferParameters{ // #nosec G101
				CredentialIssuer: "issuer.sunet.se",
				CredentialConfigurationIDs: []string{
					"PDA1Credential",
				},
				Grants: map[string]any{
					"authorization_code": &GrantAuthorizationCode{
						IssuerState: fmt.Sprintf("collect_id=%s&vct=%s&authentic_source=%s", "collect_id_1", "PDA1", "test_authentic_source"),
					},
				},
			},
			want: "credential_offer=%7B%22credential_issuer%22%3A%22issuer.sunet.se%22%2C%22credential_configuration_ids%22%3A%5B%22PDA1Credential%22%5D%2C%22grants%22%3A%7B%22authorization_code%22%3A%7B%22issuer_state%22%3A%22collect_id%3Dcollect_id_1%5Cu0026vct%3DPDA1%5Cu0026authentic_source%3Dtest_authentic_source%22%7D%7D%7D",
		},
		{
			name: "pre-authorized_code",
			parameters: &CredentialOfferParameters{ // #nosec G101
				CredentialIssuer: "https://credential-issuer.example.com",
				CredentialConfigurationIDs: []string{
					"UniversityDegreeCredential",
					"org.iso.18013.5.1.mDL",
				},
				Grants: map[string]any{
					"urn:ietf:params:oauth:grant-type:pre-authorized_code": &GrantPreAuthorizedCode{
						PreAuthorizedCode: "oaKazRN8I0IbtZ0C7JuMn5",
						TXCode: TXCode{
							InputMode:   "numeric",
							Length:      4,
							Description: "Please provide the one-time code that was sent via e-mail",
						},
						AuthorizationServer: "",
					},
				},
			},
			want: "credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fcredential-issuer.example.com%22%2C%22credential_configuration_ids%22%3A%5B%22UniversityDegreeCredential%22%2C%22org.iso.18013.5.1.mDL%22%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22oaKazRN8I0IbtZ0C7JuMn5%22%2C%22tx_code%22%3A%7B%22input_mode%22%3A%22numeric%22%2C%22length%22%3A4%2C%22description%22%3A%22Please+provide+the+one-time+code+that+was+sent+via+e-mail%22%7D%7D%7D%7D",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.parameters.CredentialOffer()
			assert.NoError(t, err)

			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestCredentialOfferParameters_CredentialOffer(t *testing.T) {
	tests := []struct {
		name                       string
		credentialOfferParameter   *CredentialOfferParameters
		wantErr                    bool
		validateCredentialIssuer   bool
		validateConfigurationIDs   bool
		validateGrants             bool
		expectedCredentialIssuer   string
		expectedConfigurationIDs   []string
		expectedGrantType          string
		expectedIssuerStatePattern string
	}{
		{ // #nosec G101
			name: "authorization_code_with_collect_id_vct_authentic_source",
			credentialOfferParameter: &CredentialOfferParameters{ // #nosec G101
				CredentialIssuer: "https://issuer.example.com",
				CredentialConfigurationIDs: []string{
					"TestCredential",
				},
				Grants: map[string]any{
					"authorization_code": GrantAuthorizationCode{
						IssuerState: fmt.Sprintf("collect_id=%s&vct=%s&authentic_source=%s", "test-collect-123", "TestCredential", "ExampleSource"),
					},
				},
			},
			wantErr:                    false,
			validateCredentialIssuer:   true,
			validateConfigurationIDs:   true,
			validateGrants:             true,
			expectedCredentialIssuer:   "https://issuer.example.com",
			expectedConfigurationIDs:   []string{"TestCredential"},
			expectedGrantType:          "authorization_code",
			expectedIssuerStatePattern: "collect_id=test-collect-123&vct=TestCredential&authentic_source=ExampleSource",
		},
		{ // #nosec G101
			name: "authorization_code_with_uuid_collect_id",
			credentialOfferParameter: &CredentialOfferParameters{ // #nosec G101
				CredentialIssuer: "https://issuer.sunet.se",
				CredentialConfigurationIDs: []string{
					"PDA1Credential",
				},
				Grants: map[string]any{
					"authorization_code": GrantAuthorizationCode{
						IssuerState: fmt.Sprintf("collect_id=%s&vct=%s&authentic_source=%s", "d779badf-f333-434a-8bdf-fc0d419231ef", "PDA1", "SUNET"),
					},
				},
			},
			wantErr:                    false,
			validateCredentialIssuer:   true,
			validateConfigurationIDs:   true,
			validateGrants:             true,
			expectedCredentialIssuer:   "https://issuer.sunet.se",
			expectedConfigurationIDs:   []string{"PDA1Credential"},
			expectedGrantType:          "authorization_code",
			expectedIssuerStatePattern: "collect_id=d779badf-f333-434a-8bdf-fc0d419231ef&vct=PDA1&authentic_source=SUNET",
		},
		{ // #nosec G101
			name: "authorization_code_with_multiple_credentials",
			credentialOfferParameter: &CredentialOfferParameters{ // #nosec G101
				CredentialIssuer: "https://issuer.example.com",
				CredentialConfigurationIDs: []string{
					"CredentialType1",
					"CredentialType2",
					"CredentialType3",
				},
				Grants: map[string]any{
					"authorization_code": GrantAuthorizationCode{
						IssuerState: fmt.Sprintf("collect_id=%s&vct=%s&authentic_source=%s", "multi-cred-123", "CredentialType1", "MultiSource"),
					},
				},
			},
			wantErr:                  false,
			validateCredentialIssuer: true,
			validateConfigurationIDs: true,
			validateGrants:           true,
			expectedCredentialIssuer: "https://issuer.example.com",
			expectedConfigurationIDs: []string{"CredentialType1", "CredentialType2", "CredentialType3"},
			expectedGrantType:        "authorization_code",
		},
		{ // #nosec G101
			name: "authorization_code_with_special_characters_in_issuer_state",
			credentialOfferParameter: &CredentialOfferParameters{ // #nosec G101
				CredentialIssuer: "https://issuer.example.com",
				CredentialConfigurationIDs: []string{
					"TestCredential",
				},
				Grants: map[string]any{
					"authorization_code": GrantAuthorizationCode{
						IssuerState: fmt.Sprintf("collect_id=%s&vct=%s&authentic_source=%s", "test-123@#$", "Test+Credential", "Source/With/Slashes"),
					},
				},
			},
			wantErr:                  false,
			validateCredentialIssuer: true,
			validateConfigurationIDs: true,
			validateGrants:           true,
			expectedCredentialIssuer: "https://issuer.example.com",
			expectedConfigurationIDs: []string{"TestCredential"},
			expectedGrantType:        "authorization_code",
		},
		{ // #nosec G101
			name: "pre_authorized_code_grant",
			credentialOfferParameter: &CredentialOfferParameters{ // #nosec G101
				CredentialIssuer: "https://issuer.example.com",
				CredentialConfigurationIDs: []string{
					"TestCredential",
				},
				Grants: map[string]any{
					"urn:ietf:params:oauth:grant-type:pre-authorized_code": GrantPreAuthorizedCode{
						PreAuthorizedCode: "test-pre-auth-code-123",
						TXCode: TXCode{
							InputMode:   "numeric",
							Length:      6,
							Description: "Enter the 6-digit code",
						},
					},
				},
			},
			wantErr:                  false,
			validateCredentialIssuer: true,
			validateConfigurationIDs: true,
			validateGrants:           true,
			expectedCredentialIssuer: "https://issuer.example.com",
			expectedConfigurationIDs: []string{"TestCredential"},
			expectedGrantType:        "urn:ietf:params:oauth:grant-type:pre-authorized_code",
		},
		{ // #nosec G101
			name: "no_grants",
			credentialOfferParameter: &CredentialOfferParameters{ // #nosec G101
				CredentialIssuer: "https://issuer.example.com",
				CredentialConfigurationIDs: []string{
					"TestCredential",
				},
				Grants: nil,
			},
			wantErr:                  false,
			validateCredentialIssuer: true,
			validateConfigurationIDs: true,
			validateGrants:           false,
			expectedCredentialIssuer: "https://issuer.example.com",
			expectedConfigurationIDs: []string{"TestCredential"},
		},
		{ // #nosec G101
			name: "empty_grants",
			credentialOfferParameter: &CredentialOfferParameters{ // #nosec G101
				CredentialIssuer: "https://issuer.example.com",
				CredentialConfigurationIDs: []string{
					"TestCredential",
				},
				Grants: map[string]any{},
			},
			wantErr:                  false,
			validateCredentialIssuer: true,
			validateConfigurationIDs: true,
			validateGrants:           false,
			expectedCredentialIssuer: "https://issuer.example.com",
			expectedConfigurationIDs: []string{"TestCredential"},
		},
		{ // #nosec G101
			name: "authorization_code_with_empty_issuer_state",
			credentialOfferParameter: &CredentialOfferParameters{ // #nosec G101
				CredentialIssuer: "https://issuer.example.com",
				CredentialConfigurationIDs: []string{
					"TestCredential",
				},
				Grants: map[string]any{
					"authorization_code": GrantAuthorizationCode{
						IssuerState: "",
					},
				},
			},
			wantErr:                    false,
			validateCredentialIssuer:   true,
			validateConfigurationIDs:   true,
			validateGrants:             true,
			expectedCredentialIssuer:   "https://issuer.example.com",
			expectedConfigurationIDs:   []string{"TestCredential"},
			expectedGrantType:          "authorization_code",
			expectedIssuerStatePattern: "",
		},
		{ // #nosec G101
			name: "authorization_code_with_authorization_server",
			credentialOfferParameter: &CredentialOfferParameters{ // #nosec G101
				CredentialIssuer: "https://issuer.example.com",
				CredentialConfigurationIDs: []string{
					"TestCredential",
				},
				Grants: map[string]any{
					"authorization_code": GrantAuthorizationCode{
						IssuerState:         fmt.Sprintf("collect_id=%s&vct=%s&authentic_source=%s", "test-123", "TestCred", "TestSource"),
						AuthorizationServer: "https://auth.example.com",
					},
				},
			},
			wantErr:                  false,
			validateCredentialIssuer: true,
			validateConfigurationIDs: true,
			validateGrants:           true,
			expectedCredentialIssuer: "https://issuer.example.com",
			expectedConfigurationIDs: []string{"TestCredential"},
			expectedGrantType:        "authorization_code",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.credentialOfferParameter.CredentialOffer()

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotEmpty(t, got)

			// Verify the credential offer can be decoded
			decodedURL, err := url.ParseQuery(string(got))
			assert.NoError(t, err)
			assert.Contains(t, decodedURL, "credential_offer")

			// Parse the JSON from the credential_offer parameter
			var parsedOffer CredentialOfferParameters
			err = json.Unmarshal([]byte(decodedURL.Get("credential_offer")), &parsedOffer)
			assert.NoError(t, err)

			// Validate credential issuer
			if tt.validateCredentialIssuer {
				assert.Equal(t, tt.expectedCredentialIssuer, parsedOffer.CredentialIssuer)
			}

			// Validate credential configuration IDs
			if tt.validateConfigurationIDs {
				assert.Equal(t, tt.expectedConfigurationIDs, parsedOffer.CredentialConfigurationIDs)
			}

			// Validate grants
			if tt.validateGrants {
				assert.NotNil(t, parsedOffer.Grants)
				assert.Contains(t, parsedOffer.Grants, tt.expectedGrantType)

				// Validate authorization_code grant if present
				if tt.expectedGrantType == "authorization_code" && tt.expectedIssuerStatePattern != "" {
					grantData, ok := parsedOffer.Grants["authorization_code"]
					assert.True(t, ok)

					// Re-marshal and unmarshal to get proper type
					grantBytes, err := json.Marshal(grantData)
					assert.NoError(t, err)

					var authGrant GrantAuthorizationCode
					err = json.Unmarshal(grantBytes, &authGrant)
					assert.NoError(t, err)

					if tt.expectedIssuerStatePattern != "" {
						assert.Equal(t, tt.expectedIssuerStatePattern, authGrant.IssuerState)
					}
				}
			}

			// Verify the credential offer is URL-encoded
			assert.True(t, strings.HasPrefix(string(got), "credential_offer="))
			assert.Contains(t, string(got), "%22credential_issuer%22")
		})
	}
}

func TestCredentialOfferParameters_CredentialOffer_RoundTrip(t *testing.T) {
	tests := []struct {
		name       string
		parameters *CredentialOfferParameters
	}{
		{
			name: "round_trip_authorization_code",
			parameters: &CredentialOfferParameters{ // #nosec G101
				CredentialIssuer: "https://issuer.example.com",
				CredentialConfigurationIDs: []string{
					"TestCredential",
				},
				Grants: map[string]any{
					"authorization_code": GrantAuthorizationCode{
						IssuerState: fmt.Sprintf("collect_id=%s&vct=%s&authentic_source=%s", "round-trip-123", "TestCred", "TestSource"),
					},
				},
			},
		},
		{
			name: "round_trip_pre_authorized_code",
			parameters: &CredentialOfferParameters{ // #nosec G101
				CredentialIssuer: "https://issuer.example.com",
				CredentialConfigurationIDs: []string{
					"UniversityDegree",
				},
				Grants: map[string]any{
					"urn:ietf:params:oauth:grant-type:pre-authorized_code": GrantPreAuthorizedCode{
						PreAuthorizedCode: "test-code-xyz",
						TXCode: TXCode{
							InputMode:   "text",
							Length:      8,
							Description: "Enter the code",
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create credential offer
			offer, err := tt.parameters.CredentialOffer()
			assert.NoError(t, err)
			assert.NotEmpty(t, offer)

			// Parse it back
			parsed, err := ParseCredentialOfferURI("openid-credential-offer://?" + string(offer))
			assert.NoError(t, err)
			assert.NotNil(t, parsed)

			// Verify round-trip preserved data
			assert.Equal(t, tt.parameters.CredentialIssuer, parsed.CredentialIssuer)
			assert.Equal(t, tt.parameters.CredentialConfigurationIDs, parsed.CredentialConfigurationIDs)
			assert.Equal(t, len(tt.parameters.Grants), len(parsed.Grants))
		})
	}
}

func TestParseCredentialOffer(t *testing.T) {
	tts := []struct {
		name string
		have string
		want *CredentialOfferParameters
	}{
		{
			name: "espoo bootcamp",
			have: "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fagent.ssi.dev.sphereon.com%2Fdid-web%2Foid4vci%22%2C%22credential_configuration_ids%22%3A%5B%22PensionSdJwt%22%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22d270fee1-9185-4e60-9901-d291e1338d7a%22%7D%7D%7D",
			want: &CredentialOfferParameters{ // #nosec G101
				CredentialIssuer:           "https://agent.ssi.dev.sphereon.com/did-web/oid4vci",
				CredentialConfigurationIDs: []string{"PensionSdJwt"},
				Grants: map[string]any{
					"urn:ietf:params:oauth:grant-type:pre-authorized_code": &GrantPreAuthorizedCode{
						PreAuthorizedCode:   "d270fee1-9185-4e60-9901-d291e1338d7a",
						TXCode:              TXCode{},
						AuthorizationServer: "",
					},
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCredentialOfferURI(tt.have)
			assert.NoError(t, err)

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCredentialOfferQR(t *testing.T) {
	tts := []struct {
		name                  string
		parameters            *CredentialOfferParameters
		walletURL             string
		expectedCredentialURL string
	}{
		{ // #nosec G101
			name:      "openid-credential-offer-default",
			walletURL: "",
			parameters: &CredentialOfferParameters{ // #nosec G101
				CredentialIssuer: "issuer.sunet.se",
				CredentialConfigurationIDs: []string{
					"PDA1Credential",
				},
				Grants: map[string]any{
					"authorization_code": &GrantAuthorizationCode{
						IssuerState: fmt.Sprintf("collect_id=%s&vct=%s&authentic_source=%s", "collect_id_1", "PDA1", "test_authentic_source"),
					},
				},
			},
			expectedCredentialURL: "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22issuer.sunet.se%22%2C%22credential_configuration_ids%22%3A%5B%22PDA1Credential%22%5D%2C%22grants%22%3A%7B%22authorization_code%22%3A%7B%22issuer_state%22%3A%22collect_id%3Dcollect_id_1%5Cu0026vct%3DPDA1%5Cu0026authentic_source%3Dtest_authentic_source%22%7D%7D%7D",
		},
		{ // #nosec G101
			name:      "web-wallet-https",
			walletURL: "https://wallet.dc4eu.eu/cb",
			parameters: &CredentialOfferParameters{ // #nosec G101
				CredentialIssuer: "https://satosa-test-1.sunet.se",
				CredentialConfigurationIDs: []string{
					"EHICCredential",
				},
				Grants: map[string]any{
					"authorization_code": &GrantAuthorizationCode{
						IssuerState: fmt.Sprintf("collect_id=%s&vct=%s&authentic_source=%s", "d779badf-f333-434a-8bdf-fc0d419231ef", "EHIC", "SUNET"),
					},
				},
			},
			expectedCredentialURL: "https://wallet.dc4eu.eu/cb?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fsatosa-test-1.sunet.se%22%2C%22credential_configuration_ids%22%3A%5B%22EHICCredential%22%5D%2C%22grants%22%3A%7B%22authorization_code%22%3A%7B%22issuer_state%22%3A%22collect_id%3Dd779badf-f333-434a-8bdf-fc0d419231ef%5Cu0026vct%3DEHIC%5Cu0026authentic_source%3DSUNET%22%7D%7D%7D",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			p, err := tt.parameters.CredentialOffer()
			assert.NoError(t, err)

			got, err := p.QR(0, 256, tt.walletURL)
			assert.NoError(t, err)

			// Validate QR is not empty
			assert.NotEmpty(t, got.QRBase64, "QRBase64 should not be empty")

			// Validate the credential offer URL matches expected
			assert.Equal(t, tt.expectedCredentialURL, got.CredentialOfferURL)
		})
	}
}

func TestCredentialOfferURIQR(t *testing.T) {
	tts := []struct {
		name             string
		parameters       *CredentialOfferParameters
		walletURL        string
		issuerURL        string
		expectedProtocol string
	}{
		{
			name: "default-protocol",
			parameters: &CredentialOfferParameters{ // #nosec G101
				CredentialIssuer: "https://issuer.sunet.se",
				CredentialConfigurationIDs: []string{
					"PDA1Credential",
				},
				Grants: map[string]any{
					"authorization_code": &GrantAuthorizationCode{
						IssuerState: fmt.Sprintf("collect_id=%s&vct=%s&authentic_source=%s", "d779badf-f333-434a-8bdf-fc0d419231ef", "PDA1", "SUNET"),
					},
				},
			},
			walletURL:        "",
			issuerURL:        "https://issuer.sunet.se",
			expectedProtocol: "openid-credential-offer://",
		},
		{
			name: "web-wallet",
			parameters: &CredentialOfferParameters{ // #nosec G101
				CredentialIssuer: "https://issuer.sunet.se",
				CredentialConfigurationIDs: []string{
					"PDA1Credential",
				},
				Grants: map[string]any{
					"authorization_code": &GrantAuthorizationCode{
						IssuerState: fmt.Sprintf("collect_id=%s&vct=%s&authentic_source=%s", "d779badf-f333-434a-8bdf-fc0d419231ef", "PDA1", "SUNET"),
					},
				},
			},
			walletURL:        "https://wallet.dc4eu.eu/cb",
			issuerURL:        "https://issuer.sunet.se",
			expectedProtocol: "https://wallet.dc4eu.eu/cb",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			p, err := tt.parameters.CredentialOfferURI()
			assert.NoError(t, err)

			qr, err := p.QR(0, 256, tt.walletURL, tt.issuerURL)
			assert.NoError(t, err)

			// Validate QR is not empty
			assert.NotEmpty(t, qr.QRBase64, "QRBase64 should not be empty")
			assert.NotEmpty(t, qr.CredentialOfferURL, "CredentialOfferURL should not be empty")

			// Validate the URL structure
			assert.Contains(t, qr.CredentialOfferURL, tt.expectedProtocol, "URL should use expected protocol/wallet URL")
			assert.Contains(t, qr.CredentialOfferURL, "credential_offer_uri=", "URL should contain credential_offer_uri parameter")
			assert.Contains(t, qr.CredentialOfferURL, url.QueryEscape(tt.issuerURL), "URL should contain encoded issuer URL")
		})
	}
}

func TestCredentialOfferURI(t *testing.T) {
	tts := []struct {
		name                 string
		parameters           *CredentialOfferParameters
		credentialServerAddr string
		want                 url.URL
	}{
		{
			name: "",
			parameters: &CredentialOfferParameters{ // #nosec G101
				CredentialIssuer: "https://issuer.sunet.se",
				CredentialConfigurationIDs: []string{
					"PDA1Credential",
				},
				Grants: map[string]any{
					"authorization_code": &GrantAuthorizationCode{
						IssuerState: fmt.Sprintf("collect_id=%s&vct=%s&authentic_source=%s", "d779badf-f333-434a-8bdf-fc0d419231ef", "PDA1", "SUNET"),
					},
				},
			},
			want: url.URL{
				Scheme: "https",
				Host:   "issuer.sunet.se",
				Path:   "credential-offer",
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.parameters.CredentialOfferURI()
			assert.NoError(t, err)

			u, err := url.Parse(got.String())
			assert.NoError(t, err)

			assert.Equal(t, tt.want.Scheme, u.Scheme)
			assert.Equal(t, tt.want.Host, u.Host)
			assert.Equal(t, tt.want.Path, strings.Split(u.Path, "/")[1])
		})
	}
}

func TestUnpackCredentialOffer(t *testing.T) {
	tts := []struct {
		name  string
		offer CredentialOffer
		want  *CredentialOfferParameters
	}{
		{
			name:  "authorization_code",
			offer: "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22http%3A%2F%2Fvc_dev_apigw:8080%22%2C%22credential_configuration_ids%22%3A%5B%22EHICCredential%22%5D%2C%22grants%22%3A%7B%22authorization_code%22%3A%7B%22issuer_state%22%3A%22collect_id%3Dcdd81c80-f4ca-41fc-a6a6-6b4e322a77d7%5Cu0026vct%3DEHIC%5Cu0026authentic_source%3DSUNET%22%7D%7D%7D",
			want: &CredentialOfferParameters{ // #nosec G101
				CredentialIssuer: "http://vc_dev_apigw:8080",
				CredentialConfigurationIDs: []string{
					"EHICCredential",
				},
				Grants: map[string]any{
					"authorization_code": &GrantAuthorizationCode{
						IssuerState: "collect_id=cdd81c80-f4ca-41fc-a6a6-6b4e322a77d7&vct=EHIC&authentic_source=SUNET",
					},
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.offer.Unpack(t.Context())
			assert.NoError(t, err)

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCredentialOfferUriUUID(t *testing.T) {
	tts := []struct {
		name string
		have *CredentialOfferParameters
	}{
		{
			name: "t1",
			have: &CredentialOfferParameters{ // #nosec G101
				CredentialIssuer: "http://test.sunet.se",
				CredentialConfigurationIDs: []string{
					"TestCredential",
				},
				Grants: map[string]any{
					"authorization_code": GrantAuthorizationCode{
						IssuerState: fmt.Sprintf("collect_id=%s&vct=%s&authentic_source=%s", "test_collect_id", "vct", "authentic_source"),
					},
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			uri, err := tt.have.CredentialOfferURI()
			assert.NoError(t, err)

			got, err := uri.UUID()
			assert.NoError(t, err)

			err = uuid.Validate(got)
			assert.NoError(t, err)
		})
	}
}

func TestNewCredentialOffer(t *testing.T) {
	t.Run("pre-authorized_code", func(t *testing.T) {
		result, err := NewCredentialOffer("https://issuer.example.com", "TestCredential", GrantTypePreAuthorizedCode)
		assert.NoError(t, err)

		// ID is set internally
		assert.NotEmpty(t, result.ID)

		// Credential offer fields are populated
		assert.Equal(t, "https://issuer.example.com", result.CredentialIssuer)
		assert.Equal(t, []string{"TestCredential"}, result.CredentialConfigurationIDs)
		assert.Contains(t, result.Grants, GrantTypePreAuthorizedCode)

		// The grant's pre-authorized_code matches the internal ID
		grantBytes, err := json.Marshal(result.Grants[GrantTypePreAuthorizedCode])
		assert.NoError(t, err)
		var grant GrantPreAuthorizedCode
		err = json.Unmarshal(grantBytes, &grant)
		assert.NoError(t, err)
		assert.Equal(t, result.ID, grant.PreAuthorizedCode)

		// ID must not appear in the JSON wire format
		wireBytes, err := json.Marshal(result)
		assert.NoError(t, err)
		var wireMap map[string]any
		err = json.Unmarshal(wireBytes, &wireMap)
		assert.NoError(t, err)
		assert.NotContains(t, wireMap, "id", "id field must not be serialized")
	})

	t.Run("authorization_code", func(t *testing.T) {
		result, err := NewCredentialOffer("https://issuer.example.com", "DegreeCredential", GrantTypeAuthorizationCode)
		assert.NoError(t, err)

		assert.NotEmpty(t, result.ID)
		assert.Equal(t, "https://issuer.example.com", result.CredentialIssuer)
		assert.Equal(t, []string{"DegreeCredential"}, result.CredentialConfigurationIDs)
		assert.Contains(t, result.Grants, GrantTypeAuthorizationCode)

		// The grant's issuer_state matches the internal ID
		grantBytes, err := json.Marshal(result.Grants[GrantTypeAuthorizationCode])
		assert.NoError(t, err)
		var grant GrantAuthorizationCode
		err = json.Unmarshal(grantBytes, &grant)
		assert.NoError(t, err)
		assert.Equal(t, result.ID, grant.IssuerState)

		// ID must not appear in the JSON wire format
		wireBytes, err := json.Marshal(result)
		assert.NoError(t, err)
		var wireMap map[string]any
		err = json.Unmarshal(wireBytes, &wireMap)
		assert.NoError(t, err)
		assert.NotContains(t, wireMap, "id", "id field must not be serialized")
	})

	t.Run("unsupported_grant_type", func(t *testing.T) {
		result, err := NewCredentialOffer("https://issuer.example.com", "TestCredential", "unsupported_grant")
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "unsupported grant type")
	})

	t.Run("unique_tokens", func(t *testing.T) {
		r1, err := NewCredentialOffer("https://issuer.example.com", "Cred", GrantTypePreAuthorizedCode)
		assert.NoError(t, err)
		r2, err := NewCredentialOffer("https://issuer.example.com", "Cred", GrantTypePreAuthorizedCode)
		assert.NoError(t, err)
		assert.NotEqual(t, r1.ID, r2.ID, "each offer must have a unique token")
	})
}
