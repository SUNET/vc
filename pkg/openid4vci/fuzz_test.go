package openid4vci

import (
	"testing"
)

// FuzzParseCredentialOfferURI fuzzes the credential offer URI parser.
// This processes untrusted URIs from QR codes or deep links.
func FuzzParseCredentialOfferURI(f *testing.F) {
	f.Add("openid-credential-offer://?credential_offer={}")
	f.Add("openid-credential-offer://?credential_offer={\"credential_issuer\":\"https://example.com\",\"credential_configuration_ids\":[\"pid\"],\"grants\":{}}")
	f.Add("openid-credential-offer://?credential_offer={\"grants\":{\"authorization_code\":{\"issuer_state\":\"abc\"}}}")
	f.Add("openid-credential-offer://?credential_offer={\"grants\":{\"urn:ietf:params:oauth:grant-type:pre-authorized_code\":{\"pre-authorized_code\":\"xyz\"}}}")
	f.Add("")
	f.Add("://")
	f.Add("openid-credential-offer://")
	f.Add("openid-credential-offer://?credential_offer=not-json")
	f.Add("openid-credential-offer://?credential_offer=" + string(make([]byte, 1024)))

	f.Fuzz(func(t *testing.T, uri string) {
		result, err := ParseCredentialOfferURI(uri)
		if err != nil {
			return
		}
		if result == nil {
			t.Fatal("ParseCredentialOfferURI returned nil without error")
		}
	})
}
