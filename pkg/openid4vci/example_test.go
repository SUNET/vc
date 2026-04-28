package openid4vci_test

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/SUNET/vc/pkg/openid4vci"
)

func ExampleCredentialOfferParameters_Marshal() {
	offer := &openid4vci.CredentialOfferParameters{ // #nosec G101
		CredentialIssuer:           "https://issuer.example.com",
		CredentialConfigurationIDs: []string{"UniversityDegree_LDP_VC"},
		Grants: map[string]any{
			"authorization_code": openid4vci.GrantAuthorizationCode{
				IssuerState: "eyJhbGciOiJSU0Et",
			},
		},
	}

	data, err := offer.Marshal()
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	// Parse back to verify structure
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println("credential_issuer:", parsed["credential_issuer"])
	ids := parsed["credential_configuration_ids"].([]any)
	fmt.Println("credential_configuration_ids:", ids[0])
	// Output:
	// credential_issuer: https://issuer.example.com
	// credential_configuration_ids: UniversityDegree_LDP_VC
}

func ExampleError_Error() {
	err := &openid4vci.Error{
		Err:              openid4vci.ErrInvalidProof,
		ErrorDescription: "proof JWT is expired",
	}

	fmt.Println(err.Error())
	// Output:
	// invalid_proof
}

func ExampleStatusCode() {
	tests := []struct {
		name string
		err  *openid4vci.Error
	}{
		{"bad request", &openid4vci.Error{Err: openid4vci.ErrInvalidCredentialRequest}},
		{"unauthorized", &openid4vci.Error{Err: openid4vci.ErrUnauthorizedClient}},
		{"forbidden", &openid4vci.Error{Err: openid4vci.ErrAccessDenied}},
		{"server error", &openid4vci.Error{Err: openid4vci.ErrServerError}},
		{"unavailable", &openid4vci.Error{Err: openid4vci.ErrTemporarilyUnavailable}},
	}

	for _, tt := range tests {
		code := openid4vci.StatusCode(tt.err)
		fmt.Printf("%s: %d\n", tt.name, code)
	}
	// Output:
	// bad request: 400
	// unauthorized: 401
	// forbidden: 403
	// server error: 500
	// unavailable: 503
}

func ExampleStatusCode_badRequest() {
	err := &openid4vci.Error{Err: openid4vci.ErrInvalidProof}
	code := openid4vci.StatusCode(err)
	fmt.Println(code == http.StatusBadRequest)
	// Output:
	// true
}

func ExampleCredentialOfferParameters_CredentialOffer() {
	offer := &openid4vci.CredentialOfferParameters{ // #nosec G101
		CredentialIssuer:           "https://issuer.example.com",
		CredentialConfigurationIDs: []string{"IdentityCredential"},
	}

	credOffer, err := offer.CredentialOffer()
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	// The credential offer is a URL-encoded string containing the JSON
	s := credOffer.String()
	fmt.Println("starts with credential_offer:", s[:17] == "credential_offer=")
	// Output:
	// starts with credential_offer: true
}
