package openid4vp_test

import (
	"fmt"

	"github.com/SUNET/vc/pkg/openid4vp"
)

func ExampleNewErrorResponse() {
	err := openid4vp.NewErrorResponse(
		openid4vp.ErrorAccessDenied,
		"user denied consent",
		"state-abc123",
	)

	fmt.Println("error:", err.Error())
	fmt.Println("code:", err.ErrorCode)
	fmt.Println("state:", err.State)
	// Output:
	// error: access_denied: user denied consent
	// code: access_denied
	// state: state-abc123
}

func ExampleErrorResponse_Error() {
	// Error with description
	err1 := openid4vp.NewErrorResponse(openid4vp.ErrorInvalidRequest, "missing nonce", "")
	fmt.Println(err1.Error())

	// Error without description
	err2 := openid4vp.NewErrorResponse(openid4vp.ErrorWalletUnavailable, "", "")
	fmt.Println(err2.Error())
	// Output:
	// invalid_request: missing nonce
	// wallet_unavailable
}

func ExampleErrorResponse_IsAuthorizationError() {
	authErr := openid4vp.NewErrorResponse(openid4vp.ErrorAccessDenied, "denied", "")
	fmt.Println("access_denied is auth error:", authErr.IsAuthorizationError())

	formatErr := openid4vp.NewErrorResponse(openid4vp.ErrorVPFormatsNotSupported, "unsupported", "")
	fmt.Println("vp_formats_not_supported is auth error:", formatErr.IsAuthorizationError())
	// Output:
	// access_denied is auth error: true
	// vp_formats_not_supported is auth error: false
}

func ExamplePresentationSubmission() {
	submission := openid4vp.PresentationSubmission{
		ID:           "submission-1",
		DefinitionID: "definition-1",
		DescriptorMap: []openid4vp.Descriptor{
			{
				ID:     "identity_credential",
				Path:   "$",
				Format: "sd_jwt",
			},
		},
	}

	fmt.Println("id:", submission.ID)
	fmt.Println("definition_id:", submission.DefinitionID)
	fmt.Println("descriptors:", len(submission.DescriptorMap))
	fmt.Println("first descriptor format:", submission.DescriptorMap[0].Format)
	// Output:
	// id: submission-1
	// definition_id: definition-1
	// descriptors: 1
	// first descriptor format: sd_jwt
}

func ExampleInputDescriptor() {
	descriptor := openid4vp.InputDescriptor{
		ID:      "identity_credential",
		Name:    "Identity Credential",
		Purpose: "We need to verify your identity",
		Constraints: openid4vp.Constraints{
			LimitDisclosure: "required",
			Fields: []openid4vp.Field{
				{
					Path: []string{"$.vc.credentialSubject.given_name"},
				},
			},
		},
	}

	fmt.Println("id:", descriptor.ID)
	fmt.Println("name:", descriptor.Name)
	fmt.Println("limit_disclosure:", descriptor.Constraints.LimitDisclosure)
	fmt.Println("fields:", len(descriptor.Constraints.Fields))
	// Output:
	// id: identity_credential
	// name: Identity Credential
	// limit_disclosure: required
	// fields: 1
}

func ExampleVerificationRejectedError() {
	err := &openid4vp.VerificationRejectedError{
		Step:   "trust_evaluation",
		Reason: "issuer not trusted",
	}

	fmt.Println(err.Error())
	// Output:
	// verification rejected on 'trust_evaluation': issuer not trusted
}

func ExampleVerificationFailedError() {
	err := &openid4vp.VerificationFailedError{
		Step: "signature_verification",
		Err:  fmt.Errorf("invalid signature"),
	}

	fmt.Println(err.Error())
	// Output:
	// verification failed on 'signature_verification': invalid signature
}
