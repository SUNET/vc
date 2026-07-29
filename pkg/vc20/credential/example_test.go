package credential_test

import (
	"fmt"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/vc20/credential"
)

func ExampleContextV2() {
	fmt.Println(credential.ContextV2)
	// Output:
	// https://www.w3.org/ns/credentials/v2
}

func ExampleNewValidator() {
	log := logger.NewSimple("test")
	v := credential.NewValidator(log)
	fmt.Printf("%T\n", v)
	// Output:
	// *credential.Validator
}

func ExampleValidator_ValidateCredential() {
	log := logger.NewSimple("test")
	v := credential.NewValidator(log)

	// A minimal valid W3C VC 2.0 credential
	cred := map[string]any{
		"@context": []any{
			"https://www.w3.org/ns/credentials/v2",
		},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "did:example:issuer",
		"credentialSubject": map[string]any{"id": "did:example:subject"},
	}

	err := v.ValidateCredential(cred)
	fmt.Println("valid credential:", err)
	// Output:
	// valid credential: <nil>
}

func ExampleValidator_ValidateCredential_missingContext() {
	log := logger.NewSimple("test")
	v := credential.NewValidator(log)

	// Missing @context
	cred := map[string]any{
		"type":              []any{"VerifiableCredential"},
		"issuer":            "did:example:issuer",
		"credentialSubject": map[string]any{"id": "did:example:subject"},
	}

	err := v.ValidateCredential(cred)
	fmt.Println(err)
	// Output:
	// missing @context
}

func ExampleValidator_ValidatePresentation() {
	log := logger.NewSimple("test")
	v := credential.NewValidator(log)

	// A minimal valid W3C VC 2.0 presentation
	vp := map[string]any{
		"@context": []any{
			"https://www.w3.org/ns/credentials/v2",
		},
		"type": []any{"VerifiablePresentation"},
	}

	err := v.ValidatePresentation(vp)
	fmt.Println("valid presentation:", err)
	// Output:
	// valid presentation: <nil>
}

func ExampleErrMissingContext() {
	fmt.Println(credential.ErrMissingContext)
	fmt.Println(credential.ErrMissingIssuer)
	fmt.Println(credential.ErrUnsupportedCryptosuite)
	// Output:
	// @context is required
	// issuer is required
	// unsupported cryptographic suite
}
