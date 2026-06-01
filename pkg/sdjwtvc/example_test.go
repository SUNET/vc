package sdjwtvc_test

import (
	"fmt"

	"github.com/SUNET/vc/pkg/sdjwtvc"
)

func ExampleNew() {
	client := sdjwtvc.New()
	fmt.Printf("%T\n", client)
	// Output:
	// *sdjwtvc.Client
}

func ExampleToken_Split() {
	// SD-JWT format: <header>.<payload>.<signature>~<disclosure1>~<disclosure2>~
	token := sdjwtvc.Token("eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJpZCJ9.c2ln~ZGlzY2xvc3VyZTE~ZGlzY2xvc3VyZTI~")

	header, body, sig, disclosures, kb, err := token.Split()
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println("header:", header)
	fmt.Println("body:", body)
	fmt.Println("sig:", sig)
	fmt.Println("disclosures:", len(disclosures))
	fmt.Println("kb:", kb)
	// Output:
	// header: eyJhbGciOiJFUzI1NiJ9
	// body: eyJ2Y3QiOiJpZCJ9
	// sig: c2ln
	// disclosures: 2
	// kb: []
}

func ExampleCombine() {
	signedJWT := "eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJpZCJ9.c2ln"
	disclosures := []string{"ZGlzYzE", "ZGlzYzI"}

	sdJWT := sdjwtvc.Combine(signedJWT, disclosures, "")
	fmt.Println(sdJWT)
	// Output:
	// eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJpZCJ9.c2ln~ZGlzYzE~ZGlzYzI~
}

func ExampleCombineWithKeyBinding() {
	sdJWT := "eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJpZCJ9.c2ln~ZGlzYzE~ZGlzYzI~"
	kbJWT := "eyJ0eXAiOiJrYitqd3QifQ.eyJub25jZSI6Im4ifQ.a2JzaWc"

	combined := sdjwtvc.CombineWithKeyBinding(sdJWT, kbJWT)
	fmt.Println(combined)
	// Output:
	// eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJpZCJ9.c2ln~ZGlzYzE~ZGlzYzI~eyJ0eXAiOiJrYitqd3QifQ.eyJub25jZSI6Im4ifQ.a2JzaWc
}

func ExampleVCTM() {
	vctm := &sdjwtvc.VCTM{
		VCT:         "https://example.com/credentials/identity",
		Name:        "Identity Credential",
		Description: "A verifiable identity credential",
		Display: []sdjwtvc.VCTMDisplay{
			{
				Locale:      "en-US",
				Name:        "Identity Credential",
				Description: "Official identity document",
				Rendering: &sdjwtvc.Rendering{
					Simple: &sdjwtvc.SimpleRendering{
						Logo: &sdjwtvc.Logo{
							URI:     "https://example.com/logo.png",
							AltText: "Logo",
						},
						BackgroundColor: "#003366",
						TextColor:       "#FFFFFF",
					},
				},
			},
		},
		Claims: []sdjwtvc.Claim{
			{
				Path: []*string{new("given_name")},
				Display: []sdjwtvc.ClaimDisplay{
					{Locale: "en-US", Label: "Given Name"},
				},
				SD:        "always",
				Mandatory: true,
			},
			{
				Path: []*string{new("family_name")},
				Display: []sdjwtvc.ClaimDisplay{
					{Locale: "en-US", Label: "Family Name"},
				},
				SD:        "always",
				Mandatory: true,
			},
		},
	}

	fmt.Println("VCT:", vctm.VCT)
	fmt.Println("Name:", vctm.Name)
	fmt.Println("Claims:", len(vctm.Claims))
	// Output:
	// VCT: https://example.com/credentials/identity
	// Name: Identity Credential
	// Claims: 2
}

func ExampleVCTM_Attributes() {
	vctm := &sdjwtvc.VCTM{
		VCT: "https://example.com/credentials/identity",
		Claims: []sdjwtvc.Claim{
			{
				Path: []*string{new("given_name")},
				Display: []sdjwtvc.ClaimDisplay{
					{Locale: "en-US", Label: "Given Name"},
					{Locale: "sv-SE", Label: "Förnamn"},
				},
				SD: "always",
			},
		},
	}

	attrs := vctm.Attributes()
	fmt.Println("en-US Given Name path:", attrs["en-US"]["Given Name"])
	fmt.Println("sv-SE Förnamn path:", attrs["sv-SE"]["Förnamn"])
	// Output:
	// en-US Given Name path: [given_name]
	// sv-SE Förnamn path: [given_name]
}

func ExampleVCTM_SRIIntegrity() {
	vctm := &sdjwtvc.VCTM{
		VCT:  "https://example.com/credentials/identity",
		Name: "Identity Credential",
	}

	integrity, err := vctm.SRIIntegrity(nil)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("has prefix:", integrity[:7])
	// Output:
	// has prefix: sha256-
}

func ExampleParseSelectiveDisclosure() {
	// Base64url-encoded disclosure: ["salt123", "given_name", "John"]
	disclosures := []string{"WyJzYWx0MTIzIiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ"}

	parsed, err := sdjwtvc.ParseSelectiveDisclosure(disclosures)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println("claim:", parsed[0].ClaimName)
	fmt.Println("value:", parsed[0].Value)
	// Output:
	// claim: given_name
	// value: John
}
