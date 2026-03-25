package socialsecurity_test

import (
	"fmt"

	"github.com/SUNET/vc/pkg/socialsecurity"
)

func ExampleEHICDocument_Marshal() {
	doc := &socialsecurity.EHICDocument{
		PersonalAdministrativeNumber: "123456789",
		IssuingAuthority: socialsecurity.IssuingAuthority{
			ID:   "auth-001",
			Name: "National Health Authority",
		},
		IssuingCountry: "SE",
		DateOfExpiry:   "2026-12-31",
		DateOfIssuance: "2024-01-01",
		DocumentNumber: "EHIC-0001",
		AuthenticSource: socialsecurity.AuthenticSource{
			ID:   "src-001",
			Name: "Swedish Social Insurance Agency",
		},
		EndingDate:   "2026-12-31",
		StartingDate: "2024-01-01",
	}

	m, err := doc.Marshal()
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println("issuing_country:", m["issuing_country"])
	fmt.Println("document_number:", m["document_number"])
	fmt.Println("date_of_expiry:", m["date_of_expiry"])
	// Output:
	// issuing_country: SE
	// document_number: EHIC-0001
	// date_of_expiry: 2026-12-31
}

func ExamplePDA1Document_Marshal() {
	doc := &socialsecurity.PDA1Document{
		PersonalAdministrativeNumber: "987654321",
		Employer: socialsecurity.Employer{
			ID:      "emp-001",
			Name:    "Example Corp",
			Country: "SE",
		},
		WorkAddress: socialsecurity.WorkAddress{
			Locality: "Stockholm",
			Country:  "SE",
		},
		IssuingAuthority: socialsecurity.IssuingAuthority{
			ID:   "auth-002",
			Name: "Swedish Social Insurance Agency",
		},
		LegislationCountry: "SE",
		StatusConfirmation: "02",
		IssuingCountry:     "SE",
		DateOfExpiry:       "2026-12-31",
		DateOfIssuance:     "2024-01-01",
		DocumentNumber:     "PDA1-0001",
		AuthenticSource: socialsecurity.AuthenticSource{
			ID:   "src-002",
			Name: "Swedish Social Insurance Agency",
		},
		EndingDate:   "2026-12-31",
		StartingDate: "2024-01-01",
	}

	m, err := doc.Marshal()
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println("issuing_country:", m["issuing_country"])
	fmt.Println("document_number:", m["document_number"])
	fmt.Println("status_confirmation:", m["status_confirmation"])
	// Output:
	// issuing_country: SE
	// document_number: PDA1-0001
	// status_confirmation: 02
}
