package education_test

import (
	"fmt"

	"github.com/SUNET/vc/pkg/education"
)

func ExampleNewDiploma() {
	doc := education.NewDiploma()
	fmt.Println("type:", doc.Type)
	fmt.Println("subject ID:", doc.CredentialSubject.ID)
	fmt.Println("subject type:", doc.CredentialSubject.Type)
	fmt.Println("date of birth:", doc.CredentialSubject.DateOfBirth)
	// Output:
	// type: [VerifiableCredential EuropeanDigitalCredential]
	// subject ID: urn:epass:person:1335bfa5-3d8f-405c-8eb3-958e1becea8c
	// subject type: Person
	// date of birth: 1972-06-19T00:00:00
}

func ExampleDiplomaDocument_AddCredentialSubject() {
	doc := &education.DiplomaDocument{
		Type: []string{"VerifiableCredential", "EuropeanDigitalCredential"},
	}
	doc.AddCredentialSubject("1990-05-15T00:00:00", "2020-06-30T00:00:00", "")

	fmt.Println("subject type:", doc.CredentialSubject.Type)
	fmt.Println("date of birth:", doc.CredentialSubject.DateOfBirth)
	fmt.Println("awarding date:", doc.CredentialSubject.HasClaim.AwardedBy.AwardingDate)
	// Output:
	// subject type: Person
	// date of birth: 1990-05-15T00:00:00
	// awarding date: 2020-06-30T00:00:00
}

func ExampleDiplomaDocument_Marshal() {
	doc := education.NewDiploma()
	m, err := doc.Marshal()
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println("has type:", m["type"] != nil)
	fmt.Println("has credentialSubject:", m["credentialSubject"] != nil)
	fmt.Println("has credentialSchema:", m["credentialSchema"] != nil)
	// Output:
	// has type: true
	// has credentialSubject: true
	// has credentialSchema: true
}
