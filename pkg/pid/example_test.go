package pid_test

import (
	"fmt"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/pid"
)

func ExampleDocument_Marshal() {
	doc := &pid.Document{
		Identity: &model.Identity{
			AuthenticSourcePersonID: "person-001",
			FamilyName:     "Andersson",
			GivenName:      "Erik",
			BirthDate:      "1985-03-15",
			BirthPlace:     "Stockholm",
			Nationality:    []string{"SE"},
			IssuingCountry: "SE",
		},
	}

	m, err := doc.Marshal()
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println("family_name:", m["family_name"])
	fmt.Println("given_name:", m["given_name"])
	fmt.Println("birth_date:", m["birth_date"])
	fmt.Println("birth_place:", m["birth_place"])
	fmt.Println("issuing_country:", m["issuing_country"])
	// Output:
	// family_name: Andersson
	// given_name: Erik
	// birth_date: 1985-03-15
	// birth_place: Stockholm
	// issuing_country: SE
}
