package model_test

import (
	"fmt"

	"github.com/SUNET/vc/pkg/model"
)

func ExampleBoolPtr() {
	p := model.BoolPtr(true)
	fmt.Println(*p)
	// Output:
	// true
}

func ExampleBoolVal() {
	t := true
	fmt.Println(model.BoolVal(&t, false))
	fmt.Println(model.BoolVal(nil, false))
	fmt.Println(model.BoolVal(nil, true))
	// Output:
	// true
	// false
	// true
}

func ExampleIdentity_Marshal() {
	identity := &model.Identity{
		FamilyName: "Svensson",
		GivenName:  "Magnus",
		BirthDate:  "1970-01-01",
	}

	doc, err := identity.Marshal()
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println("family_name:", doc["family_name"])
	fmt.Println("given_name:", doc["given_name"])
	fmt.Println("birth_date:", doc["birth_date"])
	// Output:
	// family_name: Svensson
	// given_name: Magnus
	// birth_date: 1970-01-01
}
