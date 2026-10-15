package oeapi

import "testing"

func TestPersonFlatten(t *testing.T) {
	p := &Person{
		PersonID:      "p-1",
		PrimaryCode:   &CodeRef{CodeType: "identifier", Code: "s12345678"},
		GivenName:     "Lisa",
		Surname:       "Andersson",
		SurnamePrefix: "van",
		DisplayName:   "Lisa van Andersson",
		DateOfBirth:   "1995-05-15",
		Nationality:   &Country{Alpha2: "SE"},
		Email:         "lisa@example.org",
		Affiliations:  []string{"student"},
		OtherCodes:    []CodeRef{{CodeType: "nationalIdentityNumber", Code: "199505151234"}},
	}
	m := p.Flatten()

	checks := map[string]any{
		"personId":                         "p-1",
		"primaryCode.code":                 "s12345678",
		"givenName":                        "Lisa",
		"surname":                          "Andersson",
		"dateOfBirth":                      "1995-05-15",
		"nationality":                      "SE",
		"email":                            "lisa@example.org",
		"otherCode.nationalIdentityNumber": "199505151234",
	}
	for k, want := range checks {
		if m[k] != want {
			t.Errorf("Flatten()[%q] = %v, want %v", k, m[k], want)
		}
	}
}

func TestProgrammeAssociationFlatten(t *testing.T) {
	a := &ProgrammeOfferingAssociation{
		AssociationID: "a-1",
		Role:          "student",
		State:         "associated",
		ProgrammeOffering: &ProgrammeOffering{
			Name: []LanguageTypedString{{Language: "nl-NL", Value: "Biologie"}, {Language: "en-GB", Value: "Biology offering"}},
			Programme: &Programme{
				Name:         []LanguageTypedString{{Language: "en-GB", Value: "Biology"}},
				Abbreviation: "BIO",
				Level:        "master",
			},
			Organisation: &Organisation{ShortName: "SURF"},
		},
		Result: &Result{State: "completed", Pass: "passed", Score: "9", StudyLoad: &StudyLoad{StudyLoadUnit: "ects", Value: 3}},
	}
	m := a.Flatten()

	checks := map[string]any{
		"role":                            "student",
		"state":                           "associated",
		"offering.name":                   "Biology offering",
		"offering.programme.name":         "Biology",
		"offering.programme.level":        "master",
		"offering.organisation.shortName": "SURF",
		"result.pass":                     "passed",
		"result.score":                    "9",
		"result.studyLoad.unit":           "ects",
	}
	for k, want := range checks {
		if m[k] != want {
			t.Errorf("Flatten()[%q] = %v, want %v", k, m[k], want)
		}
	}
}

func TestLocalizedValue(t *testing.T) {
	got := localizedValue([]LanguageTypedString{
		{Language: "nl-NL", Value: "Biologie"},
		{Language: "en-GB", Value: "Biology"},
	})
	if got != "Biology" {
		t.Errorf("localizedValue = %q, want Biology", got)
	}
	if got := localizedValue(nil); got != "" {
		t.Errorf("localizedValue(nil) = %q, want empty", got)
	}
	if got := localizedValue([]LanguageTypedString{{Language: "nl-NL", Value: "Alleen NL"}}); got != "Alleen NL" {
		t.Errorf("localizedValue fallback = %q, want Alleen NL", got)
	}
}

func TestMergeMaps(t *testing.T) {
	a := map[string]any{"x": 1, "y": 2}
	b := map[string]any{"y": 3, "z": 4}
	m := MergeMaps(a, b)
	if m["x"] != 1 || m["y"] != 3 || m["z"] != 4 {
		t.Errorf("MergeMaps = %v", m)
	}
}
