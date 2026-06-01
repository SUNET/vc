package sdjwtvc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClaimJSONPath(t *testing.T) {
	tts := []struct {
		name  string
		claim Claim
		want  string
	}{
		{
			name:  "single path element",
			claim: Claim{Path: []*string{new("given_name")}},
			want:  "$.given_name",
		},
		{
			name:  "nested path",
			claim: Claim{Path: []*string{new("address"), new("country")}},
			want:  "$.address.country",
		},
		{
			name:  "nil element is wildcard",
			claim: Claim{Path: []*string{new("items"), nil, new("name")}},
			want:  "$.items[*].name",
		},
		{
			name:  "nil path returns empty",
			claim: Claim{Path: nil},
			want:  "",
		},
		{
			name:  "empty path returns root",
			claim: Claim{Path: []*string{}},
			want:  "$",
		},
		{
			name:  "nil claim returns empty",
			claim: Claim{},
			want:  "",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.claim.JSONPath()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestVCTMSRIIntegrity(t *testing.T) {
	v := &VCTM{VCT: "https://example.com/credential/test"}

	t.Run("from marshalled JSON", func(t *testing.T) {
		sri, err := v.SRIIntegrity(nil)
		assert.NoError(t, err)
		assert.Contains(t, sri, "sha256-")
		assert.Len(t, sri, len("sha256-")+44) // base64 of sha256 is 44 chars
	})

	t.Run("from raw bytes", func(t *testing.T) {
		raw := []byte(`{"vct":"https://example.com/credential/test"}`)
		sri, err := v.SRIIntegrity(raw)
		assert.NoError(t, err)
		assert.Contains(t, sri, "sha256-")
	})

	t.Run("same bytes produce same hash", func(t *testing.T) {
		raw := []byte(`{"vct":"test"}`)
		sri1, _ := v.SRIIntegrity(raw)
		sri2, _ := v.SRIIntegrity(raw)
		assert.Equal(t, sri1, sri2)
	})
}

func TestVCTMAttributes(t *testing.T) {
	v := &VCTM{
		Claims: []Claim{
			{
				Path:    []*string{new("given_name")},
				Display: []ClaimDisplay{{Locale: "en", Label: "First Name"}},
			},
			{
				Path:    []*string{new("family_name")},
				Display: []ClaimDisplay{{Locale: "en", Label: "Last Name"}, {Locale: "sv", Label: "Efternamn"}},
			},
			{
				Path:    []*string{new("address"), new("country")},
				Display: []ClaimDisplay{{Locale: "en", Label: "Country"}},
			},
			{
				Path:    []*string{new("no_display")},
				Display: nil,
			},
		},
	}

	attrs := v.Attributes()

	t.Run("english locale", func(t *testing.T) {
		en := attrs["en"]
		assert.Equal(t, []string{"given_name"}, en["First Name"])
		assert.Equal(t, []string{"family_name"}, en["Last Name"])
		assert.Equal(t, []string{"address", "country"}, en["Country"])
	})

	t.Run("swedish locale", func(t *testing.T) {
		sv := attrs["sv"]
		assert.Equal(t, []string{"family_name"}, sv["Efternamn"])
	})

	t.Run("claims without display are excluded", func(t *testing.T) {
		for _, locale := range attrs {
			for label := range locale {
				assert.NotEqual(t, "no_display", label)
			}
		}
	})
}

func TestVCTMAttributesWithoutObjects(t *testing.T) {
	v := &VCTM{
		Claims: []Claim{
			{
				Path:    []*string{new("given_name")},
				Display: []ClaimDisplay{{Locale: "en", Label: "First Name"}},
			},
			{
				Path:    []*string{new("address"), new("country")},
				Display: []ClaimDisplay{{Locale: "en", Label: "Country"}},
			},
			{
				Path:    []*string{new("no_display")},
				Display: nil,
			},
		},
	}

	attrs := v.AttributesWithoutObjects()

	t.Run("single-path claims included", func(t *testing.T) {
		assert.Equal(t, []string{"given_name"}, attrs["en"]["First Name"])
	})

	t.Run("multi-path claims excluded", func(t *testing.T) {
		_, exists := attrs["en"]["Country"]
		assert.False(t, exists)
	})

	t.Run("claims without display excluded", func(t *testing.T) {
		_, exists := attrs["en"]["no_display"]
		assert.False(t, exists)
	})
}

func TestVCTMClaimJSONPath(t *testing.T) {
	v := &VCTM{
		Claims: []Claim{
			{
				Path:  []*string{new("given_name")},
				SVGID: "first_name",
			},
			{
				Path:  []*string{new("address"), new("country")},
				SVGID: "",
			},
			{
				Path:  []*string{new("items"), nil},
				SVGID: "all_items",
			},
		},
	}

	t.Run("returns paths and displayable map", func(t *testing.T) {
		jp, err := v.ClaimJSONPath()
		assert.NoError(t, err)
		assert.Equal(t, "$.given_name", jp.Displayable["first_name"])
		assert.Equal(t, "$.items[*]", jp.Displayable["all_items"])
		_, exists := jp.Displayable[""]
		assert.False(t, exists, "empty SVGID should not be in displayable map")

		assert.Equal(t, []string{"$.given_name", "$.address.country", "$.items[*]"}, jp.AllClaims)
	})

	t.Run("nil claims returns error", func(t *testing.T) {
		empty := &VCTM{}
		_, err := empty.ClaimJSONPath()
		assert.Error(t, err)
	})
}

func TestVCTMPresentation(t *testing.T) {
	t.Run("leaf claims resolved from data", func(t *testing.T) {
		v := &VCTM{
			Claims: []Claim{
				{Path: []*string{new("given_name")}, Display: []ClaimDisplay{{Locale: "en", Label: "First Name"}}},
				{Path: []*string{new("hidden")}, Display: nil},
			},
		}
		data := map[string]any{"given_name": "Helen", "hidden": "secret"}
		result := v.Presentation(data)

		assert.Len(t, result, 1)
		entry := result["given_name"].(map[string]any)
		assert.Equal(t, "First Name", entry["label"])
		assert.Equal(t, "Helen", entry["value"])
	})

	t.Run("parent with children", func(t *testing.T) {
		v := &VCTM{
			Claims: []Claim{
				{Path: []*string{new("address")}, Display: []ClaimDisplay{{Locale: "en", Label: "Address"}}},
				{Path: []*string{new("address"), new("country")}, Display: []ClaimDisplay{{Locale: "en", Label: "Country"}}},
				{Path: []*string{new("address"), new("street")}, Display: []ClaimDisplay{{Locale: "en", Label: "Street"}}},
			},
		}
		data := map[string]any{
			"address": map[string]any{"country": "SE", "street": "Tulegatan"},
		}
		result := v.Presentation(data)

		assert.Len(t, result, 1)
		addr := result["address"].(map[string]any)
		assert.Equal(t, "Address", addr["label"])
		children := addr["children"].(map[string]any)
		assert.Equal(t, "SE", children["country"].(map[string]any)["value"])
		assert.Equal(t, "Tulegatan", children["street"].(map[string]any)["value"])
	})

	t.Run("children without displayable parent are flat leaf claims", func(t *testing.T) {
		v := &VCTM{
			Claims: []Claim{
				{Path: []*string{new("address")}, Display: nil},
				{Path: []*string{new("address"), new("country")}, Display: []ClaimDisplay{{Locale: "en", Label: "Country"}}},
				{Path: []*string{new("address"), new("street")}, Display: []ClaimDisplay{{Locale: "en", Label: "Street"}}},
			},
		}
		data := map[string]any{
			"address": map[string]any{"country": "SE", "street": "Tulegatan"},
		}
		result := v.Presentation(data)

		assert.Len(t, result, 2)
		country := result["address.country"].(map[string]any)
		assert.Equal(t, "Country", country["label"])
		assert.Equal(t, "SE", country["value"])
		street := result["address.street"].(map[string]any)
		assert.Equal(t, "Street", street["label"])
		assert.Equal(t, "Tulegatan", street["value"])
	})

	t.Run("nil data returns nil", func(t *testing.T) {
		v := &VCTM{Claims: []Claim{
			{Path: []*string{new("x")}, Display: []ClaimDisplay{{Locale: "en", Label: "X"}}},
		}}
		assert.Nil(t, v.Presentation(nil))
	})

	t.Run("empty claims returns nil", func(t *testing.T) {
		v := &VCTM{Claims: []Claim{}}
		result := v.Presentation(map[string]any{"x": "y"})
		assert.Nil(t, result)
	})

	t.Run("missing data values are skipped", func(t *testing.T) {
		v := &VCTM{
			Claims: []Claim{
				{Path: []*string{new("given_name")}, Display: []ClaimDisplay{{Locale: "en", Label: "First Name"}}},
				{Path: []*string{new("missing")}, Display: []ClaimDisplay{{Locale: "en", Label: "Missing"}}},
			},
		}
		data := map[string]any{"given_name": "Helen"}
		result := v.Presentation(data)

		assert.Len(t, result, 1)
		assert.NotNil(t, result["given_name"])
	})

	t.Run("array wildcard path does not panic", func(t *testing.T) {
		v := &VCTM{
			Claims: []Claim{
				{Path: []*string{new("nationalities"), nil}, Display: []ClaimDisplay{{Locale: "en", Label: "Nationalities"}}},
				{Path: []*string{new("given_name")}, Display: []ClaimDisplay{{Locale: "en", Label: "First Name"}}},
			},
		}
		data := map[string]any{
			"nationalities": []any{"DE", "SE"},
			"given_name":    "Helen",
		}
		assert.NotPanics(t, func() {
			result := v.Presentation(data)
			// Wildcard orphan emits as a flat leaf with the array value.
			nat := result["nationalities"].(map[string]any)
			assert.Equal(t, "Nationalities", nat["label"])
			assert.Equal(t, []any{"DE", "SE"}, nat["value"])
			// Normal leaf still works.
			gn := result["given_name"].(map[string]any)
			assert.Equal(t, "Helen", gn["value"])
		})
	})

	t.Run("parent with only array-wildcard children emits value", func(t *testing.T) {
		v := &VCTM{
			Claims: []Claim{
				{Path: []*string{new("nationalities")}, Display: []ClaimDisplay{{Locale: "en", Label: "Nationalities"}}},
				{Path: []*string{new("nationalities"), nil}, Display: []ClaimDisplay{{Locale: "en", Label: "Nationality"}}},
				{Path: []*string{new("given_name")}, Display: []ClaimDisplay{{Locale: "en", Label: "First Name"}}},
			},
		}
		data := map[string]any{
			"nationalities": []any{"DE", "SE"},
			"given_name":    "Helen",
		}
		result := v.Presentation(data)
		// Parent with wildcard-only children should appear as a leaf with the array value.
		nat := result["nationalities"].(map[string]any)
		assert.Equal(t, "Nationalities", nat["label"])
		assert.Equal(t, []any{"DE", "SE"}, nat["value"])
		assert.Nil(t, nat["children"])
		// Normal leaf still works.
		gn := result["given_name"].(map[string]any)
		assert.Equal(t, "Helen", gn["value"])
	})

	t.Run("parent with nil Path[0] does not panic", func(t *testing.T) {
		v := &VCTM{
			Claims: []Claim{
				{Path: []*string{nil}, Display: []ClaimDisplay{{Locale: "en", Label: "Root"}}},
				{Path: []*string{nil, new("child")}, Display: []ClaimDisplay{{Locale: "en", Label: "Child"}}},
			},
		}
		data := map[string]any{"child": "val"}
		assert.NotPanics(t, func() {
			v.Presentation(data)
		})
	})

	t.Run("empty path claim does not panic", func(t *testing.T) {
		v := &VCTM{
			Claims: []Claim{
				{Path: []*string{}, Display: []ClaimDisplay{{Locale: "en", Label: "Empty"}}},
				{Path: []*string{new("given_name")}, Display: []ClaimDisplay{{Locale: "en", Label: "First Name"}}},
			},
		}
		data := map[string]any{"given_name": "Helen"}
		assert.NotPanics(t, func() {
			result := v.Presentation(data)
			assert.Len(t, result, 1)
			assert.Equal(t, "Helen", result["given_name"].(map[string]any)["value"])
		})
	})
	t.Run("multi-segment orphan leaves emit as flat entries", func(t *testing.T) {
		v := &VCTM{
			Claims: []Claim{
				// No displayable parent for address or birth — both are orphaned leaves.
				{Path: []*string{new("address"), new("country")}, Display: []ClaimDisplay{{Locale: "en", Label: "Address Country"}}},
				{Path: []*string{new("birth"), new("country")}, Display: []ClaimDisplay{{Locale: "en", Label: "Birth Country"}}},
			},
		}
		data := map[string]any{
			"address": map[string]any{"country": "SE"},
			"birth":   map[string]any{"country": "DE"},
		}
		result := v.Presentation(data)
		assert.Len(t, result, 2)
		// Orphan leaves are keyed by joined path segments to avoid collisions.
		addr := result["address.country"].(map[string]any)
		assert.Equal(t, "Address Country", addr["label"])
		assert.Equal(t, "SE", addr["value"])
		birth := result["birth.country"].(map[string]any)
		assert.Equal(t, "Birth Country", birth["label"])
		assert.Equal(t, "DE", birth["value"])
	})
	t.Run("deeply nested orphan leaves (diploma pattern)", func(t *testing.T) {
		v := &VCTM{
			Claims: []Claim{
				{Path: []*string{new("credentialSubject"), new("givenName"), new("und")}, Display: []ClaimDisplay{{Locale: "en", Label: "Given name"}}},
				{Path: []*string{new("credentialSubject"), new("familyName"), new("und")}, Display: []ClaimDisplay{{Locale: "en", Label: "Family name"}}},
				{Path: []*string{new("credentialSubject"), new("dateOfBirth")}, Display: []ClaimDisplay{{Locale: "en", Label: "Date of birth"}}},
			},
		}
		data := map[string]any{
			"credentialSubject": map[string]any{
				"givenName":   map[string]any{"und": "Helen"},
				"familyName":  map[string]any{"und": "Mirren"},
				"dateOfBirth": "1990-01-15",
			},
		}
		result := v.Presentation(data)
		assert.Len(t, result, 3)
		// Each entry is a flat {label, value} — no nested maps without label.
		gn := result["credentialSubject.givenName.und"].(map[string]any)
		assert.Equal(t, "Given name", gn["label"])
		assert.Equal(t, "Helen", gn["value"])
		fn := result["credentialSubject.familyName.und"].(map[string]any)
		assert.Equal(t, "Family name", fn["label"])
		assert.Equal(t, "Mirren", fn["value"])
		dob := result["credentialSubject.dateOfBirth"].(map[string]any)
		assert.Equal(t, "Date of birth", dob["label"])
		assert.Equal(t, "1990-01-15", dob["value"])
	})
}

func TestVCTMPresentationPIDRealistic(t *testing.T) {
	// Mirror the real PID VCTM: flat claims, address with 7 children,
	// place_of_birth with 3 children, nationalities with array wildcard.
	vctm := &VCTM{
		Claims: []Claim{
			// --- flat leaves (some with svg_id, some without) ---
			{Path: []*string{new("family_name")}, SVGID: "family_name", Display: []ClaimDisplay{{Locale: "en-US", Label: "Last name"}}},
			{Path: []*string{new("given_name")}, SVGID: "given_name", Display: []ClaimDisplay{{Locale: "en-US", Label: "First name"}}},
			{Path: []*string{new("birthdate")}, SVGID: "birth_date", Display: []ClaimDisplay{{Locale: "en-US", Label: "Date of birth"}}},
			{Path: []*string{new("personal_administrative_number")}, SVGID: "personal_administrative_number", Display: []ClaimDisplay{{Locale: "en-US", Label: "Personal ID"}}},
			{Path: []*string{new("sex")}, Display: []ClaimDisplay{{Locale: "en-US", Label: "Sex"}}},
			// --- address parent + children ---
			{Path: []*string{new("address")}, Display: []ClaimDisplay{{Locale: "en-US", Label: "Address"}}},
			{Path: []*string{new("address"), new("house_number")}, Display: []ClaimDisplay{{Locale: "en-US", Label: "Residence number"}}},
			{Path: []*string{new("address"), new("street_address")}, Display: []ClaimDisplay{{Locale: "en-US", Label: "Residence street"}}},
			{Path: []*string{new("address"), new("locality")}, Display: []ClaimDisplay{{Locale: "en-US", Label: "City of residence"}}},
			{Path: []*string{new("address"), new("region")}, Display: []ClaimDisplay{{Locale: "en-US", Label: "State of residence"}}},
			{Path: []*string{new("address"), new("postal_code")}, Display: []ClaimDisplay{{Locale: "en-US", Label: "Residence ZIP"}}},
			{Path: []*string{new("address"), new("country")}, Display: []ClaimDisplay{{Locale: "en-US", Label: "Country of residence"}}},
			{Path: []*string{new("address"), new("formatted")}, Display: []ClaimDisplay{{Locale: "en-US", Label: "Full address"}}},
			// --- place_of_birth parent + children ---
			{Path: []*string{new("place_of_birth")}, Display: []ClaimDisplay{{Locale: "en-US", Label: "Place of birth"}}},
			{Path: []*string{new("place_of_birth"), new("locality")}, Display: []ClaimDisplay{{Locale: "en-US", Label: "City of birth"}}},
			{Path: []*string{new("place_of_birth"), new("region")}, Display: []ClaimDisplay{{Locale: "en-US", Label: "Region of birth"}}},
			{Path: []*string{new("place_of_birth"), new("country")}, Display: []ClaimDisplay{{Locale: "en-US", Label: "Country of birth"}}},
			// --- nationalities parent + array wildcard child ---
			{Path: []*string{new("nationalities")}, Display: []ClaimDisplay{{Locale: "en-US", Label: "Nationalities"}}},
			{Path: []*string{new("nationalities"), nil}, Display: []ClaimDisplay{{Locale: "en-US", Label: "Nationality"}}},
			// --- metadata without display (should be excluded) ---
			{Path: []*string{new("iss")}, Display: nil},
			{Path: []*string{new("vct")}, Display: nil},
		},
	}

	data := map[string]any{
		"iss":                            "https://issuer.example.com",
		"vct":                            "urn:eu.europa.ec.eudi:pid:1",
		"family_name":                    "Sansen",
		"given_name":                     "Helen",
		"birthdate":                      "1990-01-15",
		"personal_administrative_number": "199001152386",
		"sex":                            "0",
		"address": map[string]any{
			"house_number":   "11",
			"street_address": "Tulegatan",
			"locality":       "Stockholm",
			"region":         "Stockholm",
			"postal_code":    "11353",
			"country":        "SE",
			"formatted":      "Tulegatan 11, 11353 Stockholm, SE",
		},
		"place_of_birth": map[string]any{
			"locality": "Lund",
			"region":   "Skåne",
			"country":  "SE",
		},
		"nationalities": []any{"SE"},
	}

	result := vctm.Presentation(data)

	// --- flat leaves ---
	t.Run("flat leaves", func(t *testing.T) {
		fn := result["family_name"].(map[string]any)
		assert.Equal(t, "Last name", fn["label"])
		assert.Equal(t, "Sansen", fn["value"])

		gn := result["given_name"].(map[string]any)
		assert.Equal(t, "First name", gn["label"])
		assert.Equal(t, "Helen", gn["value"])

		bd := result["birthdate"].(map[string]any)
		assert.Equal(t, "Date of birth", bd["label"])
		assert.Equal(t, "1990-01-15", bd["value"])

		pan := result["personal_administrative_number"].(map[string]any)
		assert.Equal(t, "Personal ID", pan["label"])
		assert.Equal(t, "199001152386", pan["value"])

		sex := result["sex"].(map[string]any)
		assert.Equal(t, "Sex", sex["label"])
		assert.Equal(t, "0", sex["value"])
	})

	// --- address parent with children ---
	t.Run("address parent with children", func(t *testing.T) {
		addr := result["address"].(map[string]any)
		assert.Equal(t, "Address", addr["label"])
		assert.Nil(t, addr["value"], "parent should not have a value")

		children := addr["children"].(map[string]any)
		assert.Len(t, children, 7)

		assert.Equal(t, "11", children["house_number"].(map[string]any)["value"])
		assert.Equal(t, "Residence number", children["house_number"].(map[string]any)["label"])

		assert.Equal(t, "Tulegatan", children["street_address"].(map[string]any)["value"])
		assert.Equal(t, "Stockholm", children["locality"].(map[string]any)["value"])
		assert.Equal(t, "Stockholm", children["region"].(map[string]any)["value"])
		assert.Equal(t, "11353", children["postal_code"].(map[string]any)["value"])
		assert.Equal(t, "SE", children["country"].(map[string]any)["value"])
		assert.Equal(t, "Tulegatan 11, 11353 Stockholm, SE", children["formatted"].(map[string]any)["value"])
	})

	// --- place_of_birth parent with children ---
	t.Run("place_of_birth parent with children", func(t *testing.T) {
		pob := result["place_of_birth"].(map[string]any)
		assert.Equal(t, "Place of birth", pob["label"])

		children := pob["children"].(map[string]any)
		assert.Len(t, children, 3)

		assert.Equal(t, "Lund", children["locality"].(map[string]any)["value"])
		assert.Equal(t, "City of birth", children["locality"].(map[string]any)["label"])
		assert.Equal(t, "Skåne", children["region"].(map[string]any)["value"])
		assert.Equal(t, "SE", children["country"].(map[string]any)["value"])
	})

	// --- nationalities: parent with array-wildcard child → leaf with value ---
	t.Run("nationalities emits as leaf with array value", func(t *testing.T) {
		nat := result["nationalities"].(map[string]any)
		assert.Equal(t, "Nationalities", nat["label"])
		assert.Equal(t, []any{"SE"}, nat["value"])
		assert.Nil(t, nat["children"], "wildcard-only parent should not have children")
	})

	// --- metadata claims without display are excluded ---
	t.Run("non-displayable claims excluded", func(t *testing.T) {
		assert.Nil(t, result["iss"])
		assert.Nil(t, result["vct"])
	})
}

func TestVCTMSVGValues(t *testing.T) {
	v := &VCTM{
		Claims: []Claim{
			{Path: []*string{new("given_name")}, SVGID: "first_name", Display: []ClaimDisplay{{Locale: "en", Label: "First Name"}}},
			{Path: []*string{new("family_name")}, SVGID: "last_name", Display: []ClaimDisplay{{Locale: "en", Label: "Last Name"}}},
			{Path: []*string{new("address"), new("country")}, SVGID: "country", Display: []ClaimDisplay{{Locale: "en", Label: "Country"}}},
			{Path: []*string{new("no_svg")}, SVGID: "", Display: []ClaimDisplay{{Locale: "en", Label: "No SVG"}}},
		},
	}

	data := map[string]any{
		"given_name":  "Helen",
		"family_name": "Mirren",
		"address":     map[string]any{"country": "SE"},
	}

	t.Run("returns svg_id keyed values", func(t *testing.T) {
		result := v.SVGValues(data)
		assert.Len(t, result, 3)
		assert.Equal(t, SVGValue{Label: "First Name", Value: "Helen"}, result["first_name"])
		assert.Equal(t, SVGValue{Label: "Last Name", Value: "Mirren"}, result["last_name"])
		assert.Equal(t, SVGValue{Label: "Country", Value: "SE"}, result["country"])
	})

	t.Run("skips claims without svg_id", func(t *testing.T) {
		result := v.SVGValues(data)
		_, exists := result["no_svg"]
		assert.False(t, exists)
	})

	t.Run("nil data returns nil", func(t *testing.T) {
		assert.Nil(t, v.SVGValues(nil))
	})

	t.Run("missing values are skipped", func(t *testing.T) {
		sparse := map[string]any{"given_name": "Helen"}
		result := v.SVGValues(sparse)
		assert.Len(t, result, 1)
		assert.Equal(t, "Helen", result["first_name"].Value)
	})
}

func TestWalkPath(t *testing.T) {
	data := map[string]any{
		"name":     "Helen",
		"empty_s":  "",
		"empty_a":  []any{},
		"empty_m":  map[string]any{},
		"items":    []any{"a", "b"},
		"nested":   map[string]any{"key": "val"},
		"zero_int": 0,
		"falsy":    false,
	}

	t.Run("empty path returns nil", func(t *testing.T) {
		assert.Nil(t, walkPath(data, []*string{}))
	})

	t.Run("nil-only path returns nil", func(t *testing.T) {
		assert.Nil(t, walkPath(data, []*string{nil}))
	})

	t.Run("resolves normal key", func(t *testing.T) {
		assert.Equal(t, "Helen", walkPath(data, []*string{new("name")}))
	})

	t.Run("empty string normalized to nil", func(t *testing.T) {
		assert.Nil(t, walkPath(data, []*string{new("empty_s")}))
	})

	t.Run("empty slice normalized to nil", func(t *testing.T) {
		assert.Nil(t, walkPath(data, []*string{new("empty_a")}))
	})

	t.Run("empty map normalized to nil", func(t *testing.T) {
		assert.Nil(t, walkPath(data, []*string{new("empty_m")}))
	})

	t.Run("non-empty slice preserved", func(t *testing.T) {
		assert.Equal(t, []any{"a", "b"}, walkPath(data, []*string{new("items")}))
	})

	t.Run("non-empty map preserved", func(t *testing.T) {
		assert.Equal(t, map[string]any{"key": "val"}, walkPath(data, []*string{new("nested")}))
	})

	t.Run("zero int preserved", func(t *testing.T) {
		assert.Equal(t, 0, walkPath(data, []*string{new("zero_int")}))
	})

	t.Run("false bool preserved", func(t *testing.T) {
		assert.Equal(t, false, walkPath(data, []*string{new("falsy")}))
	})

	t.Run("array wildcard returns parent value", func(t *testing.T) {
		assert.Equal(t, []any{"a", "b"}, walkPath(data, []*string{new("items"), nil}))
	})

	t.Run("bracket index resolves array element", func(t *testing.T) {
		assert.Equal(t, "a", walkPath(data, []*string{new("items[0]")}))
		assert.Equal(t, "b", walkPath(data, []*string{new("items[1]")}))
	})

	t.Run("bracket index out of bounds returns nil", func(t *testing.T) {
		assert.Nil(t, walkPath(data, []*string{new("items[5]")}))
	})

	t.Run("bracket index on non-array returns nil", func(t *testing.T) {
		assert.Nil(t, walkPath(data, []*string{new("name[0]")}))
	})

	t.Run("bracket index with nested traversal", func(t *testing.T) {
		deep := map[string]any{
			"claims": []any{
				map[string]any{"title": "PhD"},
				map[string]any{"title": "MSc"},
			},
		}
		assert.Equal(t, "PhD", walkPath(deep, []*string{new("claims[0]"), new("title")}))
		assert.Equal(t, "MSc", walkPath(deep, []*string{new("claims[1]"), new("title")}))
	})
}

func TestIsChildOfDisplayableParent(t *testing.T) {
	parents := map[string]bool{
		"$.address": true,
		"$.items":   true,
	}

	tts := []struct {
		name string
		path []*string
		want bool
	}{
		{
			name: "child of displayable parent",
			path: []*string{new("address"), new("country")},
			want: true,
		},
		{
			name: "not a child",
			path: []*string{new("given_name")},
			want: false,
		},
		{
			name: "single element is never a child",
			path: []*string{new("address")},
			want: false,
		},
		{
			name: "nil path element (array wildcard)",
			path: []*string{new("items"), nil, new("name")},
			want: true,
		},
		{
			name: "empty path",
			path: []*string{},
			want: false,
		},
		{
			name: "nil path",
			path: nil,
			want: false,
		},
		{
			name: "unrelated nested path",
			path: []*string{new("other"), new("field")},
			want: false,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got := isChildOfDisplayableParent(tt.path, parents)
			assert.Equal(t, tt.want, got)
		})
	}
}
