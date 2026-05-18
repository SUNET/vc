package sdjwtvc

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVCTM_Attributes(t *testing.T) {
	label1 := "Name"
	label2 := "Email"
	name := "name"
	email := "email"

	vctm := &VCTM{
		Claims: []Claim{
			{
				Path: []*string{&name},
				Display: []ClaimDisplay{
					{
						Locale: "en",
						Label:  label1,
					},
					{
						Locale: "fr",
						Label:  "Nom",
					},
				},
			},
			{
				Path: []*string{&email},
				Display: []ClaimDisplay{
					{
						Locale: "en",
						Label:  label2,
					},
				},
			},
		},
	}

	attrs := vctm.Attributes()

	assert.NotNil(t, attrs)
	assert.Contains(t, attrs, "en")
	assert.Contains(t, attrs, "fr")

	assert.Contains(t, attrs["en"], label1)
	assert.Contains(t, attrs["en"], label2)
	assert.Equal(t, []string{"name"}, attrs["en"][label1])
	assert.Equal(t, []string{"email"}, attrs["en"][label2])

	assert.Contains(t, attrs["fr"], "Nom")
	assert.Equal(t, []string{"name"}, attrs["fr"]["Nom"])
}

func TestVCTM_Attributes_RealMetadata(t *testing.T) {
	metadataDir := "../../metadata"

	testCases := []struct {
		filename        string
		expectedLangs   []string
		expectedLabels  map[string][]string // language -> list of labels
		samplePathCheck map[string]string   // label -> expected path (first one)
	}{
		{
			filename:      "vctm_pid.json",
			expectedLangs: []string{"en-US"},
			expectedLabels: map[string][]string{
				"en-US": {"Last name", "First name", "Date of birth", "Nationality"},
			},
			samplePathCheck: map[string]string{
				"Last name":     "family_name",
				"First name":    "given_name",
				"Date of birth": "birthdate",
				// Nationality uses path ["nationalities", null] so we can't check a single string path
			},
		},
		{
			filename:      "vctm_ehic.json",
			expectedLangs: []string{"en-US"},
			expectedLabels: map[string][]string{
				"en-US": {"Social Security PIN", "Issuing authority", "Issuing authority id", "Issuing authority name"},
			},
			samplePathCheck: map[string]string{
				"Social Security PIN":    "personal_administrative_number",
				"Issuing authority id":   "id",
				"Issuing authority name": "name",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.filename, func(t *testing.T) {
			// Load the VCTM file
			filePath := filepath.Join(metadataDir, tc.filename)
			data, err := os.ReadFile(filePath) // #nosec G304
			require.NoError(t, err, "Failed to read %s", tc.filename)

			var vctm VCTM
			err = json.Unmarshal(data, &vctm)
			require.NoError(t, err, "Failed to unmarshal %s", tc.filename)

			// Test Attributes()
			attrs := vctm.Attributes()
			assert.NotNil(t, attrs)

			// Check expected languages are present
			for _, lang := range tc.expectedLangs {
				assert.Contains(t, attrs, lang, "Missing language: %s", lang)
			}

			// Check expected labels are present for each language
			for lang, expectedLabels := range tc.expectedLabels {
				require.Contains(t, attrs, lang)
				for _, label := range expectedLabels {
					assert.Contains(t, attrs[lang], label, "Missing label '%s' for language %s", label, lang)
				}
			}

			// Check specific path mappings
			for label, expectedPath := range tc.samplePathCheck {
				for lang := range tc.expectedLabels {
					if paths, ok := attrs[lang][label]; ok {
						assert.NotEmpty(t, paths, "Label '%s' should have paths", label)
						// Check if the expected path is in the paths slice
						found := slices.Contains(paths, expectedPath)
						assert.True(t, found, "Expected path '%s' not found for label '%s'", expectedPath, label)
					}
				}
			}
		})
	}
}

func TestVCTM_Attributes_EmptyClaims(t *testing.T) {
	vctm := &VCTM{
		Claims: []Claim{},
	}

	attrs := vctm.Attributes()
	assert.NotNil(t, attrs)
	assert.Empty(t, attrs)
}

func TestVCTM_AttributesWithoutObjects(t *testing.T) {
	// Set up test data with both simple and object attributes
	simpleName := "name"
	simpleEmail := "email"
	simpleAge := "age"
	addressPath1 := "address"
	addressPath2 := "street"
	contactPath1 := "contact"
	contactPath2 := "phone"

	vctm := &VCTM{
		Claims: []Claim{
			{
				// Simple attribute - should be included
				Path: []*string{&simpleName},
				Display: []ClaimDisplay{
					{
						Locale: "en",
						Label:  "Name",
					},
					{
						Locale: "fr",
						Label:  "Nom",
					},
				},
			},
			{
				// Object attribute (nested) - should be excluded
				Path: []*string{&addressPath1, &addressPath2},
				Display: []ClaimDisplay{
					{
						Locale: "en",
						Label:  "Street Address",
					},
				},
			},
			{
				// Simple attribute - should be included
				Path: []*string{&simpleEmail},
				Display: []ClaimDisplay{
					{
						Locale: "en",
						Label:  "Email",
					},
				},
			},
			{
				// Object attribute (nested) - should be excluded
				Path: []*string{&contactPath1, &contactPath2},
				Display: []ClaimDisplay{
					{
						Locale: "en",
						Label:  "Phone Number",
					},
					{
						Locale: "fr",
						Label:  "Numéro de téléphone",
					},
				},
			},
			{
				// Simple attribute - should be included
				Path: []*string{&simpleAge},
				Display: []ClaimDisplay{
					{
						Locale: "en",
						Label:  "Age",
					},
				},
			},
		},
	}

	attrs := vctm.AttributesWithoutObjects()

	// Verify results
	assert.NotNil(t, attrs)
	assert.Contains(t, attrs, "en")
	assert.Contains(t, attrs, "fr")

	// Check that simple attributes are included
	assert.Contains(t, attrs["en"], "Name")
	assert.Contains(t, attrs["en"], "Email")
	assert.Contains(t, attrs["en"], "Age")
	assert.Equal(t, []string{"name"}, attrs["en"]["Name"])
	assert.Equal(t, []string{"email"}, attrs["en"]["Email"])
	assert.Equal(t, []string{"age"}, attrs["en"]["Age"])

	// Check that object attributes are excluded
	assert.NotContains(t, attrs["en"], "Street Address")
	assert.NotContains(t, attrs["en"], "Phone Number")

	// Check French language
	assert.Contains(t, attrs["fr"], "Nom")
	assert.Equal(t, []string{"name"}, attrs["fr"]["Nom"])
	assert.NotContains(t, attrs["fr"], "Numéro de téléphone")
}

func TestVCTM_AttributesWithoutObjects_EmptyClaims(t *testing.T) {
	vctm := &VCTM{
		Claims: []Claim{},
	}

	attrs := vctm.AttributesWithoutObjects()
	assert.NotNil(t, attrs)
	assert.Empty(t, attrs)
}

func TestVCTM_AttributesWithoutObjects_OnlyObjects(t *testing.T) {
	// Test case where all claims are objects
	path1 := "address"
	path2 := "street"
	path3 := "contact"
	path4 := "email"

	vctm := &VCTM{
		Claims: []Claim{
			{
				Path: []*string{&path1, &path2},
				Display: []ClaimDisplay{
					{
						Locale: "en",
						Label:  "Street Address",
					},
				},
			},
			{
				Path: []*string{&path3, &path4},
				Display: []ClaimDisplay{
					{
						Locale: "en",
						Label:  "Contact Email",
					},
				},
			},
		},
	}

	attrs := vctm.AttributesWithoutObjects()
	assert.NotNil(t, attrs)
	assert.Empty(t, attrs)
}

func TestVCTM_AttributesWithoutObjects_OnlySimple(t *testing.T) {
	// Test case where all claims are simple (non-object)
	name := "name"
	email := "email"
	age := "age"

	vctm := &VCTM{
		Claims: []Claim{
			{
				Path: []*string{&name},
				Display: []ClaimDisplay{
					{
						Locale: "en",
						Label:  "Name",
					},
				},
			},
			{
				Path: []*string{&email},
				Display: []ClaimDisplay{
					{
						Locale: "en",
						Label:  "Email",
					},
				},
			},
			{
				Path: []*string{&age},
				Display: []ClaimDisplay{
					{
						Locale: "en",
						Label:  "Age",
					},
				},
			},
		},
	}

	attrs := vctm.AttributesWithoutObjects()
	assert.NotNil(t, attrs)
	assert.Contains(t, attrs, "en")
	assert.Len(t, attrs["en"], 3)
	assert.Contains(t, attrs["en"], "Name")
	assert.Contains(t, attrs["en"], "Email")
	assert.Contains(t, attrs["en"], "Age")
}

func TestVCTM_AttributesWithoutObjects_CompareWithAttributes(t *testing.T) {
	// Verify that AttributesWithoutObjects is a subset of Attributes
	simpleName := "name"
	simpleEmail := "email"
	addressPath1 := "address"
	addressPath2 := "street"

	vctm := &VCTM{
		Claims: []Claim{
			{
				Path: []*string{&simpleName},
				Display: []ClaimDisplay{
					{
						Locale: "en",
						Label:  "Name",
					},
				},
			},
			{
				Path: []*string{&addressPath1, &addressPath2},
				Display: []ClaimDisplay{
					{
						Locale: "en",
						Label:  "Street Address",
					},
				},
			},
			{
				Path: []*string{&simpleEmail},
				Display: []ClaimDisplay{
					{
						Locale: "en",
						Label:  "Email",
					},
				},
			},
		},
	}

	allAttrs := vctm.Attributes()
	simpleAttrs := vctm.AttributesWithoutObjects()

	// All attributes should have 3 items (Name, Street Address, Email)
	assert.Len(t, allAttrs["en"], 3)

	// Simple attributes should have only 2 items (Name, Email)
	assert.Len(t, simpleAttrs["en"], 2)

	// Simple attrs should be a subset
	for lang, labels := range simpleAttrs {
		for label, paths := range labels {
			assert.Contains(t, allAttrs[lang], label)
			assert.Equal(t, allAttrs[lang][label], paths)
		}
	}
}

func TestVCTM_ClaimJSONPath(t *testing.T) {
	name := "name"
	given := "given"
	family := "family"

	vctm := &VCTM{
		Claims: []Claim{
			{
				Path:  []*string{&name},
				SVGID: "name-field",
			},
			{
				Path:  []*string{&name, &given},
				SVGID: "given-name",
			},
			{
				Path: []*string{&family},
			},
		},
	}

	jsonPath, err := vctm.ClaimJSONPath()
	assert.NoError(t, err)
	assert.NotNil(t, jsonPath)

	assert.Contains(t, jsonPath.Displayable, "name-field")
	assert.Equal(t, "$.name", jsonPath.Displayable["name-field"])
	assert.Contains(t, jsonPath.Displayable, "given-name")
	assert.Equal(t, "$.name.given", jsonPath.Displayable["given-name"])

	assert.Len(t, jsonPath.AllClaims, 3)
	assert.Contains(t, jsonPath.AllClaims, "$.name")
	assert.Contains(t, jsonPath.AllClaims, "$.name.given")
	assert.Contains(t, jsonPath.AllClaims, "$.family")
}

func TestVCTM_ClaimJSONPath_NilClaims(t *testing.T) {
	vctm := &VCTM{
		Claims: nil,
	}

	jsonPath, err := vctm.ClaimJSONPath()
	assert.Error(t, err)
	assert.Nil(t, jsonPath)
	assert.Contains(t, err.Error(), "claims are nil")
}

func TestClaim_JSONPath(t *testing.T) {
	t.Run("simple_path", func(t *testing.T) {
		name := "name"
		claim := &Claim{
			Path: []*string{&name},
		}

		path := claim.JSONPath()
		assert.Equal(t, "$.name", path)
	})

	t.Run("nested_path", func(t *testing.T) {
		address := "address"
		street := "street"
		claim := &Claim{
			Path: []*string{&address, &street},
		}

		path := claim.JSONPath()
		assert.Equal(t, "$.address.street", path)
	})

	t.Run("nil_claim", func(t *testing.T) {
		var claim *Claim = nil
		path := claim.JSONPath()
		assert.Equal(t, "", path)
	})

	t.Run("nil_path", func(t *testing.T) {
		claim := &Claim{
			Path: nil,
		}

		path := claim.JSONPath()
		assert.Equal(t, "", path)
	})

	t.Run("empty_path", func(t *testing.T) {
		claim := &Claim{
			Path: []*string{},
		}

		path := claim.JSONPath()
		assert.Equal(t, "$", path)
	})

	t.Run("deep_nesting", func(t *testing.T) {
		a := "a"
		b := "b"
		c := "c"
		d := "d"
		claim := &Claim{
			Path: []*string{&a, &b, &c, &d},
		}

		path := claim.JSONPath()
		assert.Equal(t, "$.a.b.c.d", path)
	})

	t.Run("wildcard_array_element", func(t *testing.T) {
		nationalities := "nationalities"
		claim := &Claim{
			Path: []*string{&nationalities, nil},
		}

		path := claim.JSONPath()
		assert.Equal(t, "$.nationalities[*]", path)
	})

	t.Run("wildcard_only", func(t *testing.T) {
		claim := &Claim{
			Path: []*string{nil},
		}

		path := claim.JSONPath()
		assert.Equal(t, "$[*]", path)
	})

	t.Run("wildcard_then_key", func(t *testing.T) {
		addresses := "addresses"
		street := "street"
		claim := &Claim{
			Path: []*string{&addresses, nil, &street},
		}

		path := claim.JSONPath()
		assert.Equal(t, "$.addresses[*].street", path)
	})

	t.Run("multiple_wildcards", func(t *testing.T) {
		matrix := "matrix"
		claim := &Claim{
			Path: []*string{&matrix, nil, nil},
		}

		path := claim.JSONPath()
		assert.Equal(t, "$.matrix[*][*]", path)
	})
}
