package mdoc

import "testing"

func TestLoadMDDLSchema(t *testing.T) {
	valid := []byte(`{
		"format": "mso_mdoc",
		"doctype": "org.iso.18013.5.1.mDL",
		"claims": {"org.iso.18013.5.1": {"family_name": {"mandatory": true, "value_type": "tstr"}}}
	}`)

	schema, err := LoadMDDLSchema(valid)
	if err != nil {
		t.Fatalf("LoadMDDLSchema() error = %v", err)
	}
	if schema.DocType != "org.iso.18013.5.1.mDL" {
		t.Errorf("DocType = %q, want org.iso.18013.5.1.mDL", schema.DocType)
	}

	tests := []struct {
		name string
		raw  string
	}{
		{"invalid JSON", `not json`},
		{"wrong format", `{"format": "dc+sd-jwt", "doctype": "x", "claims": {"ns": {"a": {}}}}`},
		{"missing doctype", `{"format": "mso_mdoc", "claims": {"ns": {"a": {}}}}`},
		{"no claims", `{"format": "mso_mdoc", "doctype": "x"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := LoadMDDLSchema([]byte(tt.raw)); err == nil {
				t.Error("expected an error, got none")
			}
		})
	}
}

func TestMDDLSchema_Attributes(t *testing.T) {
	schema := &MDDLSchema{
		Format:  "mso_mdoc",
		DocType: "org.iso.18013.5.1.mDL",
		Claims: map[string]NamespaceClaims{
			"org.iso.18013.5.1": {
				"family_name": {
					Mandatory: true,
					ValueType: "tstr",
					Display: []ClaimDisplay{
						{Locale: "en-US", Name: "Family Name"},
						{Locale: "sv", Name: "Efternamn"},
					},
				},
				"portrait": {ValueType: "bstr"}, // no display info
			},
		},
	}

	attrs := schema.Attributes()

	enUS, ok := attrs["en-US"]
	if !ok {
		t.Fatal("missing en-US locale")
	}
	path, ok := enUS["Family Name"]
	if !ok {
		t.Fatal("missing 'Family Name' label under en-US")
	}
	if len(path) != 2 || *path[0] != "org.iso.18013.5.1" || *path[1] != "family_name" {
		t.Errorf("path = %v, want [org.iso.18013.5.1 family_name]", path)
	}

	sv, ok := attrs["sv"]
	if !ok {
		t.Fatal("missing sv locale")
	}
	if _, ok := sv["Efternamn"]; !ok {
		t.Error("missing 'Efternamn' label under sv")
	}

	// Claims without any Display must still surface, bucketed under the
	// default locale using their raw element ID as the label — otherwise a
	// schema authored without display info would produce empty Attributes.
	defaultBucket, ok := attrs[defaultLocale]
	if !ok {
		t.Fatalf("missing default locale %q for claim with no display info", defaultLocale)
	}
	if _, ok := defaultBucket["portrait"]; !ok {
		t.Error("missing fallback 'portrait' label under default locale")
	}
}
