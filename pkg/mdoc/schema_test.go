package mdoc

import (
	"reflect"
	"testing"
)

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
		{
			"duplicate element ID across namespaces",
			`{
				"format": "mso_mdoc",
				"doctype": "x",
				"claims": {
					"ns1": {"given_name": {"mandatory": true, "value_type": "tstr"}},
					"ns2": {"given_name": {"mandatory": false, "value_type": "tstr"}}
				}
			}`,
		},
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

func TestMDDLSchema_SVGValues(t *testing.T) {
	schema := &MDDLSchema{
		Format:  "mso_mdoc",
		DocType: "org.iso.18013.5.1.mDL",
		Claims: map[string]NamespaceClaims{
			"org.iso.18013.5.1": {
				"family_name": {
					Display: []ClaimDisplay{{Locale: "en-US", Name: "Family Name"}},
					SVGID:   "family_name",
				},
				"given_name": {
					// No SVGID — must not appear in SVGValues, mirroring
					// sdjwtvc.VCTM.SVGValues skipping claims with no svg_id.
					Display: []ClaimDisplay{{Locale: "en-US", Name: "Given Name"}},
				},
				"portrait": {
					// SVGID set but no Display — must also be skipped, since
					// there is no label to attach to the resolved value.
					SVGID: "portrait_image",
				},
				"nationality": {
					Display: []ClaimDisplay{{Locale: "en-US", Name: "Nationality"}},
					SVGID:   "nationality",
				},
			},
		},
	}

	data := map[string]any{
		"family_name": "Andersson",
		"given_name":  "Helen",
		"portrait":    "base64data",
		// nationality deliberately absent from data.
	}

	got := schema.SVGValues(data)
	want := map[string]SVGValue{
		"family_name": {Label: "Family Name", Value: "Andersson"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SVGValues() = %+v, want %+v", got, want)
	}
}

func TestMDDLSchema_SVGValues_NoSVGIDsReturnsNil(t *testing.T) {
	schema := &MDDLSchema{
		Claims: map[string]NamespaceClaims{
			"org.iso.18013.5.1": {
				"family_name": {Display: []ClaimDisplay{{Locale: "en-US", Name: "Family Name"}}},
			},
		},
	}

	if got := schema.SVGValues(map[string]any{"family_name": "Andersson"}); got != nil {
		t.Errorf("SVGValues() = %+v, want nil when no claim declares svg_id", got)
	}
}
