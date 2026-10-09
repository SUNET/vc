package mdoc

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/SUNET/vc/pkg/mdoc/zkcircuit"
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
		{
			// Below zkcircuit.MinSaltBytes. 16 used to be rejected here
			// too, back when "0 or 32" was hardcoded; it is accepted now,
			// because which length a credential needs is the circuit's to
			// say and 16 is this package's own default for a non-ZK item.
			"zk_salt_bytes below the accepted range",
			`{
				"format": "mso_mdoc",
				"doctype": "x",
				"claims": {"ns": {"a": {}}},
				"zk_salt_bytes": 4
			}`,
		},
		{
			"zk_salt_bytes above the accepted range",
			`{
				"format": "mso_mdoc",
				"doctype": "x",
				"claims": {"ns": {"a": {}}},
				"zk_salt_bytes": 65
			}`,
		},
		{
			// An empty system name resolves to no circuit and would
			// otherwise be dropped silently, leaving a schema that looks
			// like it declares a ZK system but is issued with default
			// sizing.
			"blank zk_systems entry",
			`{
				"format": "mso_mdoc",
				"doctype": "x",
				"claims": {"ns": {"a": {}}},
				"zk_systems": ["vega-mc", "  "]
			}`,
		},
		{
			// A schema is file-, URL-, or registry-backed - an unbounded
			// zk_salt_bytes reaches make([]byte, saltSize) unchecked and
			// could otherwise exhaust memory during issuance.
			"huge zk_salt_bytes",
			`{
				"format": "mso_mdoc",
				"doctype": "x",
				"claims": {"ns": {"a": {}}},
				"zk_salt_bytes": 1000000000
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

// The accepted range is zkcircuit's, so a pinned value and a
// catalog-published one are held to the same bound. 8 and 64 are the
// edges; 32 is what zk-cred-vega's r12 circuit publishes today.
func TestLoadMDDLSchema_ZkSaltBytesAcceptsZeroAndTheCatalogRange(t *testing.T) {
	for _, saltBytes := range []int{0, zkcircuit.MinSaltBytes, 32, zkcircuit.MaxSaltBytes} {
		t.Run(fmt.Sprintf("saltBytes=%d", saltBytes), func(t *testing.T) {
			raw := []byte(fmt.Sprintf(`{
				"format": "mso_mdoc",
				"doctype": "x",
				"claims": {"ns": {"a": {}}},
				"zk_salt_bytes": %d
			}`, saltBytes))
			schema, err := LoadMDDLSchema(raw)
			if err != nil {
				t.Fatalf("LoadMDDLSchema() error = %v", err)
			}
			if schema.ZkSaltBytes != saltBytes {
				t.Errorf("ZkSaltBytes = %d, want %d", schema.ZkSaltBytes, saltBytes)
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
				"document_number": {
					// Label set distinct from Name - must win over Name,
					// mirroring sdjwtvc.VCTM.SVGValues using Display[0].Label.
					Display: []ClaimDisplay{{Locale: "en-US", Name: "Document Number", Label: "Doc No."}},
					SVGID:   "document_number",
				},
			},
		},
	}

	data := map[string]any{
		"family_name":     "Andersson",
		"given_name":      "Helen",
		"portrait":        "base64data",
		"document_number": "123456789",
		// nationality deliberately absent from data.
	}

	got := schema.SVGValues(data)
	want := map[string]SVGValue{
		"family_name":     {Label: "Family Name", Value: "Andersson"},
		"document_number": {Label: "Doc No.", Value: "123456789"},
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

func TestLoadMDDLSchema_KeepsZkSystems(t *testing.T) {
	schema, err := LoadMDDLSchema([]byte(`{
		"format": "mso_mdoc",
		"doctype": "org.iso.18013.5.1.mDL",
		"claims": {"ns": {"a": {}}},
		"zk_systems": ["vega-mc"]
	}`))
	if err != nil {
		t.Fatalf("LoadMDDLSchema() error = %v", err)
	}
	if len(schema.ZkSystems) != 1 || schema.ZkSystems[0] != "vega-mc" {
		t.Errorf("ZkSystems = %v, want [vega-mc]", schema.ZkSystems)
	}
}
