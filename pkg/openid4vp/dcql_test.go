package openid4vp

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

var mockDCQLExample = []byte(`{
  "credentials": [
    {
      "id": "my_credential",
      "format": "dc+sd-jwt",
      "meta": {
        "vct_values": [ "https://credentials.example.com/identity_credential" ]
      },
      "claims": [
          {"path": ["last_name"]},
          {"path": ["first_name"]},
          {"path": ["address", "street_address"]}
      ]
    }
  ]
}`)

var mockDCQLExampleFromWWWallet = []byte(`{
  "credentials": [
    {
      "id": "CustomVerifiableId0",
      "format": "vc+sd-jwt",
      "meta": {
        "vct_values": [
          "urn:eudi:pid:1"
        ]
      },
      "claims": [
        {"path": ["given_name"]},
        {"path": ["birth_given_name"]},
        {"path": ["family_name"]},
        {"path": ["birth_family_name"]},
        {"path": ["birthdate"]},
        {"path": ["place_of_birth", "country"]},
        {"path": ["place_of_birth", "region"]},
        {"path": ["place_of_birth", "locality"]},
        {"path": ["nationalities"]},
        {"path": ["personal_administrative_number"]},
        {"path": ["sex"]},
        {"path": ["address", "formatted"]},
        {"path": ["address", "street_address"]},
        {"path": ["address", "house_number"]},
        {"path": ["address", "postal_code"]},
        {"path": ["address", "locality"]},
        {"path": ["address", "region"]},
        {"path": ["address", "country"]},
        {"path": ["age_equal_or_over", "14"]},
        {"path": ["age_equal_or_over", "16"]},
        {"path": ["age_equal_or_over", "18"]},
        {"path": ["age_equal_or_over", "21"]},
        {"path": ["age_equal_or_over", "65"]},
        {"path": ["age_in_years"]},
        {"path": ["age_birth_year"]},
        {"path": ["email"]},
        {"path": ["phone_number"]},
        {"path": ["issuing_authority"]},
        {"path": ["issuing_country"]},
        {"path": ["issuing_jurisdiction"]},
        {"path": ["date_of_expiry"]},
        {"path": ["date_of_issuance"]},
        {"path": ["document_number"]},
        {"path": ["picture"]}
      ]
    }
  ],
  "credential_sets": [
    {
      "options": [
        ["CustomVerifiableId0"]
      ]
    }
  ]
}`)

func TestExample(t *testing.T) {
	tts := []struct {
		name string
		have *DCQL
		want []byte
	}{
		{
			name: "example from spec",
			have: &DCQL{
				Credentials: []CredentialQuery{
					{
						ID:     "my_credential",
						Format: "dc+sd-jwt",
						Meta: MetaQuery{
							VCTValues: []string{"https://credentials.example.com/identity_credential"},
						},
						Claims: []ClaimQuery{
							{Path: StringPath("last_name")},
							{Path: StringPath("first_name")},
							{Path: StringPath("address", "street_address")},
						},
					},
				},
			},
			want: mockDCQLExample,
		},
		{
			name: "example from wwwallet",
			have: &DCQL{
				CredentialSets: []CredentialSetQuery{
					{
						Options: [][]string{{"CustomVerifiableId0"}},
					},
				},
				Credentials: []CredentialQuery{
					{
						ID:     "CustomVerifiableId0",
						Format: "vc+sd-jwt",
						Meta: MetaQuery{
							VCTValues: []string{"urn:eudi:pid:1"},
						},
						Claims: []ClaimQuery{
							{Path: StringPath("given_name")},
							{Path: StringPath("birth_given_name")},
							{Path: StringPath("family_name")},
							{Path: StringPath("birth_family_name")},
							{Path: StringPath("birthdate")},
							{Path: StringPath("place_of_birth", "country")},
							{Path: StringPath("place_of_birth", "region")},
							{Path: StringPath("place_of_birth", "locality")},
							{Path: StringPath("nationalities")},
							{Path: StringPath("personal_administrative_number")},
							{Path: StringPath("sex")},
							{Path: StringPath("address", "formatted")},
							{Path: StringPath("address", "street_address")},
							{Path: StringPath("address", "house_number")},
							{Path: StringPath("address", "postal_code")},
							{Path: StringPath("address", "locality")},
							{Path: StringPath("address", "region")},
							{Path: StringPath("address", "country")},
							{Path: StringPath("age_equal_or_over", "14")},
							{Path: StringPath("age_equal_or_over", "16")},
							{Path: StringPath("age_equal_or_over", "18")},
							{Path: StringPath("age_equal_or_over", "21")},
							{Path: StringPath("age_equal_or_over", "65")},
							{Path: StringPath("age_in_years")},
							{Path: StringPath("age_birth_year")},
							{Path: StringPath("email")},
							{Path: StringPath("phone_number")},
							{Path: StringPath("issuing_authority")},
							{Path: StringPath("issuing_country")},
							{Path: StringPath("issuing_jurisdiction")},
							{Path: StringPath("date_of_expiry")},
							{Path: StringPath("date_of_issuance")},
							{Path: StringPath("document_number")},
							{Path: StringPath("picture")},
						},
					},
				},
			},
			want: mockDCQLExampleFromWWWallet,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.MarshalIndent(tt.have, "", "  ")
			assert.NoError(t, err)
			assert.JSONEq(t, string(tt.want), string(got))
		})
	}
}

// TestClaimSetsRoundTrip verifies that claim_sets ([][]string) and claim IDs
// survive JSON marshal/unmarshal round-trips per OID4VP §6.4.1.
func TestClaimSetsRoundTrip(t *testing.T) {
	dcql := &DCQL{
		Credentials: []CredentialQuery{
			{
				ID:     "pid",
				Format: "dc+sd-jwt",
				Meta: MetaQuery{
					VCTValues: []string{"urn:eudi:pid:1"},
				},
				Claims: []ClaimQuery{
					{ID: "name", Path: StringPath("given_name")},
					{ID: "family", Path: StringPath("family_name")},
					{ID: "age", Path: StringPath("age_over_18")},
				},
				ClaimSet: [][]string{
					{"name", "family"},
					{"name", "age"},
				},
			},
		},
	}

	// Marshal to JSON
	data, err := json.Marshal(dcql)
	assert.NoError(t, err)

	// Unmarshal back
	var decoded DCQL
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)

	cred := decoded.Credentials[0]
	// Verify claim IDs survived
	assert.Equal(t, "name", cred.Claims[0].ID)
	assert.Equal(t, "family", cred.Claims[1].ID)
	assert.Equal(t, "age", cred.Claims[2].ID)

	// Verify claim_sets survived as [][]string
	assert.Equal(t, [][]string{{"name", "family"}, {"name", "age"}}, cred.ClaimSet)

	// Verify the JSON contains expected structure
	assert.Contains(t, string(data), `"claim_sets"`)
	assert.Contains(t, string(data), `"id":"name"`)
}

// TestClaimQueryValues_RoundTrip verifies OpenID4VP §6.3 "values": strings,
// integers, and booleans round-trip through JSON and reach the wire under the
// "values" key. Uses the exact query from Appendix D of the spec plus a mixed-
// type case.
func TestClaimQueryValues_RoundTrip(t *testing.T) {
	tts := []struct {
		name       string
		query      ClaimQuery
		wantOnWire string
	}{
		{
			name: "strings (spec Appendix D example)",
			query: ClaimQuery{
				Path:   StringPath("postal_code"),
				Values: []any{"90210", "90211"},
			},
			wantOnWire: `{"path":["postal_code"],"values":["90210","90211"]}`,
		},
		{
			name: "integers",
			query: ClaimQuery{
				Path:   StringPath("age_in_years"),
				Values: []any{18, 21},
			},
			wantOnWire: `{"path":["age_in_years"],"values":[18,21]}`,
		},
		{
			name: "booleans",
			query: ClaimQuery{
				Path:   StringPath("is_adult"),
				Values: []any{true, false},
			},
			wantOnWire: `{"path":["is_adult"],"values":[true,false]}`,
		},
		{
			name: "mixed string int bool",
			query: ClaimQuery{
				ID:     "mix",
				Path:   StringPath("mixed"),
				Values: []any{"x", 1, true},
			},
			wantOnWire: `{"id":"mix","path":["mixed"],"values":["x",1,true]}`,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.query)
			assert.NoError(t, err)
			assert.JSONEq(t, tt.wantOnWire, string(data))

			var decoded ClaimQuery
			assert.NoError(t, json.Unmarshal(data, &decoded))
			assert.Equal(t, tt.query.ID, decoded.ID)
			assert.Equal(t, tt.query.Path, decoded.Path)
			assert.Len(t, decoded.Values, len(tt.query.Values))

			reMarshaled, err := json.Marshal(decoded)
			assert.NoError(t, err)
			assert.JSONEq(t, tt.wantOnWire, string(reMarshaled))
		})
	}
}

// TestClaimQueryValues_OmittedWhenAbsent guards the omitempty semantics on the
// wire tag: a ClaimQuery with no Values MUST NOT emit a "values" key.
func TestClaimQueryValues_OmittedWhenAbsent(t *testing.T) {
	data, err := json.Marshal(ClaimQuery{Path: StringPath("family_name")})
	assert.NoError(t, err)
	assert.NotContains(t, string(data), `"values"`)
}

// TestClaimQueryValues_MarshalRejectsInvalid enforces that MarshalJSON refuses
// to emit output when Values is non-nil but violates OpenID4VP §6.3 (empty
// slice, unsupported element types). A nil Values slice must still be silently
// omitted via omitempty.
func TestClaimQueryValues_MarshalRejectsInvalid(t *testing.T) {
	tts := []struct {
		name  string
		query ClaimQuery
	}{
		{"empty slice", ClaimQuery{Path: StringPath("x"), Values: []any{}}},
		{"nil element", ClaimQuery{Path: StringPath("x"), Values: []any{nil}}},
		{"nested map", ClaimQuery{Path: StringPath("x"), Values: []any{map[string]any{"k": "v"}}}},
		{"nested slice", ClaimQuery{Path: StringPath("x"), Values: []any{[]any{1, 2}}}},
		{"non-integer float", ClaimQuery{Path: StringPath("x"), Values: []any{1.5}}},
	}
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			_, err := json.Marshal(tt.query)
			assert.Error(t, err)
		})
	}
}

// TestClaimQueryPath_MarshalRejectsInvalid enforces that MarshalJSON refuses
// to emit output when Path violates OpenID4VP §6.3 (missing or empty-string
// element). Path is REQUIRED, so an in-memory struct with a bad path must
// fail fast rather than produce non-spec-compliant output.
func TestClaimQueryPath_MarshalRejectsInvalid(t *testing.T) {
	empty := ""
	tts := []struct {
		name  string
		query ClaimQuery
	}{
		{"nil path", ClaimQuery{}},
		{"empty path", ClaimQuery{Path: []*string{}}},
		{"empty-string element", ClaimQuery{Path: []*string{&empty}}},
	}
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			_, err := json.Marshal(tt.query)
			assert.Error(t, err)
		})
	}
}

// TestClaimQueryValues_RejectsInvalid enforces validateClaimValues at the
// UnmarshalJSON boundary. Nested objects/arrays, non-integer floats, and null
// elements are not permitted by OpenID4VP §6.3.
func TestClaimQueryValues_RejectsInvalid(t *testing.T) {
	tts := []struct {
		name string
		body string
	}{
		{"empty array", `{"path":["x"],"values":[]}`},
		{"null element", `{"path":["x"],"values":[null]}`},
		{"nested object", `{"path":["x"],"values":[{"k":"v"}]}`},
		{"nested array", `{"path":["x"],"values":[[1,2]]}`},
		{"non-integer float", `{"path":["x"],"values":[1.5]}`},
		{"explicit null", `{"path":["x"],"values":null}`},
		{"scalar string", `{"path":["x"],"values":"nope"}`},
		{"scalar number", `{"path":["x"],"values":42}`},
		{"scalar bool", `{"path":["x"],"values":true}`},
		{"object", `{"path":["x"],"values":{"a":1}}`},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			var cq ClaimQuery
			assert.Error(t, json.Unmarshal([]byte(tt.body), &cq))
		})
	}
}

// TestClaimQueryValues_AbsentIsAccepted confirms that a claim without a
// "values" key unmarshals cleanly (values is OPTIONAL per §6.3) and marshals
// back without leaking a "values" key.
func TestClaimQueryValues_AbsentIsAccepted(t *testing.T) {
	var cq ClaimQuery
	assert.NoError(t, json.Unmarshal([]byte(`{"path":["family_name"]}`), &cq))
	assert.Nil(t, cq.Values)

	out, err := json.Marshal(cq)
	assert.NoError(t, err)
	assert.NotContains(t, string(out), `"values"`)
}

// TestClaimQueryValues_YAMLRejectsNullAndScalars mirrors the JSON boundary tests
// through the two-pass UnmarshalYAML.
func TestClaimQueryValues_YAMLRejectsNullAndScalars(t *testing.T) {
	tts := []struct {
		name string
		body string
	}{
		{"explicit null", "path:\n  - x\nvalues: null\n"},
		{"empty inline", "path:\n  - x\nvalues: []\n"},
		{"scalar string", "path:\n  - x\nvalues: nope\n"},
		{"scalar number", "path:\n  - x\nvalues: 42\n"},
		{"scalar bool", "path:\n  - x\nvalues: true\n"},
	}
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			var cq ClaimQuery
			assert.Error(t, yaml.Unmarshal([]byte(tt.body), &cq))
		})
	}
}

// TestClaimQueryValues_YAMLRoundTrip mirrors the JSON test path through the
// custom UnmarshalYAML.
func TestClaimQueryValues_YAMLRoundTrip(t *testing.T) {
	src := []byte("path:\n  - postal_code\nvalues:\n  - \"90210\"\n  - \"90211\"\n")
	var cq ClaimQuery
	assert.NoError(t, yaml.Unmarshal(src, &cq))
	assert.Equal(t, StringPath("postal_code"), cq.Path)
	assert.Equal(t, []any{"90210", "90211"}, cq.Values)
}

// TestClaimQuery_MarshalYAML_RoundTrip guards that MarshalYAML emits id/path/
// values instead of an empty mapping. The yaml:"-" tags on the struct fields
// would otherwise drop everything.
func TestClaimQuery_MarshalYAML_RoundTrip(t *testing.T) {
	orig := ClaimQuery{
		ID:     "postal",
		Path:   ArrayElementPath("addresses"),
		Values: []any{"90210", "90211"},
	}
	out, err := yaml.Marshal(orig)
	assert.NoError(t, err)
	assert.Contains(t, string(out), "id: postal")
	assert.Contains(t, string(out), "path:")
	assert.Contains(t, string(out), "values:")

	var decoded ClaimQuery
	assert.NoError(t, yaml.Unmarshal(out, &decoded))
	assert.Equal(t, orig.ID, decoded.ID)
	assert.Equal(t, orig.Path, decoded.Path)
	assert.Equal(t, orig.Values, decoded.Values)
}

// TestDCQL_MarshalYAML_RoundTrip guards that a full DCQL query round-trips
// through YAML with claim id/path/values preserved.
func TestDCQL_MarshalYAML_RoundTrip(t *testing.T) {
	orig := DCQL{
		Credentials: []CredentialQuery{{
			ID:     "pid",
			Format: FormatSDJWTVC,
			Meta:   MetaQuery{VCTValues: []string{"urn:eu:pid"}},
			Claims: []ClaimQuery{
				{ID: "fn", Path: StringPath("family_name")},
				{ID: "pc", Path: StringPath("address", "postal_code"), Values: []any{"90210"}},
			},
		}},
	}
	out, err := yaml.Marshal(orig)
	assert.NoError(t, err)

	var decoded DCQL
	assert.NoError(t, yaml.Unmarshal(out, &decoded))
	assert.Equal(t, orig, decoded)
}

// TestValidateClaimValues_FloatBounds guards the pre-conversion range check
// added to validateClaimValues so out-of-range or non-finite floats can never
// reach the int64 conversion, and integer-valued floats beyond the IEEE-754
// safe integer range (±(2^53-1)) are rejected because JSON decoding may have
// silently rounded them.
func TestValidateClaimValues_FloatBounds(t *testing.T) {
	// A float64 just above math.MaxInt64 that is still finite and integer-valued.
	overflowFloat64 := math.Nextafter(float64(math.MaxInt64), math.MaxFloat64)
	underflowFloat64 := math.Nextafter(float64(math.MinInt64), -math.MaxFloat64)
	// Just outside the JSON-safe integer range.
	aboveSafeInt := float64(1 << 53) // 2^53 is representable but 2^53+1 is not; anything > 2^53-1 is unsafe.
	belowSafeInt := -float64(1 << 53)

	tts := []struct {
		name    string
		values  []any
		wantErr bool
	}{
		{"NaN float64", []any{math.NaN()}, true},
		{"+Inf float64", []any{math.Inf(1)}, true},
		{"-Inf float64", []any{math.Inf(-1)}, true},
		{"overflow float64", []any{overflowFloat64}, true},
		{"underflow float64", []any{underflowFloat64}, true},
		{"above safe int float64", []any{aboveSafeInt}, true},
		{"below safe int float64", []any{belowSafeInt}, true},
		{"non-integer float64", []any{1.5}, true},
		{"NaN float32", []any{float32(math.NaN())}, true},
		{"+Inf float32", []any{float32(math.Inf(1))}, true},
		{"overflow float32", []any{float32(math.MaxFloat32)}, true},
		{"non-integer float32", []any{float32(1.5)}, true},
		{"integer float64", []any{float64(42)}, false},
		{"max safe int float64", []any{float64(1<<53 - 1)}, false},
		{"min safe int float64", []any{-float64(1<<53 - 1)}, false},
		{"integer float32", []any{float32(42)}, false},
		{"zero float64", []any{0.0}, false},
	}
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			err := validateClaimValues(tt.values, true)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestCredentialSetRequiredTriState verifies that CredentialSetQuery.Required
// distinguishes "omitted" (spec default true), "explicit false", and
// "explicit true" across a JSON round-trip, per OpenID4VP 1.0 §6.2.
func TestCredentialSetRequiredTriState(t *testing.T) {
	tts := []struct {
		name            string
		raw             string
		wantRequiredPtr *bool
		wantIsRequired  bool
		wantRoundTrip   string
	}{
		{
			name:            "omitted required means spec default true",
			raw:             `{"options":[["a"]]}`,
			wantRequiredPtr: nil,
			wantIsRequired:  true,
			wantRoundTrip:   `{"options":[["a"]]}`,
		},
		{
			name:            "explicit false is preserved",
			raw:             `{"options":[["a"]],"required":false}`,
			wantRequiredPtr: new(false),
			wantIsRequired:  false,
			wantRoundTrip:   `{"options":[["a"]],"required":false}`,
		},
		{
			name:            "explicit true is preserved",
			raw:             `{"options":[["a"]],"required":true}`,
			wantRequiredPtr: new(true),
			wantIsRequired:  true,
			wantRoundTrip:   `{"options":[["a"]],"required":true}`,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			var got CredentialSetQuery
			require.NoError(t, json.Unmarshal([]byte(tt.raw), &got))

			if tt.wantRequiredPtr == nil {
				require.Nil(t, got.Required)
			} else {
				require.NotNil(t, got.Required)
				require.Equal(t, *tt.wantRequiredPtr, *got.Required)
			}
			require.Equal(t, tt.wantIsRequired, got.IsRequired())

			out, err := json.Marshal(got)
			require.NoError(t, err)
			require.JSONEq(t, tt.wantRoundTrip, string(out))
		})
	}
}

// TestCredentialQueryRequireCryptographicHolderBindingTriState verifies that
// CredentialQuery.RequireCryptographicHolderBinding distinguishes "omitted"
// (spec default true), "explicit false", and "explicit true" across a JSON
// round-trip, per OpenID4VP 1.0 §6.1.
func TestCredentialQueryRequireCryptographicHolderBindingTriState(t *testing.T) {
	base := `"id":"c","format":"dc+sd-jwt","meta":{"vct_values":["urn:x"]}`

	tts := []struct {
		name            string
		raw             string
		wantRequiredPtr *bool
		wantEffective   bool
		wantRoundTrip   string
	}{
		{
			name:            "omitted means spec default true",
			raw:             `{` + base + `}`,
			wantRequiredPtr: nil,
			wantEffective:   true,
			wantRoundTrip:   `{` + base + `}`,
		},
		{
			name:            "explicit false is preserved",
			raw:             `{` + base + `,"require_cryptographic_holder_binding":false}`,
			wantRequiredPtr: new(false),
			wantEffective:   false,
			wantRoundTrip:   `{` + base + `,"require_cryptographic_holder_binding":false}`,
		},
		{
			name:            "explicit true is preserved",
			raw:             `{` + base + `,"require_cryptographic_holder_binding":true}`,
			wantRequiredPtr: new(true),
			wantEffective:   true,
			wantRoundTrip:   `{` + base + `,"require_cryptographic_holder_binding":true}`,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			var got CredentialQuery
			require.NoError(t, json.Unmarshal([]byte(tt.raw), &got))

			if tt.wantRequiredPtr == nil {
				require.Nil(t, got.RequireCryptographicHolderBinding)
			} else {
				require.NotNil(t, got.RequireCryptographicHolderBinding)
				require.Equal(t, *tt.wantRequiredPtr, *got.RequireCryptographicHolderBinding)
			}
			require.Equal(t, tt.wantEffective, got.RequiresCryptographicHolderBinding())

			out, err := json.Marshal(got)
			require.NoError(t, err)
			require.JSONEq(t, tt.wantRoundTrip, string(out))
		})
	}
}
