package credential

import (
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTransformClaims(t *testing.T) {
	tests := []struct {
		name       string
		mapping    model.AttributeMapping
		attributes map[string]any
		want       map[string]any
		wantErr    string
	}{
		{
			name: "simple flat mapping",
			mapping: model.AttributeMapping{
				"given_name":  {Claim: "given_name", Required: true},
				"family_name": {Claim: "family_name", Required: true},
			},
			attributes: map[string]any{
				"given_name":  "Alice",
				"family_name": "Smith",
			},
			want: map[string]any{
				"given_name":  "Alice",
				"family_name": "Smith",
			},
		},
		{
			name: "nested claim paths",
			mapping: model.AttributeMapping{
				"oid_given_name":  {Claim: "identity.given_name", Required: true},
				"oid_family_name": {Claim: "identity.family_name", Required: true},
			},
			attributes: map[string]any{
				"oid_given_name":  "Bob",
				"oid_family_name": "Jones",
			},
			want: map[string]any{
				"identity": map[string]any{
					"given_name":  "Bob",
					"family_name": "Jones",
				},
			},
		},
		{
			name: "missing required attribute",
			mapping: model.AttributeMapping{
				"given_name": {Claim: "given_name", Required: true},
			},
			attributes: map[string]any{},
			wantErr:    "missing required attribute",
		},
		{
			name: "optional attribute missing uses default",
			mapping: model.AttributeMapping{
				"country": {Claim: "country", Required: false, Default: "SE"},
			},
			attributes: map[string]any{},
			want: map[string]any{
				"country": "SE",
			},
		},
		{
			name: "optional attribute missing no default is skipped",
			mapping: model.AttributeMapping{
				"nickname": {Claim: "nickname", Required: false},
			},
			attributes: map[string]any{},
			want:       map[string]any{},
		},
		{
			name: "transform lowercase",
			mapping: model.AttributeMapping{
				"email": {Claim: "email", Required: true, Transform: "lowercase"},
			},
			attributes: map[string]any{
				"email": "Alice@Example.COM",
			},
			want: map[string]any{
				"email": "alice@example.com",
			},
		},
		{
			name: "transform uppercase",
			mapping: model.AttributeMapping{
				"country": {Claim: "country", Required: true, Transform: "uppercase"},
			},
			attributes: map[string]any{
				"country": "se",
			},
			want: map[string]any{
				"country": "SE",
			},
		},
		{
			name: "transform trim",
			mapping: model.AttributeMapping{
				"name": {Claim: "name", Required: true, Transform: "trim"},
			},
			attributes: map[string]any{
				"name": "  Alice  ",
			},
			want: map[string]any{
				"name": "Alice",
			},
		},
		{
			name: "extra attributes are ignored",
			mapping: model.AttributeMapping{
				"name": {Claim: "name", Required: true},
			},
			attributes: map[string]any{
				"name":  "Alice",
				"extra": "ignored",
			},
			want: map[string]any{
				"name": "Alice",
			},
		},
		{
			name:       "empty mapping produces empty doc",
			mapping:    model.AttributeMapping{},
			attributes: map[string]any{"anything": "value"},
			want:       map[string]any{},
		},
		{
			name: "transform country_alpha2 from name",
			mapping: model.AttributeMapping{
				"country": {Claim: "nationalities", Required: true, Transform: "country_alpha2"},
			},
			attributes: map[string]any{
				"country": "Sweden",
			},
			want: map[string]any{
				"nationalities": "SE",
			},
		},
		{
			name: "transform country_alpha2 from alpha3",
			mapping: model.AttributeMapping{
				"country": {Claim: "nationalities", Required: true, Transform: "country_alpha2"},
			},
			attributes: map[string]any{
				"country": "SWE",
			},
			want: map[string]any{
				"nationalities": "SE",
			},
		},
		{
			name: "transform country_alpha3 from name",
			mapping: model.AttributeMapping{
				"country": {Claim: "nationalities", Required: true, Transform: "country_alpha3"},
			},
			attributes: map[string]any{
				"country": "Sweden",
			},
			want: map[string]any{
				"nationalities": "SWE",
			},
		},
		{
			name: "transform country_alpha2 from lowercase name",
			mapping: model.AttributeMapping{
				"country": {Claim: "nationalities", Required: true, Transform: "country_alpha2"},
			},
			attributes: map[string]any{
				"country": "sweden",
			},
			want: map[string]any{
				"nationalities": "SE",
			},
		},
		{
			name: "transform country_alpha2 from lowercase alpha3",
			mapping: model.AttributeMapping{
				"country": {Claim: "nationalities", Required: true, Transform: "country_alpha2"},
			},
			attributes: map[string]any{
				"country": "swe",
			},
			want: map[string]any{
				"nationalities": "SE",
			},
		},
		{
			name: "transform country_alpha3 from lowercase name",
			mapping: model.AttributeMapping{
				"country": {Claim: "nationalities", Required: true, Transform: "country_alpha3"},
			},
			attributes: map[string]any{
				"country": "sweden",
			},
			want: map[string]any{
				"nationalities": "SWE",
			},
		},
		{
			name: "transform country_alpha3 from lowercase alpha3",
			mapping: model.AttributeMapping{
				"country": {Claim: "nationalities", Required: true, Transform: "country_alpha3"},
			},
			attributes: map[string]any{
				"country": "swe",
			},
			want: map[string]any{
				"nationalities": "SWE",
			},
		},
		{
			name: "as_array wraps scalar after transform",
			mapping: model.AttributeMapping{
				"country": {Claim: "nationalities", Required: true, Transform: "country_alpha2", AsArray: true},
			},
			attributes: map[string]any{
				"country": "Sweden",
			},
			want: map[string]any{
				"nationalities": []any{"SE"},
			},
		},
		{
			name: "as_array no-op on existing []any slice",
			mapping: model.AttributeMapping{
				"nats": {Claim: "nationalities", AsArray: true},
			},
			attributes: map[string]any{
				"nats": []any{"SE", "NO"},
			},
			want: map[string]any{
				"nationalities": []any{"SE", "NO"},
			},
		},
		{
			name: "as_array no-op on existing []string slice",
			mapping: model.AttributeMapping{
				"nats": {Claim: "nationalities", AsArray: true},
			},
			attributes: map[string]any{
				"nats": []string{"SE", "NO"},
			},
			want: map[string]any{
				"nationalities": []string{"SE", "NO"},
			},
		},
		{
			name: "as_array wraps plain scalar without transform",
			mapping: model.AttributeMapping{
				"country": {Claim: "nationalities", AsArray: true},
			},
			attributes: map[string]any{
				"country": "SE",
			},
			want: map[string]any{
				"nationalities": []any{"SE"},
			},
		},
		{
			name: "transform country_alpha2 unknown returns original",
			mapping: model.AttributeMapping{
				"country": {Claim: "nationalities", Required: true, Transform: "country_alpha2"},
			},
			attributes: map[string]any{
				"country": "NotACountry",
			},
			want: map[string]any{
				"nationalities": "NotACountry",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transformer := NewClaimTransformer(tt.mapping)
			got, err := transformer.TransformClaims(tt.attributes)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func FuzzApplyTransform(f *testing.F) {
	f.Add("hello world", "lowercase")
	f.Add("HELLO WORLD", "uppercase")
	f.Add("  spaced  ", "trim")
	f.Add("unchanged", "")
	f.Add("test", "unknown")
	f.Add("Sweden", "country_alpha2")
	f.Add("Sweden", "country_alpha3")
	f.Add("sweden", "country_alpha2")
	f.Add("sweden", "country_alpha3")
	f.Add("SWE", "country_alpha2")
	f.Add("SWE", "country_alpha3")
	f.Add("swe", "country_alpha2")
	f.Add("swe", "country_alpha3")
	f.Add("SE", "country_alpha2")
	f.Add("SE", "country_alpha3")
	f.Add("se", "country_alpha2")
	f.Add("se", "country_alpha3")
	f.Add("sWe", "country_alpha2")
	f.Add("sWe", "country_alpha3")
	f.Add("sWE", "country_alpha2")
	f.Add("sWE", "country_alpha3")
	f.Add("SwEdEn", "country_alpha2")
	f.Add("SwEdEn", "country_alpha3")
	f.Add("NotACountry", "country_alpha2")
	f.Add("NotACountry", "country_alpha3")
	f.Add("", "country_alpha2")
	f.Add("", "country_alpha3")

	f.Fuzz(func(t *testing.T, input string, transform string) {
		result := ApplyTransform(input, transform)
		// Result must always be a string when input is a string
		_, ok := result.(string)
		assert.True(t, ok, "expected string result for string input")
	})
}

func FuzzSetNestedValue(f *testing.F) {
	f.Add("simple", "value")
	f.Add("a.b.c", "deep")
	f.Add("x.y", "nested")

	f.Fuzz(func(t *testing.T, path string, value string) {
		if path == "" {
			return
		}
		doc := make(map[string]any)
		err := SetNestedValue(doc, path, value)
		if err != nil {
			return
		}
		got, ok := GetNestedValue(doc, path)
		assert.True(t, ok, "value should be retrievable after set")
		assert.Equal(t, value, got)
	})
}
