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
