package credential

import (
	"testing"

	"github.com/SUNET/vc/pkg/claimpath"
	"github.com/SUNET/vc/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Apply is a pure rename + presence step. Value transformations
// (case folding, canonicalisation, date reformatting) live in derivations —
// see pkg/credential/derivations_test.go.
func TestAttributeMapper_Apply(t *testing.T) {
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
				"given_name":  {Claim: claimpath.Keys("given_name"), Required: true},
				"family_name": {Claim: claimpath.Keys("family_name"), Required: true},
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
				"oid_given_name":  {Claim: claimpath.Keys("identity", "given_name"), Required: true},
				"oid_family_name": {Claim: claimpath.Keys("identity", "family_name"), Required: true},
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
				"given_name": {Claim: claimpath.Keys("given_name"), Required: true},
			},
			attributes: map[string]any{},
			wantErr:    "missing required attribute",
		},
		{
			name: "optional attribute missing uses default",
			mapping: model.AttributeMapping{
				"country": {Claim: claimpath.Keys("country"), Required: false, Default: "SE"},
			},
			attributes: map[string]any{},
			want:       map[string]any{"country": "SE"},
		},
		{
			name: "optional attribute missing no default is skipped",
			mapping: model.AttributeMapping{
				"nickname": {Claim: claimpath.Keys("nickname"), Required: false},
			},
			attributes: map[string]any{},
			want:       map[string]any{},
		},
		{
			name: "extra attributes are ignored",
			mapping: model.AttributeMapping{
				"name": {Claim: claimpath.Keys("name"), Required: true},
			},
			attributes: map[string]any{"name": "Alice", "extra": "ignored"},
			want:       map[string]any{"name": "Alice"},
		},
		{
			name:       "empty mapping produces empty doc",
			mapping:    model.AttributeMapping{},
			attributes: map[string]any{"anything": "value"},
			want:       map[string]any{},
		},
		{
			name: "multi-value slice with as_array preserves both values",
			mapping: model.AttributeMapping{
				"nats": {Claim: claimpath.Keys("nationalities"), AsArray: true},
			},
			attributes: map[string]any{"nats": []string{"SE", "NO"}},
			want:       map[string]any{"nationalities": []string{"SE", "NO"}},
		},
		{
			name: "multi-value slice mapped to non-array claim collapses to first",
			mapping: model.AttributeMapping{
				"nats": {Claim: claimpath.Keys("nationality")},
			},
			attributes: map[string]any{"nats": []string{"SE", "NO"}},
			want:       map[string]any{"nationality": "SE"},
		},
		{
			name: "scalar attribute with as_array wraps in single-element slice",
			mapping: model.AttributeMapping{
				"nat": {Claim: claimpath.Keys("nationalities"), AsArray: true},
			},
			attributes: map[string]any{"nat": "SE"},
			want:       map[string]any{"nationalities": []string{"SE"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapper := NewAttributeMapper(tt.mapping, claimpath.Nested())
			got, err := mapper.Apply(tt.attributes)

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

func TestWrapAsArray(t *testing.T) {
	tests := []struct {
		name  string
		input any
		want  any
	}{
		{"scalar string is wrapped in []string", "SE", []string{"SE"}},
		{"any-typed variable holding string is wrapped", any("SE"), []string{"SE"}},
		{"empty string is wrapped", "", []string{""}},
		{"existing []string is unchanged", []string{"SE", "NO"}, []string{"SE", "NO"}},
		{"existing []any is unchanged", []any{"SE", "NO"}, []any{"SE", "NO"}},
		{"existing []int is unchanged", []int{1, 2, 3}, []int{1, 2, 3}},
		{"non-string scalar (int) is unchanged", 42, 42},
		{"non-string scalar (bool) is unchanged", true, true},
		{"nil is unchanged", nil, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, wrapAsArray(tt.input))
		})
	}
}
