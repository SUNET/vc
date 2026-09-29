package credential

import (
	"testing"

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
			want:       map[string]any{"country": "SE"},
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
			name: "extra attributes are ignored",
			mapping: model.AttributeMapping{
				"name": {Claim: "name", Required: true},
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
				"nats": {Claim: "nationalities", AsArray: true},
			},
			attributes: map[string]any{"nats": []string{"SE", "NO"}},
			want:       map[string]any{"nationalities": []string{"SE", "NO"}},
		},
		{
			name: "multi-value slice mapped to non-array claim collapses to first",
			mapping: model.AttributeMapping{
				"nats": {Claim: "nationality"},
			},
			attributes: map[string]any{"nats": []string{"SE", "NO"}},
			want:       map[string]any{"nationality": "SE"},
		},
		{
			name: "scalar attribute with as_array wraps in single-element slice",
			mapping: model.AttributeMapping{
				"nat": {Claim: "nationalities", AsArray: true},
			},
			attributes: map[string]any{"nat": "SE"},
			want:       map[string]any{"nationalities": []string{"SE"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapper := NewAttributeMapper(tt.mapping)
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

func TestMergeDefaults(t *testing.T) {
	tests := []struct {
		name     string
		claims   map[string]any
		defaults map[string]any
		want     map[string]any
	}{
		{
			name:     "flat default injected when missing",
			claims:   map[string]any{},
			defaults: map[string]any{"issuing_country": "SE"},
			want:     map[string]any{"issuing_country": "SE"},
		},
		{
			name:     "flat default does not overwrite existing flat claim",
			claims:   map[string]any{"issuing_country": "NO"},
			defaults: map[string]any{"issuing_country": "SE"},
			want:     map[string]any{"issuing_country": "NO"},
		},
		{
			name:     "nested default becomes nested claim",
			claims:   map[string]any{},
			defaults: map[string]any{"identity.country": "SE"},
			want:     map[string]any{"identity": map[string]any{"country": "SE"}},
		},
		{
			name:     "nested default does not overwrite existing nested claim",
			claims:   map[string]any{"identity": map[string]any{"country": "NO"}},
			defaults: map[string]any{"identity.country": "SE"},
			want:     map[string]any{"identity": map[string]any{"country": "NO"}},
		},
		{
			name:     "nested default merges into existing sibling",
			claims:   map[string]any{"identity": map[string]any{"given_name": "Alice"}},
			defaults: map[string]any{"identity.country": "SE"},
			want: map[string]any{
				"identity": map[string]any{"given_name": "Alice", "country": "SE"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := MergeDefaults(tt.claims, tt.defaults)
			require.NoError(t, err)
			assert.Equal(t, tt.want, tt.claims)
		})
	}
}

func TestMergeDefaults_PathConflict(t *testing.T) {
	claims := map[string]any{"identity": "not-a-map"}
	err := MergeDefaults(claims, map[string]any{"identity.country": "SE"})
	require.Error(t, err)
}

func TestMergeDefaults_OverlappingPathsRejected(t *testing.T) {
	err := MergeDefaults(map[string]any{}, map[string]any{
		"identity":         map[string]any{"country": "NO"},
		"identity.country": "SE",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "overlapping default paths")
}

func TestMergeDefaults_DeterministicOrder(t *testing.T) {
	for range 50 {
		claims := map[string]any{}
		err := MergeDefaults(claims, map[string]any{
			"a.b": "1",
			"a.c": "2",
			"x.y": "3",
		})
		require.NoError(t, err)
		assert.Equal(t, map[string]any{
			"a": map[string]any{"b": "1", "c": "2"},
			"x": map[string]any{"y": "3"},
		}, claims)
	}
}
