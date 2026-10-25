package model

import (
	"slices"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/claimpath"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAssertionScope_MergeDefaults(t *testing.T) {
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	nested := claimpath.Nested()
	value := func(path claimpath.Pointer, v any) ClaimDefault { return ClaimDefault{Path: path, Value: v} }

	tests := []struct {
		name     string
		scope    AssertionScope
		doc      map[string]any
		want     map[string]any
		wantErrs bool
	}{
		{
			name:  "no expiry_duration merges Defaults verbatim plus date_of_issuance",
			scope: AssertionScope{Defaults: ClaimDefaults{value(claimpath.Keys("issuing_authority"), "SUNET"), value(claimpath.Keys("date_of_expiry"), "2030-01-01")}},
			doc:   map[string]any{},
			want:  map[string]any{"issuing_authority": "SUNET", "date_of_expiry": "2030-01-01", "date_of_issuance": "2026-09-17"},
		},
		{
			name:  "expiry_duration overrides static date_of_expiry",
			scope: AssertionScope{Defaults: ClaimDefaults{value(claimpath.Keys("date_of_expiry"), "2020-01-01")}, ExpiryDuration: "8760h"},
			doc:   map[string]any{},
			want:  map[string]any{"date_of_expiry": "2027-09-17", "date_of_issuance": "2026-09-17"},
		},
		{
			name:  "date_of_issuance overrides any static default",
			scope: AssertionScope{Defaults: ClaimDefaults{value(claimpath.Keys("date_of_issuance"), "2020-01-01")}},
			doc:   map[string]any{},
			want:  map[string]any{"date_of_issuance": "2026-09-17"},
		},
		{
			name:  "an existing claim wins over its default",
			scope: AssertionScope{Defaults: ClaimDefaults{value(claimpath.Keys("issuing_country"), "SE")}},
			doc:   map[string]any{"issuing_country": "NO"},
			want:  map[string]any{"issuing_country": "NO", "date_of_issuance": "2026-09-17"},
		},
		{
			name:  "a nested default merges into an existing sibling",
			scope: AssertionScope{Defaults: ClaimDefaults{value(claimpath.Keys("identity", "country"), "SE")}},
			doc:   map[string]any{"identity": map[string]any{"given_name": "Alice"}},
			want:  map[string]any{"identity": map[string]any{"given_name": "Alice", "country": "SE"}, "date_of_issuance": "2026-09-17"},
		},
		{name: "invalid expiry_duration", scope: AssertionScope{ExpiryDuration: "not-a-duration"}, doc: map[string]any{}, wantErrs: true},
		{name: "non-positive expiry_duration", scope: AssertionScope{ExpiryDuration: "-1h"}, doc: map[string]any{}, wantErrs: true},
		{
			name:     "a default beneath a scalar claim",
			scope:    AssertionScope{Defaults: ClaimDefaults{value(claimpath.Keys("identity", "country"), "SE")}},
			doc:      map[string]any{"identity": "not-a-map"},
			wantErrs: true,
		},
		{
			name:     "overlapping defaults",
			scope:    AssertionScope{Defaults: ClaimDefaults{value(claimpath.Keys("identity"), map[string]any{"country": "NO"}), value(claimpath.Keys("identity", "country"), "SE")}},
			doc:      map[string]any{},
			wantErrs: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := slices.Clone(tt.scope.Defaults)
			err := tt.scope.MergeDefaults(tt.doc, now, nested)
			if tt.wantErrs {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, tt.doc)
			assert.Equal(t, before, tt.scope.Defaults, "Defaults is not mutated")
		})
	}
}

func TestPresentationScope_MergeDefaults(t *testing.T) {
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	scope := PresentationScope{
		Defaults:       ClaimDefaults{{Path: claimpath.Keys("issuing_authority"), Value: "SUNET"}},
		ExpiryDuration: "8760h",
	}
	doc := map[string]any{}
	require.NoError(t, scope.MergeDefaults(doc, now, claimpath.Nested()))
	assert.Equal(t, map[string]any{"issuing_authority": "SUNET", "date_of_expiry": "2027-09-17", "date_of_issuance": "2026-09-17"}, doc)
}

func TestLookupCredentialSources_Presentation(t *testing.T) {
	ds := &DataSources{
		Presentation: PresentationConfig{
			Scopes: map[string]PresentationScope{
				"eduid_age_verification": {
					AuthProvider: "openid4vp",
					From: map[string]PresentedCredential{
						"eduid": {RequiredClaims: RequiredClaims{{Path: claimpath.Keys("birthdate")}}},
					},
				},
			},
		},
	}
	sources, err := ds.LookupCredentialSources("eduid_age_verification")
	require.NoError(t, err)
	require.Len(t, sources, 1)
	assert.Equal(t, DataSourcePresentation, sources[0].DataSource)
	assert.Equal(t, "openid4vp", sources[0].AuthProvider)
}
