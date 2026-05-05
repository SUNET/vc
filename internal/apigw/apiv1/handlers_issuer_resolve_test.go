package apiv1

import (
	"context"
	"errors"
	"testing"

	"github.com/SUNET/vc/internal/apigw/db"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockIdentityMappingStore is a test double for db.IdentityMappingStore
type mockIdentityMappingStore struct {
	resolveResult string
	resolveErr    error
	resolveQuery  *db.ResolveMappingQuery // captured for assertions
}

func (m *mockIdentityMappingStore) CreateMapping(_ context.Context, _ *model.IdentityMapping) error {
	return nil
}
func (m *mockIdentityMappingStore) EnsureMapping(_ context.Context, _ *model.IdentityMapping) error {
	return nil
}
func (m *mockIdentityMappingStore) ResolveMapping(_ context.Context, query *db.ResolveMappingQuery) (string, error) {
	m.resolveQuery = query
	return m.resolveResult, m.resolveErr
}
func (m *mockIdentityMappingStore) UpdateMapping(_ context.Context, _ *model.IdentityMapping) error {
	return nil
}
func (m *mockIdentityMappingStore) DeleteMapping(_ context.Context, _ *db.DeleteMappingQuery) error {
	return nil
}

func newTestClient(t *testing.T, store *mockIdentityMappingStore) *Client {
	t.Helper()
	log, err := logger.New("test", "", false)
	require.NoError(t, err)
	return &Client{
		log:                  log,
		identityMappingStore: store,
	}
}

func TestResolveIdentifier_DirectClaim(t *testing.T) {
	tts := []struct {
		name   string
		claims map[string]any
		want   string
	}{
		{
			name:   "authentic_source_person_id",
			claims: map[string]any{"authentic_source_person_id": "aspid-789"},
			want:   "aspid-789",
		},
		{
			name:   "authentic_source_person_id_with_other_claims",
			claims: map[string]any{"sub": "ignored", "authentic_source_person_id": "aspid-direct"},
			want:   "aspid-direct",
		},
		{
			name:   "skips_empty_string",
			claims: map[string]any{"authentic_source_person_id": "", "family_name": "Doe"},
			want:   "mapped-id",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			store := &mockIdentityMappingStore{resolveResult: "mapped-id"}
			c := newTestClient(t, store)

			id, err := c.ResolveIdentifier(t.Context(), "AS1", tt.claims)

			require.NoError(t, err)
			assert.Equal(t, tt.want, id)
		})
	}
}

func TestResolveIdentifier_IdentityMapping(t *testing.T) {
	tts := []struct {
		name          string
		authenticSrc  string
		claims        map[string]any
		storeResult   string
		storeErr      error
		want          string
		wantErr       string
		wantAttrCount int
	}{
		{
			name:         "success_full_attributes",
			authenticSrc: "SUNET",
			claims: map[string]any{
				"family_name": "Doe",
				"given_name":  "John",
				"birth_date":  "1990-01-15",
			},
			storeResult:   "resolved-id",
			want:          "resolved-id",
			wantAttrCount: 3,
		},
		{
			name:         "success_partial_attributes",
			authenticSrc: "AS1",
			claims: map[string]any{
				"family_name": "Smith",
			},
			storeResult:   "partial-id",
			want:          "partial-id",
			wantAttrCount: 1,
		},
		{
			name:         "store_returns_error",
			authenticSrc: "AS1",
			claims: map[string]any{
				"family_name": "Unknown",
				"given_name":  "Person",
				"birth_date":  "2000-01-01",
			},
			storeErr: errors.New("not found"),
			wantErr:  "identity mapping resolution failed",
		},
		{
			name:         "sub_falls_through_to_mapping",
			authenticSrc: "AS1",
			claims: map[string]any{
				"sub":         "external-op-id",
				"family_name": "Doe",
				"given_name":  "Jane",
				"birth_date":  "1985-06-15",
			},
			storeResult:   "mapped-id",
			want:          "mapped-id",
			wantAttrCount: 3,
		},
		{
			name:         "non_string_identifiers_fall_through",
			authenticSrc: "AS1",
			claims: map[string]any{
				"authentic_source_person_id": 42,
				"family_name":                "Doe",
				"given_name":                 "Jane",
				"birth_date":                 "1985-06-15",
			},
			storeResult:   "mapped-id",
			want:          "mapped-id",
			wantAttrCount: 3,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			store := &mockIdentityMappingStore{
				resolveResult: tt.storeResult,
				resolveErr:    tt.storeErr,
			}
			c := newTestClient(t, store)

			id, err := c.ResolveIdentifier(t.Context(), tt.authenticSrc, tt.claims)

			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, id)
			require.NotNil(t, store.resolveQuery)
			assert.Equal(t, tt.authenticSrc, store.resolveQuery.AuthenticSource)
			if tt.wantAttrCount > 0 {
				assert.Len(t, store.resolveQuery.Attributes, tt.wantAttrCount)
			}
		})
	}
}

func TestResolveIdentifier_Error(t *testing.T) {
	tts := []struct {
		name    string
		claims  map[string]any
		wantErr string
	}{
		{
			name:    "empty_claims",
			claims:  map[string]any{},
			wantErr: "no identifier claim or identity attributes",
		},
		{
			name:    "irrelevant_claims_only",
			claims:  map[string]any{"email": "user@example.com", "iss": "https://idp.example.com"},
			wantErr: "no identifier claim or identity attributes",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestClient(t, &mockIdentityMappingStore{})

			_, err := c.ResolveIdentifier(t.Context(), "AS1", tt.claims)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}
