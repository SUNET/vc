package apiv1

import (
	"testing"
	"time"

	"github.com/SUNET/vc/internal/apigw/cache"
	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResolveVCIIdentifier_Assertion verifies that when DataSource is "assertion",
// ResolveVCIIdentifier does NOT call ResolveIdentifier (identity mapping lookup)
// and instead returns the identifier from claims or fallbacks.
func TestResolveVCIIdentifier_Assertion(t *testing.T) {
	tts := []struct {
		name            string
		dataSource      string
		claims          map[string]any
		fallbacks       []string
		wantIdentifier  string
		wantStoreCalled bool
	}{
		{
			name:       "assertion_prefers_authentic_source_person_id",
			dataSource: string(model.DataSourceAssertion),
			claims: map[string]any{
				"authentic_source_person_id": "aspid-direct",
				"sub":                        "oidc-subject-456",
			},
			wantIdentifier:  "aspid-direct",
			wantStoreCalled: false,
		},
		{
			name:       "assertion_falls_back_to_sub",
			dataSource: string(model.DataSourceAssertion),
			claims: map[string]any{
				"sub":         "oidc-subject-123",
				"given_name":  "Jane",
				"family_name": "Doe",
			},
			wantIdentifier:  "oidc-subject-123",
			wantStoreCalled: false,
		},
		{
			name:       "assertion_uses_fallbacks_when_no_claims",
			dataSource: string(model.DataSourceAssertion),
			claims: map[string]any{
				"given_name":  "Test",
				"family_name": "User",
			},
			fallbacks:       []string{"", "idtoken-subject"},
			wantIdentifier:  "idtoken-subject",
			wantStoreCalled: false,
		},
		{
			name:       "assertion_empty_when_nothing_available",
			dataSource: string(model.DataSourceAssertion),
			claims: map[string]any{
				"given_name": "Test",
			},
			wantIdentifier:  "",
			wantStoreCalled: false,
		},
		{
			name:       "assertion_skips_mapping_even_when_store_has_result",
			dataSource: string(model.DataSourceAssertion),
			claims: map[string]any{
				"sub":         "subject-from-claim",
				"family_name": "Doe",
				"given_name":  "John",
				"birth_date":  "1985-03-15",
			},
			wantIdentifier:  "subject-from-claim",
			wantStoreCalled: false,
		},
		{
			name:       "datastore_uses_identity_mapping",
			dataSource: string(model.DataSourceDatastore),
			claims: map[string]any{
				"family_name": "Doe",
				"given_name":  "John",
				"birth_date":  "1985-03-15",
			},
			wantIdentifier:  "resolved-via-mapping",
			wantStoreCalled: true,
		},
		{
			name:       "external_api_uses_identity_mapping",
			dataSource: string(model.DataSourceExternalAPI),
			claims: map[string]any{
				"family_name": "Doe",
				"given_name":  "John",
				"birth_date":  "1985-03-15",
			},
			wantIdentifier:  "resolved-via-mapping",
			wantStoreCalled: true,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			store := &mockIdentityMappingStore{resolveResult: "resolved-via-mapping"}

			authContextStore := cache.NewTestMemoryStore(10 * time.Minute)
			docCache := cache.NewTestMemoryCache[map[string]*model.CompleteDocument](10 * time.Minute)

			client := newTestClient(t, store)
			client.cacheService = &cache.Service{
				AuthContext: authContextStore,
				Document:    docCache,
			}

			authCtx := &cache.AuthorizationContext{
				SessionID:       "test-session",
				DataSource:      tt.dataSource,
				AuthenticSource: "test-source",
			}

			identifier, err := client.ResolveVCIIdentifier(t.Context(), authCtx, tt.claims, tt.fallbacks...)
			require.NoError(t, err)

			assert.Equal(t, tt.wantIdentifier, identifier)

			if tt.wantStoreCalled {
				assert.NotNil(t, store.resolveQuery, "identity mapping store should have been called")
			} else {
				assert.Nil(t, store.resolveQuery, "identity mapping store should NOT have been called for assertion")
			}
		})
	}
}

// TestResolveVCIIdentifier_PreExistingIdentifier verifies that if authCtx already
// has an Identifier set, it is returned immediately without further resolution.
func TestResolveVCIIdentifier_PreExistingIdentifier(t *testing.T) {
	store := &mockIdentityMappingStore{resolveResult: "should-not-be-used"}
	client := newTestClient(t, store)

	authCtx := &cache.AuthorizationContext{
		SessionID:       "test-session",
		DataSource:      string(model.DataSourceAssertion),
		AuthenticSource: "test-source",
		Identifier:      "pre-existing-id",
	}

	identifier, err := client.ResolveVCIIdentifier(t.Context(), authCtx, map[string]any{"sub": "other"})
	require.NoError(t, err)
	assert.Equal(t, "pre-existing-id", identifier)
	assert.Nil(t, store.resolveQuery, "store should not be called when identifier already set")
}

// TestAssertionDataSource_CredentialIssuance_AllowsEmptyIdentifier verifies that
// the credential issuance handler does not hard-fail on an empty identifier when
// DataSource is "assertion".
func TestAssertionDataSource_CredentialIssuance_AllowsEmptyIdentifier(t *testing.T) {
	tts := []struct {
		name       string
		dataSource model.DataSourceType
		identifier string
		wantErr    bool
	}{
		{
			name:       "assertion_empty_identifier_allowed",
			dataSource: model.DataSourceAssertion,
			identifier: "",
			wantErr:    false,
		},
		{
			name:       "assertion_with_identifier_allowed",
			dataSource: model.DataSourceAssertion,
			identifier: "some-id",
			wantErr:    false,
		},
		{
			name:       "datastore_empty_identifier_rejected",
			dataSource: model.DataSourceDatastore,
			identifier: "",
			wantErr:    true,
		},
		{
			name:       "external_api_empty_identifier_rejected",
			dataSource: model.DataSourceExternalAPI,
			identifier: "",
			wantErr:    true,
		},
		{
			name:       "datastore_with_identifier_allowed",
			dataSource: model.DataSourceDatastore,
			identifier: "person-123",
			wantErr:    false,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got, err := requireIdentifier(tt.identifier, tt.dataSource)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.identifier, got)
			}
		})
	}
}
