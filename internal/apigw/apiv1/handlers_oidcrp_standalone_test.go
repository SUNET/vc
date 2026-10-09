package apiv1

import (
	"testing"
	"time"

	"github.com/SUNET/vc/internal/apigw/auth_providers/oidcrp"
	apigwcache "github.com/SUNET/vc/internal/apigw/cache"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOIDCRPCallbackStandaloneDatastoreCachesDocument proves the standalone
// (non-VCI) OIDC callback routes a datastore scope through the datastore
// lookup: it must resolve the identity against the scope's configured
// authentic_source namespace, persist that namespace onto the pre-auth
// AuthorizationContext, and cache the pre-loaded datastore document instead of
// the OIDC callback claims. Helper-only coverage of LookupDatastoreByIdentity
// cannot catch this branch being removed or miswired, so the assertions are
// taken against what the callback itself persisted and cached.
func TestOIDCRPCallbackStandaloneDatastoreCachesDocument(t *testing.T) {
	const (
		scope           = "ehic"
		authenticSource = "SUNET"
		personID        = "person-001"
		documentID      = "doc-001"
	)

	client, service, cacheService := newStandaloneDatastoreTestClient(t, scope, authenticSource)

	ctx := t.Context()
	authReq, err := service.InitiateAuth(ctx, scope, nil, nil)
	require.NoError(t, err)

	session, err := service.GetSession(ctx, authReq.State)
	require.NoError(t, err)

	reply, err := client.OIDCRPCallback(ctx, &OIDCRPCallbackRequest{
		Code:  "standalone-test-code|" + session.Nonce,
		State: authReq.State,
	}, service)
	require.NoError(t, err)
	require.NotNil(t, reply)
	assert.Equal(t, "success", reply.Status)
	require.NotNil(t, reply.CredentialOffer)

	preAuthCode := reply.CredentialOffer.ID
	require.NotEmpty(t, preAuthCode)

	// The pre-auth context must carry the datastore data source and the scope's
	// configured namespace, so the token/credential endpoints resolve the same
	// identity mapping the PAR/VCI path already does.
	authCtx, err := cacheService.AuthContext.Get(ctx, &apigwcache.AuthorizationContext{SessionID: preAuthCode})
	require.NoError(t, err)
	assert.Equal(t, string(model.DataSourceDatastore), authCtx.DataSource)
	assert.Equal(t, authenticSource, authCtx.AuthenticSource)

	// The cached document must be the pre-loaded datastore document (keyed by
	// its authentic source), not the OIDC callback claims (which the assertion
	// path would cache under the IdP issuer URL).
	cached, ok := cacheService.Document.Get(ctx, preAuthCode)
	require.True(t, ok, "datastore document must be cached for the pre-auth code")
	require.Len(t, cached, 1)
	doc, ok := cached[authenticSource]
	require.True(t, ok, "document must be cached under the datastore authentic source, not the IdP issuer")
	assert.Equal(t, documentID, doc.Meta.DocumentID)
}

// newStandaloneDatastoreTestClient wires a Client for the standalone OIDC
// datastore path: a real oidcrp.Service against a mock OP that asserts the
// person id, in-memory datastore/identity stores seeded with the scope's
// document, and the auth-context/document caches the callback writes to.
func newStandaloneDatastoreTestClient(t *testing.T, scope, authenticSource string) (*Client, *oidcrp.Service, *apigwcache.Service) {
	t.Helper()
	ctx := t.Context()

	log, err := logger.New("standalone-datastore-test", "", false)
	require.NoError(t, err)

	tracer, err := trace.NewForTesting(ctx, "standalone-datastore-test", log)
	require.NoError(t, err)

	op := newPolicyMockOP(t)
	op.asserts = map[string]any{"authentic_source_person_id": "person-001"}

	sessionCache := apigwcache.NewTestMemoryCache[*oidcrp.Session](5 * time.Minute)
	t.Cleanup(sessionCache.Stop)

	service, err := oidcrp.New(ctx, &model.OIDCRP{
		Enable: true,
		Registration: &model.OIDCRPRegistrationConfig{
			Preconfigured: &model.OIDCRPPreconfiguredConfig{
				Enable:       true,
				ClientID:     op.clientID,
				ClientSecret: "standalone-test-secret",
			},
			Dynamic: &model.OIDCRPDynamicRegistrationConfig{Enable: false},
		},
		IssuerURL:       op.issuerURL,
		RedirectURI:     op.issuerURL + "/callback",
		Scopes:          []string{"openid"},
		SessionDuration: 300,
	}, sessionCache, nil, nil, log)
	require.NoError(t, err)
	require.NotNil(t, service)

	datastore := newMemoryDatastoreStore()
	identityStore := newMemoryIdentityMappingStore()
	seedDoc(t, datastore, authenticSource, scope, "doc-001", []string{"person-001"},
		map[string]any{"card": "SE-123"})

	cacheService := &apigwcache.Service{
		AuthContext: apigwcache.NewTestMemoryStore(10 * time.Minute),
		Document:    apigwcache.NewTestMemoryCache[map[string]*model.CompleteDocument](10 * time.Minute),
	}

	client := &Client{
		log:    log,
		tracer: tracer,
		cfg: &model.Cfg{
			Common: &model.Common{},
			APIGW: &model.APIGW{
				Delivery: model.APIGWDelivery{
					CredentialOffers: model.CredentialOffers{IssuerURL: "https://issuer.example.com"},
				},
				DataSources: model.DataSources{
					Datastore: model.DatastoreConfig{Scopes: map[string]model.DatastoreScope{
						scope: {
							AuthProvider:    model.AuthProviderOIDC,
							AuthenticSource: authenticSource,
							AuthClaims:      []string{"authentic_source_person_id"},
						},
					}},
				},
			},
		},
		datastoreStore:       datastore,
		identityMappingStore: identityStore,
		cacheService:         cacheService,
	}

	return client, service, cacheService
}
