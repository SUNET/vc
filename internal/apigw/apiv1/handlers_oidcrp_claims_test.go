package apiv1

import (
	"testing"
	"time"

	"github.com/SUNET/vc/internal/apigw/auth_providers/oidcrp"
	"github.com/SUNET/vc/internal/apigw/cache"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ehicMetadata has the shape that matters for issue #712: a credential type
// that declares credential content and nothing at all from the identity
// vocabulary. That is not a contrived case — no VCTM shipped in metadata/
// declares authentic_source_person_id, and vctm_ehic.json declares none of
// family_name, given_name or birth_date either.
func ehicMetadata() *model.CredentialMetadata {
	return &model.CredentialMetadata{VCTM: &sdjwtvc.VCTM{Claims: []sdjwtvc.Claim{
		{Path: []*string{new("social_security_pin")}},
		{Path: []*string{new("starting_date")}},
		{Path: []*string{new("date_of_issuance")}},
	}}}
}

// oidcIdentityClaims is what a provider hands back when no attribute_mapping
// is configured: the identity claims a datastore scope's auth_claims names,
// the ID-token envelope, and one claim the credential type actually declares.
func oidcIdentityClaims() map[string]any {
	return map[string]any{
		"authentic_source_person_id": "person-001",
		"given_name":                 "Helen",
		"family_name":                "Nilsson",
		"birth_date":                 "1970-01-01",
		"social_security_pin":        "12345",
		"sub":                        "helen@idp.example",
		"email":                      "helen@example.org",
		"iss":                        "https://idp.example",
		"aud":                        "vc-apigw",
		"exp":                        1893456000,
		"iat":                        1893452400,
	}
}

// claimsTestClient wires just enough of a Client to run the claim split, the
// datastore lookup and the document build.
func claimsTestClient(t *testing.T) (*Client, *memoryDatastoreStore, *memoryIdentityMappingStore, *cache.Service) {
	t.Helper()

	datastore := newMemoryDatastoreStore()
	identityStore := newMemoryIdentityMappingStore()
	cacheService := &cache.Service{
		Document: cache.NewTestMemoryCache[map[string]*model.CompleteDocument](10 * time.Minute),
	}

	c := &Client{
		log: logger.NewSimple("test"),
		cfg: &model.Cfg{
			Common: &model.Common{
				CredentialMetadata: map[string]*model.CredentialMetadata{"ehic": ehicMetadata()},
			},
			APIGW: &model.APIGW{
				DataSources: model.DataSources{
					Assertion: model.AssertionConfig{
						Scopes: map[string]model.AssertionScope{
							"ehic": {
								AuthProvider: "oidc",
								Defaults:     map[string]any{"starting_date": "2030-01-01"},
							},
						},
					},
				},
			},
		},
		datastoreStore:       datastore,
		identityMappingStore: identityStore,
		cacheService:         cacheService,
	}

	return c, datastore, identityStore, cacheService
}

// TestCallbackClaims_DatastoreLookupSeesAuthClaims is issue #712 for the VCI
// datastore path: auth_claims is operator configuration naming the claims used
// for identity lookup, and has nothing to do with what the credential type
// declares. Filtering it against the credential type leaves the lookup with
// nothing to work with.
func TestCallbackClaims_DatastoreLookupSeesAuthClaims(t *testing.T) {
	c, datastore, identityStore, cacheService := claimsTestClient(t)

	seedMapping(t, identityStore, "SUNET", "person-001", map[string]string{
		"given_name":  "Helen",
		"family_name": "Nilsson",
		"birth_date":  "1970-01-01",
	})
	seedDoc(t, datastore, "SUNET", "ehic", "doc-001", []string{"person-001"},
		map[string]any{"social_security_pin": "12345"})

	// Nil transformer: no attribute_mapping configured, which is the only
	// configuration in which the callback filter used to run at all.
	cc, err := c.newCallbackClaims("ehic", oidcIdentityClaims(), nil)
	require.NoError(t, err)

	dsCred := &model.DatastoreScope{AuthClaims: []string{"given_name", "family_name", "birth_date"}}

	require.NoError(t, c.LookupDatastoreByIdentity(t.Context(), "sess-1", "ehic", "SUNET", cc.identity, dsCred))

	cached, ok := cacheService.Document.Get(t.Context(), "sess-1")
	require.True(t, ok)
	require.Len(t, cached, 1)
	assert.Equal(t, "doc-001", cached["SUNET"].Meta.DocumentID)

	// The other side of the split, to show the filter is real and that feeding
	// it to the lookup is what issue #712 was: the credential-content claim set
	// cannot satisfy auth_claims.
	err = c.LookupDatastoreByIdentity(t.Context(), "sess-2", "ehic", "SUNET", cc.documentData(), dsCred)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required identity claims missing")
}

// TestCallbackClaims_PersonIDReachesResolveIdentifier covers the identifier
// side of the same split, used by both the VCI (ResolveVCIIdentifier) and the
// standalone (ResolveIdentifier) path.
func TestCallbackClaims_PersonIDReachesResolveIdentifier(t *testing.T) {
	c, _, _, _ := claimsTestClient(t)

	cc, err := c.newCallbackClaims("ehic", oidcIdentityClaims(), nil)
	require.NoError(t, err)

	// ResolveIdentifier path 1. The identity mapping store is empty on purpose:
	// if authentic_source_person_id did not survive, path 2 would have no
	// attributes either (the credential type declares none of them) and this
	// would fail with "no identifier claim or identity attributes found".
	id, err := c.ResolveIdentifier(t.Context(), "SUNET", cc.identity)
	require.NoError(t, err)
	assert.Equal(t, "person-001", id)

	// Same claim, other vocabulary: it is not credential content.
	assert.NotContains(t, cc.documentData(), "authentic_source_person_id")
}

// TestBuildOIDCDocument_KeepsIssue623Filtering pins that #623's protection
// still applies wherever claims become credential content. Both OIDC document
// points — the VCI assertion branch and the standalone branch — build their
// document here, which is the whole reason the decision lives in one place.
func TestBuildOIDCDocument_KeepsIssue623Filtering(t *testing.T) {
	undeclared := []string{
		"authentic_source_person_id", "given_name", "family_name", "birth_date",
		"sub", "email", "iss", "aud", "exp", "iat",
	}

	t.Run("VCI assertion branch", func(t *testing.T) {
		c, _, _, _ := claimsTestClient(t)
		cc, err := c.newCallbackClaims("ehic", oidcIdentityClaims(), nil)
		require.NoError(t, err)

		doc, err := c.buildOIDCDocument(cc, "https://issuer.example", true)
		require.NoError(t, err)

		assert.Equal(t, "https://issuer.example", doc.Meta.AuthenticSource)
		assert.Equal(t, "12345", doc.DocumentData["social_security_pin"])
		// Assertion defaults are still merged.
		assert.Equal(t, "2030-01-01", doc.DocumentData["starting_date"])
		assert.Contains(t, doc.DocumentData, "date_of_issuance")
		for _, name := range undeclared {
			assert.NotContains(t, doc.DocumentData, name, "undeclared claim must not become credential content")
		}

		// Merging defaults into the document must not pollute the identity
		// claims, which identity resolution still reads afterwards.
		assert.NotContains(t, cc.identity, "starting_date")
		assert.Equal(t, "person-001", cc.identity["authentic_source_person_id"])
	})

	t.Run("standalone branch, assertion data source", func(t *testing.T) {
		c, _, _, _ := claimsTestClient(t)
		cc, err := c.newCallbackClaims("ehic", oidcIdentityClaims(), nil)
		require.NoError(t, err)

		doc, err := c.buildOIDCDocument(cc, "https://issuer.example", true)
		require.NoError(t, err)

		assert.Equal(t, "12345", doc.DocumentData["social_security_pin"])
		assert.Equal(t, "2030-01-01", doc.DocumentData["starting_date"])
		for _, name := range undeclared {
			assert.NotContains(t, doc.DocumentData, name)
		}
	})

	// Standalone mode stores document data for every data source, not only for
	// assertion, so the filtering has to hold there too.
	t.Run("standalone branch, non-assertion data source", func(t *testing.T) {
		c, _, _, _ := claimsTestClient(t)
		cc, err := c.newCallbackClaims("ehic", oidcIdentityClaims(), nil)
		require.NoError(t, err)

		doc, err := c.buildOIDCDocument(cc, "https://issuer.example", false)
		require.NoError(t, err)

		assert.Equal(t, "12345", doc.DocumentData["social_security_pin"])
		assert.NotContains(t, doc.DocumentData, "starting_date", "assertion defaults are not for other data sources")
		assert.NotContains(t, doc.DocumentData, "date_of_issuance")
		for _, name := range undeclared {
			assert.NotContains(t, doc.DocumentData, name)
		}
	})
}

// TestBuildOIDCDocument_DoesNotMutateIdentityClaims: assertion defaults are
// credential content, not an authenticated identity. Merging them must not
// reach the claim set ResolveVCIIdentifier reads afterwards, or a default
// named sub or authentic_source_person_id would come back as an authenticated
// identifier. The two cases here are the ones where document data would
// otherwise still be the identity map itself.
func TestBuildOIDCDocument_DoesNotMutateIdentityClaims(t *testing.T) {
	setDefaults := func(c *Client, scope string) {
		c.cfg.APIGW.DataSources.Assertion.Scopes[scope] = model.AssertionScope{
			AuthProvider: "oidc",
			Defaults:     map[string]any{"authentic_source_person_id": "default-not-an-identity"},
		}
	}

	t.Run("transformer configured, nothing is filtered", func(t *testing.T) {
		c, _, _, _ := claimsTestClient(t)
		setDefaults(c, "ehic")

		transformer := oidcrp.NewClaimTransformer(model.AttributeMapping{"given_name": {Claim: "given_name"}})
		cc, err := c.newCallbackClaims("ehic", oidcIdentityClaims(), transformer)
		require.NoError(t, err)

		doc, err := c.buildOIDCDocument(cc, "https://issuer.example", true)
		require.NoError(t, err)

		assert.Equal(t, "default-not-an-identity", doc.DocumentData["authentic_source_person_id"])
		assert.NotContains(t, cc.identity, "authentic_source_person_id",
			"an assertion default must not become an authenticated identity")
	})

	t.Run("no metadata to filter against", func(t *testing.T) {
		c, _, _, _ := claimsTestClient(t)
		setDefaults(c, "unknown-scope")

		raw := map[string]any{"given_name": "Helen"}
		cc, err := c.newCallbackClaims("unknown-scope", raw, nil)
		require.NoError(t, err)

		doc, err := c.buildOIDCDocument(cc, "https://issuer.example", true)
		require.NoError(t, err)

		assert.Equal(t, "default-not-an-identity", doc.DocumentData["authentic_source_person_id"])
		assert.NotContains(t, cc.identity, "authentic_source_person_id")
		assert.NotContains(t, raw, "authentic_source_person_id",
			"the provider's own claim map must not be written to either")
	})

	// Assertion defaults are dot-notation paths, so MergeDefaults walks into
	// nested maps to set one. A shallow copy of the top level would leave that
	// nested map shared with the identity claims.
	t.Run("default path nested inside an existing claim", func(t *testing.T) {
		c, _, _, _ := claimsTestClient(t)
		c.cfg.APIGW.DataSources.Assertion.Scopes["unknown-scope"] = model.AssertionScope{
			AuthProvider: "oidc",
			Defaults:     map[string]any{"address.locality": "Stockholm"},
		}

		address := map[string]any{"country": "SE"}
		cc, err := c.newCallbackClaims("unknown-scope", map[string]any{"address": address}, nil)
		require.NoError(t, err)

		doc, err := c.buildOIDCDocument(cc, "https://issuer.example", true)
		require.NoError(t, err)

		documentAddress, ok := doc.DocumentData["address"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "Stockholm", documentAddress["locality"])
		assert.NotContains(t, address, "locality", "a nested default must not reach the identity claims")
	})
}

// TestCallbackClaims_TransformerOutputNotFiltered preserves the condition the
// filter has always had: with an attribute_mapping configured the operator has
// already declared which claims the credential gets, and filtering that output
// against the credential type on top would overrule them.
func TestCallbackClaims_TransformerOutputNotFiltered(t *testing.T) {
	c, _, _, _ := claimsTestClient(t)

	transformer := oidcrp.NewClaimTransformer(model.AttributeMapping{
		"given_name": {Claim: "given_name"},
		"email":      {Claim: "email"},
	})

	cc, err := c.newCallbackClaims("ehic", oidcIdentityClaims(), transformer)
	require.NoError(t, err)

	assert.Equal(t, map[string]any{"given_name": "Helen", "email": "helen@example.org"}, cc.identity)
	assert.Equal(t, cc.identity, cc.documentData(), "transformer output must not be filtered on top")

	doc, err := c.buildOIDCDocument(cc, "https://issuer.example", false)
	require.NoError(t, err)
	assert.Equal(t, "helen@example.org", doc.DocumentData["email"])
}

// TestCallbackClaims_TransformerError surfaces a required-attribute failure to
// the caller rather than issuing from a half-built claim set.
func TestCallbackClaims_TransformerError(t *testing.T) {
	c, _, _, _ := claimsTestClient(t)

	transformer := oidcrp.NewClaimTransformer(model.AttributeMapping{
		"personal_administrative_number": {Claim: "personal_administrative_number", Required: true},
	})

	cc, err := c.newCallbackClaims("ehic", oidcIdentityClaims(), transformer)
	require.Error(t, err)
	assert.Nil(t, cc)
}
