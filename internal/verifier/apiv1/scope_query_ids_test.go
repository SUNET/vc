package apiv1

import (
	"testing"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestScopeQueryIDs covers the mapping that lets VerificationDirectPost find a
// wallet's response. A wallet keys vp_token by query id, and every shipped
// template names its query something other than the request's scope (eudi_pid
// for pid), so without the mapping the verifier reads a key never sent.
func TestScopeQueryIDs(t *testing.T) {
	client := dcqlClientFor(t, map[string]*model.CredentialMetadata{
		"pid":      sdJWTScope("urn:eudi:pid:1"),
		"ehic":     sdJWTScope("urn:eudi:ehic:1"),
		"pid_mdoc": {Format: "mso_mdoc", MDDL: &mdoc.MDDLSchema{DocType: "eu.europa.ec.eudi.pid.1"}},
		// No expressible constraint, so no honest way to recognise its query.
		"diploma_ldp": w3cScope("urn:eudi:diploma:1"),
	}, nil)

	// Shaped like presentation_requests/: query ids are template names.
	dcql := &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{
		{ID: "eudi_pid", Format: "dc+sd-jwt", Meta: openid4vp.MetaQuery{VCTValues: []string{"urn:eudi:pid:1"}}},
		{ID: "mdl_query", Format: "mso_mdoc", Meta: openid4vp.MetaQuery{DoctypeValue: "eu.europa.ec.eudi.pid.1"}},
		// Already keyed by its scope, as buildDCQLQueryFromConfig builds them.
		{ID: "ehic", Format: "dc+sd-jwt", Meta: openid4vp.MetaQuery{VCTValues: []string{"urn:eudi:ehic:1"}}},
	}}

	got := client.ScopeQueryIDs(t.Context(), dcql, []string{"pid", "ehic", "pid_mdoc", "diploma_ldp", "profile"})

	// Only the pairs that actually differ, so the common case costs nothing.
	assert.Equal(t, map[string]string{
		"pid":      "eudi_pid",
		"pid_mdoc": "mdl_query",
	}, got)
}

// TestScopeQueryIDsNoTemplateNames is the config-fallback shape: every query is
// keyed by its own scope, so there is nothing to record and the response lookup
// stays direct.
func TestScopeQueryIDsNoTemplateNames(t *testing.T) {
	client := dcqlClientFor(t, map[string]*model.CredentialMetadata{
		"pid": sdJWTScope("urn:eudi:pid:1"),
	}, nil)

	dcql, err := client.buildDCQLQueryFromConfig([]string{"pid"})
	require.NoError(t, err)

	assert.Empty(t, client.ScopeQueryIDs(t.Context(), dcql, []string{"pid"}))
}

// TestUncoveredScopesRejectsUnaskedCredential covers the request side.
// createDCQLQuery selects ONE template, so a request naming credentials it does
// not cover goes out as a subset while authCtx.Scopes keeps the full list -
// then waits for a token the wallet was never asked for.
func TestUncoveredScopesRejectsUnaskedCredential(t *testing.T) {
	client := dcqlClientFor(t, map[string]*model.CredentialMetadata{
		"pid":  sdJWTScope("urn:eudi:pid:1"),
		"ehic": sdJWTScope("urn:eudi:ehic:1"),
		// Not expressible: a template may cover it with type_values and there
		// is no way to tell yet, so it must NOT be reported.
		"diploma_ldp": w3cScope("urn:eudi:diploma:1"),
	}, nil)

	pidOnly := &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{
		{ID: "eudi_pid", Format: "dc+sd-jwt", Meta: openid4vp.MetaQuery{VCTValues: []string{"urn:eudi:pid:1"}}},
	}}

	assert.Equal(t, []string{"ehic"},
		client.uncoveredScopes(t.Context(), pidOnly, []string{"pid", "ehic", "profile"}),
		"a configured, expressible scope the query never mentions is unfulfillable")

	assert.Empty(t, client.uncoveredScopes(t.Context(), pidOnly, []string{"pid", "diploma_ldp"}),
		"a scope with no expressible constraint must not be reported: a template may cover it")

	assert.Empty(t, client.uncoveredScopes(t.Context(), pidOnly, []string{"pid", "profile", "openid"}),
		"unconfigured scopes are ordinary OIDC scopes")
}

// TestVPTokensForScope covers the response side: how a wallet's vp_token is
// matched back to the scope that asked for it.
//
// The template case is the reported bug: the request is made with scope
// "pid", the shipped template names its query "eudi_pid", and the wallet
// answers under the query id, so the scope-keyed lookup finds nothing.
func TestVPTokensForScope(t *testing.T) {
	client, _ := CreateTestClientWithMock(t, nil)

	tests := []struct {
		name             string
		authCtx          *cache.AuthorizationContext
		credentialScopes []string
		// defaultAllowed is what defaultTokenAllowed decided for this
		// request; see TestDefaultTokenAllowed for how it is derived.
		defaultAllowed bool
		vpToken        map[string][]string
		scope          string
		want           []string
		wantError      string
	}{
		{
			name:             "keyed by the scope, as a config-built query is",
			authCtx:          &cache.AuthorizationContext{Scopes: []string{"pid", "ehic"}},
			credentialScopes: []string{"pid", "ehic"},
			vpToken:          map[string][]string{"pid": {"token-pid"}},
			scope:            "pid",
			want:             []string{"token-pid"},
		},
		{
			// The bug: without the mapping this is "VP token not found".
			name: "keyed by the template's query id",
			authCtx: &cache.AuthorizationContext{
				Scopes:        []string{"pid", "ehic"},
				ScopeQueryIDs: map[string]string{"pid": "eudi_pid"},
			},
			credentialScopes: []string{"pid", "ehic"},
			vpToken:          map[string][]string{"eudi_pid": {"token-pid"}},
			scope:            "pid",
			want:             []string{"token-pid"},
		},
		{
			// The scope's own key wins, so a wallet that answers correctly is
			// never second-guessed by the mapping.
			name: "scope key preferred over the mapped query id",
			authCtx: &cache.AuthorizationContext{
				Scopes:        []string{"pid", "ehic"},
				ScopeQueryIDs: map[string]string{"pid": "eudi_pid"},
			},
			credentialScopes: []string{"pid", "ehic"},
			vpToken:          map[string][]string{"pid": {"right"}, "eudi_pid": {"wrong"}},
			scope:            "pid",
			want:             []string{"right"},
		},
		{
			// The shape an ordinary OIDC request has: several scopes asked for,
			// one credential among them.
			name:             "plain-string vp_token with a single requested credential",
			authCtx:          &cache.AuthorizationContext{Scopes: []string{"openid", "profile", "pid"}},
			credentialScopes: []string{"pid"},
			defaultAllowed:   true,
			vpToken:          map[string][]string{"_default": {"token-pid"}},
			scope:            "pid",
			want:             []string{"token-pid"},
		},
		{
			// _default with several scopes would reuse one credential for each,
			// carrying whichever validations belong to the others.
			name:             "plain-string vp_token refused for a multi-scope request",
			authCtx:          &cache.AuthorizationContext{Scopes: []string{"pid", "ehic"}},
			credentialScopes: []string{"pid", "ehic"},
			vpToken:          map[string][]string{"_default": {"token"}},
			scope:            "pid",
			wantError:        "_default fallback is only allowed when the request asks for exactly one credential and that scope is it",
		},
		{
			name:             "nothing usable",
			authCtx:          &cache.AuthorizationContext{Scopes: []string{"pid"}},
			credentialScopes: []string{"pid"},
			defaultAllowed:   true,
			vpToken:          map[string][]string{"something_else": {"token"}},
			scope:            "pid",
			wantError:        "VP token not found for scope: pid",
		},
		{
			// The finding: a template author writes the queries, and there can
			// be more of them than the scopes that map onto them. One scope
			// against a two-credential query left the scope count at 1, so
			// _default was accepted and only one credential was ever validated.
			name:             "plain-string vp_token refused when _default cannot be attributed",
			authCtx:          &cache.AuthorizationContext{Scopes: []string{"openid", "pid"}},
			credentialScopes: []string{"pid"},
			vpToken:          map[string][]string{"_default": {"token"}},
			scope:            "pid",
			wantError:        "_default fallback is only allowed when the request asks for exactly one credential and that scope is it",
		},
		{
			// A mapping that points at a key the wallet did not send must not
			// swallow the error.
			name: "mapped query id absent from the response",
			authCtx: &cache.AuthorizationContext{
				Scopes:        []string{"pid", "ehic"},
				ScopeQueryIDs: map[string]string{"pid": "eudi_pid"},
			},
			credentialScopes: []string{"pid", "ehic"},
			vpToken:          map[string][]string{"ehic": {"token-ehic"}},
			scope:            "pid",
			wantError:        "_default fallback is only allowed when the request asks for exactly one credential and that scope is it",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := client.vpTokensForScope(tt.authCtx.ScopeQueryIDs, tt.defaultAllowed, openid4vp.VPResponse{VPToken: tt.vpToken}, tt.scope)
			if tt.wantError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantError)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// stubTemplate is a presentation template with the shape the shipped ones have:
// a query named for the template, selected by scopes that need not be
// credential_metadata keys.
type stubTemplate struct {
	id     string
	scopes []string
	dcql   *openid4vp.DCQL
}

func (t stubTemplate) GetID() string                 { return t.id }
func (t stubTemplate) GetOIDCScopes() []string       { return t.scopes }
func (t stubTemplate) GetDCQLQuery() *openid4vp.DCQL { return t.dcql }

// TestScopeQueryIDsAliasTemplateScope covers the shape half the shipped
// templates have: eudi_pid_full is selected by scope "pid_full" while the
// credential is configured as "pid". Such a scope has no constraint of its own
// but is what lands in authCtx.Scopes, so skipping unconfigured scopes left
// exactly these templates broken.
func TestScopeQueryIDsAliasTemplateScope(t *testing.T) {
	client := dcqlClientFor(t, map[string]*model.CredentialMetadata{
		"pid": sdJWTScope("urn:eudi:pid:1"),
	}, nil)

	// What eudi_pid_full is: one query named for the template, selected by a
	// scope that configures no credential.
	dcql := &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{
		{ID: "eudi_pid", Format: "dc+sd-jwt", Meta: openid4vp.MetaQuery{VCTValues: []string{"urn:eudi:pid:1"}}},
	}}
	client.presentationBuilder = openid4vp.NewPresentationBuilder([]openid4vp.PresentationRequestTemplate{
		stubTemplate{id: "eudi_pid_full", scopes: []string{"pid_full"}, dcql: dcql},
	})

	pairs := client.ScopeQueryIDs(t.Context(), dcql, []string{"pid_full"})
	assert.Equal(t, map[string]string{"pid_full": "eudi_pid"}, pairs,
		"an alias scope must still resolve to the query the wallet answers under")

	// And the response then resolves, which is the whole point.
	tokens, err := client.vpTokensForScope(
		pairs,
		false,
		openid4vp.VPResponse{VPToken: map[string][]string{"eudi_pid": {"token-pid"}}},
		"pid_full",
	)
	require.NoError(t, err)
	assert.Equal(t, []string{"token-pid"}, tokens)
}

// TestScopeQueryIDsIgnoresScopesTheTemplateDoesNotClaim covers a review
// finding: a request can name scopes the selected template says nothing about -
// "pid_full something_else" still selects the PID template - and mapping those
// would key the same credential under a scope the template never claimed, so
// VerificationDirectPost would process and cache the one credential twice.
func TestScopeQueryIDsIgnoresScopesTheTemplateDoesNotClaim(t *testing.T) {
	client := dcqlClientFor(t, map[string]*model.CredentialMetadata{
		"pid": sdJWTScope("urn:eudi:pid:1"),
	}, nil)

	dcql := &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{
		{ID: "eudi_pid", Format: "dc+sd-jwt", Meta: openid4vp.MetaQuery{VCTValues: []string{"urn:eudi:pid:1"}}},
	}}
	client.presentationBuilder = openid4vp.NewPresentationBuilder([]openid4vp.PresentationRequestTemplate{
		stubTemplate{id: "eudi_pid_full", scopes: []string{"pid_full"}, dcql: dcql},
	})

	pairs := client.ScopeQueryIDs(t.Context(), dcql, []string{"pid_full", "something_else"})
	assert.Equal(t, map[string]string{"pid_full": "eudi_pid"}, pairs)
	assert.NotContains(t, pairs, "something_else")
}

// TestScopeQueryIDsAliasScopeAmbiguous pins the limit of that fallback: with
// several queries in the request there is nothing to choose on, since a
// template's queries carry no record of which of its oidc_scopes each answers.
// The scope is left unmapped rather than guessed at.
func TestScopeQueryIDsAliasScopeAmbiguous(t *testing.T) {
	client := dcqlClientFor(t, map[string]*model.CredentialMetadata{
		"pid":  sdJWTScope("urn:eudi:pid:1"),
		"ehic": sdJWTScope("urn:eudi:ehic:1"),
	}, nil)

	dcql := &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{
		{ID: "eudi_pid", Format: "dc+sd-jwt", Meta: openid4vp.MetaQuery{VCTValues: []string{"urn:eudi:pid:1"}}},
		{ID: "eudi_ehic", Format: "dc+sd-jwt", Meta: openid4vp.MetaQuery{VCTValues: []string{"urn:eudi:ehic:1"}}},
	}}

	got := client.ScopeQueryIDs(t.Context(), dcql, []string{"combined_full"})
	assert.Empty(t, got, "an unconfigured scope with several candidate queries must not be guessed")

	// Configured scopes in the same request still pair exactly, by constraint.
	assert.Equal(t, map[string]string{"pid": "eudi_pid", "ehic": "eudi_ehic"},
		client.ScopeQueryIDs(t.Context(), dcql, []string{"pid", "ehic"}))
}

// TestCredentialScopes covers which requested scopes the response is actually
// resolved for.
//
// authCtx.Scopes is the raw OIDC scope list: "openid" is always there (OIDC
// Core requires it) and the shipped eudi_pid_basic template is selected by
// "pid profile". Requiring a VP token for those meant any request naming more
// than one scope failed - no wallet returns a credential for "profile".
func TestCredentialScopes(t *testing.T) {
	client, _ := CreateTestClientWithMock(t, nil)

	t.Run("ordinary OIDC scopes are not part of the presentation", func(t *testing.T) {
		got := client.credentialScopesLit(&cache.AuthorizationContext{
			Scopes: []string{"openid", "profile", "pid"},
			DCQLQuery: &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{
				{ID: "pid"},
			}},
		})
		assert.Equal(t, []string{"pid"}, got)
	})

	t.Run("request order is preserved", func(t *testing.T) {
		got := client.credentialScopesLit(&cache.AuthorizationContext{
			Scopes: []string{"ehic", "openid", "pid"},
			DCQLQuery: &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{
				{ID: "pid"}, {ID: "ehic"},
			}},
		})
		assert.Equal(t, []string{"ehic", "pid"}, got)
	})

	t.Run("an unmapped scope is kept, not dropped", func(t *testing.T) {
		// Covers a review finding. Dropping a scope no query obviously stands
		// for is the dangerous direction: it vanishes from the loop instead of
		// failing there, and if every scope vanished the presentation would be
		// cached having validated no VP token at all.
		got := client.credentialScopesLit(&cache.AuthorizationContext{
			Scopes: []string{"openid", "pid", "custom_claim"},
			DCQLQuery: &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{
				{ID: "pid"},
			}},
		})
		assert.Equal(t, []string{"pid", "custom_claim"}, got)
	})

	t.Run("no cached query falls back to every scope", func(t *testing.T) {
		// A session created before this existed, mid rolling deploy.
		got := client.credentialScopesLit(&cache.AuthorizationContext{
			Scopes: []string{"openid", "pid"},
		})
		assert.Equal(t, []string{"openid", "pid"}, got)
	})

	t.Run("a standard scope configured as a credential is kept", func(t *testing.T) {
		// Covers a review finding. PresentationBuilder deliberately lets a
		// standard scope select a template, and nothing stops
		// credential_metadata configuring "profile" - so excluding those by
		// name would skip validating a credential the request asked for.
		configured, _ := CreateTestClientWithMock(t, &model.Cfg{
			Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{
				"profile": sdJWTScope("urn:example:profile:1"),
			}},
			Verifier: &model.Verifier{},
		})
		got := configured.credentialScopesLit(&cache.AuthorizationContext{
			Scopes: []string{"openid", "profile"},
			DCQLQuery: &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{
				{ID: "profile"},
			}},
		})
		assert.Equal(t, []string{"profile"}, got)
	})

	t.Run("a standard scope named by a query is kept", func(t *testing.T) {
		got := client.credentialScopesLit(&cache.AuthorizationContext{
			Scopes: []string{"openid", "email"},
			DCQLQuery: &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{
				{ID: "email"},
			}},
		})
		assert.Equal(t, []string{"email"}, got)
	})

	t.Run("a query with only ordinary scopes leaves nothing to check", func(t *testing.T) {
		// eudi_pid_basic declares "pid profile", so "profile" alone selects it.
		// The guard in VerificationDirectPost turns this into an error rather
		// than a presentation accepted with nothing verified.
		got := client.credentialScopesLit(&cache.AuthorizationContext{
			Scopes: []string{"openid", "profile"},
			DCQLQuery: &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{
				{ID: "eudi_pid"},
			}},
		})
		assert.Empty(t, got)
	})
}

// TestScopeQueryIDsSharedQueryIsAmbiguous: uniqueness must hold both ways.
// queryIDForConstraint refuses a scope matching several queries, but two scopes
// can still land on one - aliases sharing a vct. Keeping both would process the
// single VP token twice, under each scope's validations.
func TestScopeQueryIDsSharedQueryIsAmbiguous(t *testing.T) {
	client := dcqlClientFor(t, map[string]*model.CredentialMetadata{
		"pid":       sdJWTScope("urn:eudi:pid:1"),
		"pid_alias": sdJWTScope("urn:eudi:pid:1"),
	}, nil)

	dcql := &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{
		{ID: "eudi_pid", Format: "dc+sd-jwt", Meta: openid4vp.MetaQuery{VCTValues: []string{"urn:eudi:pid:1"}}},
	}}

	assert.Empty(t, client.ScopeQueryIDs(t.Context(), dcql, []string{"pid", "pid_alias"}),
		"two scopes claiming one query must not both be mapped to it")

	// On its own each is unambiguous and still maps.
	assert.Equal(t, map[string]string{"pid": "eudi_pid"},
		client.ScopeQueryIDs(t.Context(), dcql, []string{"pid"}))
}

// TestScopeQueryIDsRebuildForLegacySession covers a review finding about
// sessions created before ScopeQueryIDs existed: DCQLQuery is persisted (that
// field predates this change) while the mapping is nil, so a template-built
// query's response would not resolve and a presentation the user had already
// completed would fail mid rolling deploy.
//
// The mapping is a pure function of the request, so it can simply be rebuilt.
func TestScopeQueryIDsRebuildForLegacySession(t *testing.T) {
	client := dcqlClientFor(t, map[string]*model.CredentialMetadata{
		"pid": sdJWTScope("urn:eudi:pid:1"),
	}, nil)

	dcql := &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{
		{ID: "eudi_pid", Format: "dc+sd-jwt", Meta: openid4vp.MetaQuery{VCTValues: []string{"urn:eudi:pid:1"}}},
	}}

	// What the cache holds for such a session: a query, no mapping.
	legacy := &cache.AuthorizationContext{
		Scopes:        []string{"openid", "pid"},
		ScopeQueryIDs: nil,
		DCQLQuery:     dcql,
	}

	rebuilt := client.ScopeQueryIDs(t.Context(), legacy.DCQLQuery, legacy.Scopes)
	require.Equal(t, map[string]string{"pid": "eudi_pid"}, rebuilt)

	legacy.ScopeQueryIDs = rebuilt
	tokens, err := client.vpTokensForScope(legacy.ScopeQueryIDs, false,
		openid4vp.VPResponse{VPToken: map[string][]string{"eudi_pid": {"token"}}}, "pid")
	require.NoError(t, err)
	assert.Equal(t, []string{"token"}, tokens)
}

// TestUncoveredScopesRejectsAmbiguousCoverage: the coverage check and the
// mapping must agree. ScopeQueryIDs refuses to map two aliases sharing a vct
// onto one query; a weaker coverage check reported both covered, so the request
// went out and direct-post failed afterwards.
func TestUncoveredScopesRejectsAmbiguousCoverage(t *testing.T) {
	client := dcqlClientFor(t, map[string]*model.CredentialMetadata{
		"pid":       sdJWTScope("urn:eudi:pid:1"),
		"pid_alias": sdJWTScope("urn:eudi:pid:1"),
	}, nil)

	dcql := &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{
		{ID: "eudi_pid", Format: "dc+sd-jwt", Meta: openid4vp.MetaQuery{VCTValues: []string{"urn:eudi:pid:1"}}},
	}}

	assert.ElementsMatch(t, []string{"pid", "pid_alias"},
		client.uncoveredScopes(t.Context(), dcql, []string{"pid", "pid_alias"}),
		"an ambiguous pairing must be caught before the request is sent")

	// One alias alone is unambiguous and covered.
	assert.Empty(t, client.uncoveredScopes(t.Context(), dcql, []string{"pid"}))
}

// TestScopeQueryIDsDirectKeyedCollision: a template query may be NAMED after a
// configured scope. A query "pid" looked like a direct hit needing no mapping
// while an alias mapped onto it, so the collision went unnoticed and the one VP
// token was processed twice. Identity pairings are tracked now, though not
// persisted.
func TestScopeQueryIDsDirectKeyedCollision(t *testing.T) {
	client := dcqlClientFor(t, map[string]*model.CredentialMetadata{
		"pid":       sdJWTScope("urn:eudi:pid:1"),
		"pid_alias": sdJWTScope("urn:eudi:pid:1"),
	}, nil)

	// The query is named for one of the scopes.
	dcql := &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{
		{ID: "pid", Format: "dc+sd-jwt", Meta: openid4vp.MetaQuery{VCTValues: []string{"urn:eudi:pid:1"}}},
	}}

	assert.Empty(t, client.ScopeQueryIDs(t.Context(), dcql, []string{"pid", "pid_alias"}))
	assert.ElementsMatch(t, []string{"pid", "pid_alias"},
		client.uncoveredScopes(t.Context(), dcql, []string{"pid", "pid_alias"}),
		"a contested query must leave both scopes unanswered, so the request is refused up front")
}

// TestUncoveredScopesIgnoresNameOnlyMatches: a query named after a scope but
// constrained for another credential must not count as covering it. Query ids
// are arbitrary, so a name match says nothing.
func TestUncoveredScopesIgnoresNameOnlyMatches(t *testing.T) {
	client := dcqlClientFor(t, map[string]*model.CredentialMetadata{
		"pid":  sdJWTScope("urn:eudi:pid:1"),
		"ehic": sdJWTScope("urn:eudi:ehic:1"),
	}, nil)

	// Named "pid", constrained for the EHIC type.
	dcql := &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{
		{ID: "pid", Format: "dc+sd-jwt", Meta: openid4vp.MetaQuery{VCTValues: []string{"urn:eudi:ehic:1"}}},
	}}

	assert.Equal(t, []string{"pid"}, client.uncoveredScopes(t.Context(), dcql, []string{"pid"}),
		"a name-only match must not count as coverage")

	// The scope the query is actually constrained for is answered by it.
	assert.Empty(t, client.uncoveredScopes(t.Context(), dcql, []string{"ehic"}))
	assert.Equal(t, map[string]string{"ehic": "pid"}, client.ScopeQueryIDs(t.Context(), dcql, []string{"ehic"}))
}

// TestQueryIDForScopeIn pins the resolution the ZK path and the collision
// guard share: the scope's query id when the two differ, the scope otherwise.
//
// The ZK mdoc path used to match credential queries by SCOPE, so a
// template-built request (query "eudi_pid", scope "pid") found none and
// verified against an empty zkMeta - failing for want of a zk_system_type
// that was in the query all along.
func TestQueryIDForScopeIn(t *testing.T) {
	authCtx := &cache.AuthorizationContext{
		Scopes:        []string{"pid", "ehic"},
		ScopeQueryIDs: map[string]string{"pid": "eudi_pid"},
	}

	assert.Equal(t, "eudi_pid", queryIDForScopeIn(authCtx.ScopeQueryIDs, "pid"),
		"a mapped scope resolves to its query id")
	assert.Equal(t, "ehic", queryIDForScopeIn(authCtx.ScopeQueryIDs, "ehic"),
		"an unmapped scope is its own key - only differing pairs are persisted")

	assert.Equal(t, "nosuch", queryIDForScopeIn(nil, "nosuch"),
		"a session with no mapping at all still resolves")
}

// credentialScopesLit is a test shim for the common case of an inline auth
// context: the request-local mapping is just the one the context carries.
func (c *Client) credentialScopesLit(authCtx *cache.AuthorizationContext) []string {
	return c.credentialScopes(authCtx, authCtx.ScopeQueryIDs)
}

// TestDefaultTokenAllowed pins when a plain-string vp_token can be attributed.
//
// Two counts look like they answer this and neither does. A template author
// writes the DCQL, so there can be more credential queries than the scopes
// mapped onto them; and credentialScopes deliberately keeps an unclaimed
// non-standard scope, so it fails in the validation loop rather than
// disappearing from it - which makes a length check read "openid profile
// custom_claim" as a single-credential request and cache the template's PID
// under custom_claim.
func TestDefaultTokenAllowed(t *testing.T) {
	client, _ := CreateTestClientWithMock(t, nil)

	onePID := &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{{ID: "pid"}}}
	twoCredentials := &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{{ID: "pid"}, {ID: "ehic"}}}

	tests := []struct {
		name             string
		authCtx          *cache.AuthorizationContext
		scopeQueryIDs    map[string]string
		credentialScopes []string
		want             bool
	}{
		{
			name:             "the ordinary single-credential request",
			authCtx:          &cache.AuthorizationContext{Scopes: []string{"openid", "pid"}, DCQLQuery: onePID},
			credentialScopes: []string{"pid"},
			want:             true,
		},
		{
			// The finding: profile selects the template, custom_claim is kept
			// because dropping it would skip its validation, and it is the
			// only scope left - but it is not the credential the query asks
			// for, so nothing can be attributed to it.
			name:             "an unclaimed scope left alone in the list",
			authCtx:          &cache.AuthorizationContext{Scopes: []string{"openid", "profile", "custom_claim"}, DCQLQuery: onePID},
			credentialScopes: []string{"custom_claim"},
			want:             false,
		},
		{
			name:             "one scope but the query asks for two credentials",
			authCtx:          &cache.AuthorizationContext{Scopes: []string{"openid", "pid"}, DCQLQuery: twoCredentials},
			credentialScopes: []string{"pid"},
			want:             false,
		},
		{
			name:             "an aliased scope resolved through its query id",
			authCtx:          &cache.AuthorizationContext{Scopes: []string{"pid_full"}, DCQLQuery: onePID},
			scopeQueryIDs:    map[string]string{"pid_full": "pid"},
			credentialScopes: []string{"pid_full"},
			want:             true,
		},
		{
			name:             "more than one credential scope",
			authCtx:          &cache.AuthorizationContext{Scopes: []string{"pid", "ehic"}, DCQLQuery: twoCredentials},
			credentialScopes: []string{"pid", "ehic"},
			want:             false,
		},
		{
			// No cached query: the scope count is all there is, as before.
			name:             "a session that predates the cached query",
			authCtx:          &cache.AuthorizationContext{Scopes: []string{"pid"}},
			credentialScopes: []string{"pid"},
			want:             true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, client.defaultTokenAllowed(tt.authCtx, tt.scopeQueryIDs, tt.credentialScopes))
		})
	}
}
