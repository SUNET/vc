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
// wallet's response (SUNET/vc#682).
//
// A wallet keys its vp_token by DCQL credential query id, but every shipped
// presentation template names its query something other than the OIDC scope the
// request is made with - eudi_pid for pid, eudi_ehic for ehic. The verifier
// resolves tokens per scope, so without a mapping it reads a key the wallet
// never sent and the whole presentation fails after the user completed it.
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

	got := client.ScopeQueryIDs(dcql, []string{"pid", "ehic", "pid_mdoc", "diploma_ldp", "profile"})

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

	assert.Empty(t, client.ScopeQueryIDs(dcql, []string{"pid"}))
}

// TestUncoveredScopesRejectsUnaskedCredential covers the request side of the
// same missing relationship.
//
// createDCQLQuery selects ONE template by scope. If the request names other
// configured credentials the template does not cover, the query goes out
// covering a subset while authCtx.Scopes keeps the full list - and
// VerificationDirectPost then waits for a VP token for a credential the wallet
// was never asked about, failing only after a completed presentation.
func TestUncoveredScopesRejectsUnaskedCredential(t *testing.T) {
	client := dcqlClientFor(t, map[string]*model.CredentialMetadata{
		"pid":  sdJWTScope("urn:eudi:pid:1"),
		"ehic": sdJWTScope("urn:eudi:ehic:1"),
		// Not expressible: a template may cover it with type_values and there
		// is no way to tell yet, so it must NOT be reported (SUNET/vc#680).
		"diploma_ldp": w3cScope("urn:eudi:diploma:1"),
	}, nil)

	pidOnly := &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{
		{ID: "eudi_pid", Format: "dc+sd-jwt", Meta: openid4vp.MetaQuery{VCTValues: []string{"urn:eudi:pid:1"}}},
	}}

	assert.Equal(t, []string{"ehic"},
		client.uncoveredScopes(pidOnly, []string{"pid", "ehic", "profile"}),
		"a configured, expressible scope the query never mentions is unfulfillable")

	assert.Empty(t, client.uncoveredScopes(pidOnly, []string{"pid", "diploma_ldp"}),
		"a scope with no expressible constraint must not be reported: a template may cover it")

	assert.Empty(t, client.uncoveredScopes(pidOnly, []string{"pid", "profile", "openid"}),
		"unconfigured scopes are ordinary OIDC scopes")
}

// TestVPTokensForScope covers the response side: how a wallet's vp_token is
// matched back to the scope that asked for it.
//
// The template case is the reported bug (SUNET/vc#682). The request is made
// with scope "pid", the shipped template names its query "eudi_pid", and the
// wallet answers under the query id - so the scope-keyed lookup finds nothing
// and the presentation fails after the user has completed it.
func TestVPTokensForScope(t *testing.T) {
	client, _ := CreateTestClientWithMock(t, nil)

	tests := []struct {
		name      string
		authCtx   *cache.AuthorizationContext
		vpToken   map[string][]string
		scope     string
		want      []string
		wantError string
	}{
		{
			name:    "keyed by the scope, as a config-built query is",
			authCtx: &cache.AuthorizationContext{Scopes: []string{"pid", "ehic"}},
			vpToken: map[string][]string{"pid": {"token-pid"}},
			scope:   "pid",
			want:    []string{"token-pid"},
		},
		{
			// The bug: without the mapping this is "VP token not found".
			name: "keyed by the template's query id",
			authCtx: &cache.AuthorizationContext{
				Scopes:        []string{"pid", "ehic"},
				ScopeQueryIDs: map[string]string{"pid": "eudi_pid"},
			},
			vpToken: map[string][]string{"eudi_pid": {"token-pid"}},
			scope:   "pid",
			want:    []string{"token-pid"},
		},
		{
			// The scope's own key wins, so a wallet that answers correctly is
			// never second-guessed by the mapping.
			name: "scope key preferred over the mapped query id",
			authCtx: &cache.AuthorizationContext{
				Scopes:        []string{"pid", "ehic"},
				ScopeQueryIDs: map[string]string{"pid": "eudi_pid"},
			},
			vpToken: map[string][]string{"pid": {"right"}, "eudi_pid": {"wrong"}},
			scope:   "pid",
			want:    []string{"right"},
		},
		{
			name:    "plain-string vp_token with a single requested scope",
			authCtx: &cache.AuthorizationContext{Scopes: []string{"pid"}},
			vpToken: map[string][]string{"_default": {"token-pid"}},
			scope:   "pid",
			want:    []string{"token-pid"},
		},
		{
			// _default with several scopes would reuse one credential for each,
			// carrying whichever validations belong to the others.
			name:      "plain-string vp_token refused for a multi-scope request",
			authCtx:   &cache.AuthorizationContext{Scopes: []string{"pid", "ehic"}},
			vpToken:   map[string][]string{"_default": {"token"}},
			scope:     "pid",
			wantError: "_default fallback is only allowed when a single scope is requested",
		},
		{
			name:      "nothing usable",
			authCtx:   &cache.AuthorizationContext{Scopes: []string{"pid"}},
			vpToken:   map[string][]string{"something_else": {"token"}},
			scope:     "pid",
			wantError: "VP token not found for scope: pid",
		},
		{
			// A mapping that points at a key the wallet did not send must not
			// swallow the error.
			name: "mapped query id absent from the response",
			authCtx: &cache.AuthorizationContext{
				Scopes:        []string{"pid", "ehic"},
				ScopeQueryIDs: map[string]string{"pid": "eudi_pid"},
			},
			vpToken:   map[string][]string{"ehic": {"token-ehic"}},
			scope:     "pid",
			wantError: "_default fallback is only allowed when a single scope is requested",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := client.vpTokensForScope(tt.authCtx, openid4vp.VPResponse{VPToken: tt.vpToken}, tt.scope)
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

// TestScopeQueryIDsAliasTemplateScope covers a review finding, and the shape
// half the shipped templates actually have.
//
// eudi_pid_full is selected by the OIDC scope "pid_full" while the credential
// is configured as "pid"; the eduID full and age templates do the same. Such a
// scope is not a credential_metadata key, so it has no constraint of its own -
// but it is what lands in authCtx.Scopes and what the response is looked up by.
// Skipping unconfigured scopes left precisely these templates as broken as
// before the fix.
func TestScopeQueryIDsAliasTemplateScope(t *testing.T) {
	client := dcqlClientFor(t, map[string]*model.CredentialMetadata{
		"pid": sdJWTScope("urn:eudi:pid:1"),
	}, nil)

	// What eudi_pid_full produces: one query, named for the template.
	dcql := &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{
		{ID: "eudi_pid", Format: "dc+sd-jwt", Meta: openid4vp.MetaQuery{VCTValues: []string{"urn:eudi:pid:1"}}},
	}}

	assert.Equal(t, map[string]string{"pid_full": "eudi_pid"},
		client.ScopeQueryIDs(dcql, []string{"pid_full"}),
		"an alias scope must still resolve to the query the wallet answers under")

	// And the response then resolves, which is the whole point.
	tokens, err := client.vpTokensForScope(
		&cache.AuthorizationContext{
			Scopes:        []string{"pid_full"},
			ScopeQueryIDs: client.ScopeQueryIDs(dcql, []string{"pid_full"}),
		},
		openid4vp.VPResponse{VPToken: map[string][]string{"eudi_pid": {"token-pid"}}},
		"pid_full",
	)
	require.NoError(t, err)
	assert.Equal(t, []string{"token-pid"}, tokens)
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

	got := client.ScopeQueryIDs(dcql, []string{"combined_full"})
	assert.Empty(t, got, "an unconfigured scope with several candidate queries must not be guessed")

	// Configured scopes in the same request still pair exactly, by constraint.
	assert.Equal(t, map[string]string{"pid": "eudi_pid", "ehic": "eudi_ehic"},
		client.ScopeQueryIDs(dcql, []string{"pid", "ehic"}))
}
