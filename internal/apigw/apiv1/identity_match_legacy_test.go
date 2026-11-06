package apiv1

import (
	"encoding/hex"
	"maps"
	"slices"
	"testing"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/claimpath"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// storedNames returns a rule as a session of the earlier release stores
// it: a BSON list of {path: dotted claim name, test: {equals}} entries.
func storedNames(t *testing.T, byName map[string]string) *openid4vci.StoredIdentityMatch {
	t.Helper()
	entries := bson.A{}
	for _, name := range slices.Sorted(maps.Keys(byName)) {
		entries = append(entries, bson.M{"path": name, "test": bson.M{"equals": byName[name]}})
	}
	data, err := bson.Marshal(bson.M{"claims": entries})
	require.NoError(t, err)
	var stored openid4vci.StoredIdentityMatch
	require.NoError(t, bson.Unmarshal(data, &stored))
	return &stored
}

// legacyPresentation is a verified presentation of format.
type legacyPresentation struct {
	format    string
	presented map[string]any
}

// legacyMatchPresentations are the presentations legacyMatchVectors were
// matched against.
func legacyMatchPresentations(t *testing.T) map[string]legacyPresentation {
	t.Helper()
	sd := func(m map[string]any) legacyPresentation { return legacyPresentation{openid4vp.FormatSDJWTVC, m} }
	md := func(docType string, ns map[string]map[string]any) legacyPresentation {
		return legacyPresentation{openid4vp.FormatMsoMdoc, mdocPresented(t, docType, ns)}
	}
	return map[string]legacyPresentation{
		"sd_anna":         sd(map[string]any{"given_name": "Anna", "family_name": "Andersson"}),
		"sd_bo_bergstrom": sd(map[string]any{"given_name": "Bo", "family_name": "Bergstrom"}),
		"sd_bo_andersson": sd(map[string]any{"given_name": "Bo", "family_name": "Andersson"}),
		"sd_anna_only":    sd(map[string]any{"given_name": "Anna"}),
		"sd_anna_extra":   sd(map[string]any{"given_name": "Anna", "family_name": "Andersson", "birth_date": "1970-01-01"}),
		"sd_iso_nested":   sd(map[string]any{"org": map[string]any{"iso": map[string]any{"18013": map[string]any{"5": map[string]any{"1": map[string]any{"family_name": "Andersson"}}}}}}),
		"sd_iso_flat":     sd(map[string]any{"org.iso.18013.5.1.family_name": "Andersson"}),
		"sd_roles":        sd(map[string]any{"roles": []any{"employee", "legal_representative"}}),
		"sd_roles_other":  sd(map[string]any{"roles": []any{"employee"}}),
		"sd_address":      sd(map[string]any{"address": map[string]any{"country": "SE"}}),
		"mdl_anna": md("org.iso.18013.5.1.mDL", map[string]map[string]any{
			"org.iso.18013.5.1": {"given_name": "Anna", "family_name": "Andersson", "birth_date": mdoc.FullDate("1980-01-01")},
		}),
		"pid_mdoc_anna": md("eu.europa.ec.eudi.pid.1", map[string]map[string]any{
			"eu.europa.ec.eudi.pid.1": {"given_name": "Anna", "family_name": "Andersson", "birth_date": mdoc.FullDate("1980-01-01")},
		}),
		"mdl_anna_later": md("org.iso.18013.5.1.mDL", map[string]map[string]any{
			"org.iso.18013.5.1": {"given_name": "Anna", "family_name": "Andersson", "birth_date": mdoc.FullDate("1980-01-02")},
		}),
	}
}

// legacyMatchVectors are identity match rules in the earlier release's
// form, the session that release's code stores for each (a BSON
// cache.AuthorizationContext), and the presentations its
// matchPresentedIdentity accepts. Generated from sunet/main at ff1df9572.
var legacyMatchVectors = map[string]struct {
	claims  map[string]string
	session string
	matches []string
}{
	"birth": {
		claims:  map[string]string{"birth_date": "1980-01-01"},
		session: "a30000000273657373696f6e5f696400090000006d352d62697274680012657870697265735f617400000000000000000002636c69656e745f6964000100000000036964656e746974795f6d61746368005100000004636c61696d7300440000000330003c0000000270617468000b00000062697274685f64617465000374657374001c00000002657175616c73000b000000313938302d30312d3031000000000000",
		matches: []string{"mdl_anna"},
	},
	"nested": {
		claims:  map[string]string{"address.country": "SE"},
		session: "a10000000273657373696f6e5f6964000a0000006d352d6e65737465640012657870697265735f617400000000000000000002636c69656e745f6964000100000000036964656e746974795f6d61746368004e00000004636c61696d7300410000000330003900000002706174680010000000616464726573732e636f756e747279000374657374001400000002657175616c7300030000005345000000000000",
		matches: []string{"sd_address"},
	},
	"pid_ns": {
		claims:  map[string]string{"eu.europa.ec.eudi.pid.1.family_name": "Andersson"},
		session: "bc0000000273657373696f6e5f6964000a0000006d352d7069645f6e730012657870697265735f617400000000000000000002636c69656e745f6964000100000000036964656e746974795f6d61746368006900000004636c61696d73005c000000033000540000000270617468002400000065752e6575726f70612e65632e657564692e7069642e312e66616d696c795f6e616d65000374657374001b00000002657175616c73000a000000416e64657273736f6e000000000000",
		matches: []string{"pid_mdoc_anna"},
	},
	"portal": {
		claims:  map[string]string{"given_name": "Anna", "family_name": "Andersson"},
		session: "dd0000000273657373696f6e5f6964000a0000006d352d706f7274616c0012657870697265735f617400000000000000000002636c69656e745f6964000100000000036964656e746974795f6d61746368008a00000004636c61696d73007d0000000330003c0000000270617468000c00000066616d696c795f6e616d65000374657374001b00000002657175616c73000a000000416e64657273736f6e000000033100360000000270617468000b000000676976656e5f6e616d65000374657374001600000002657175616c730005000000416e6e61000000000000",
		matches: []string{"mdl_anna", "mdl_anna_later", "sd_anna", "sd_anna_extra"},
	},
	"qualified": {
		claims:  map[string]string{"org.iso.18013.5.1.family_name": "Andersson"},
		session: "b90000000273657373696f6e5f6964000d0000006d352d7175616c69666965640012657870697265735f617400000000000000000002636c69656e745f6964000100000000036964656e746974795f6d61746368006300000004636c61696d7300560000000330004e0000000270617468001e0000006f72672e69736f2e31383031332e352e312e66616d696c795f6e616d65000374657374001b00000002657175616c73000a000000416e64657273736f6e000000000000",
		matches: []string{"mdl_anna", "mdl_anna_later", "sd_iso_nested"},
	},
	"roles": {
		claims:  map[string]string{"roles": "legal_representative"},
		session: "a80000000273657373696f6e5f696400090000006d352d726f6c65730012657870697265735f617400000000000000000002636c69656e745f6964000100000000036964656e746974795f6d61746368005600000004636c61696d7300490000000330004100000002706174680006000000726f6c6573000374657374002600000002657175616c7300150000006c6567616c5f726570726573656e746174697665000000000000",
		matches: []string{"sd_roles"},
	},
}

// matchingPresentations returns the presentations rule matches.
func matchingPresentations(t *testing.T, client *Client, rule *openid4vci.StoredIdentityMatch) []string {
	t.Helper()
	presentations := legacyMatchPresentations(t)
	var matches []string
	for _, name := range slices.Sorted(maps.Keys(presentations)) {
		p := presentations[name]
		err := client.matchPresentedIdentity(p.format, p.presented, rule)
		if err == nil {
			matches = append(matches, name)
			continue
		}
		require.ErrorIs(t, err, errIdentityMismatch, name)
	}
	return matches
}

// A session the earlier release wrote, read during a rolling deploy,
// matches the presentations that release matched.
func TestIdentityMatch_ReadsSessionsOfTheEarlierRelease(t *testing.T) {
	client := newChallengeClient(t)
	for name, vector := range legacyMatchVectors {
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(vector.session)
			require.NoError(t, err)
			var authCtx cache.AuthorizationContext
			require.NoError(t, bson.Unmarshal(data, &authCtx))
			require.Equal(t, vector.matches, matchingPresentations(t, client, authCtx.IdentityMatch))
		})
	}
}

// A request in the earlier release's form matches the presentations that
// release matched, on a scope whose auth scopes accept an SD-JWT VC and
// two mdocs. Such a scope reads a name without a dot as given_name in an
// SD-JWT VC and as an element of org.iso.18013.5.1 in an mdoc.
func TestPrepareLegacyIssuance_MatchesLikeTheEarlierRelease(t *testing.T) {
	client := newChallengeClient(t)
	client.cfg.Common.CredentialMetadata["mdl_auth"] = &model.CredentialMetadata{Format: openid4vp.FormatMsoMdoc, Doctype: "org.iso.18013.5.1.mDL"}
	client.cfg.Common.CredentialMetadata["pid_mdoc_auth"] = &model.CredentialMetadata{Format: openid4vp.FormatMsoMdoc, Doctype: "eu.europa.ec.eudi.pid.1"}
	scopes := client.cfg.APIGW.DataSources.Datastore.Scopes[challengeScope]
	scopes.AuthScopes = map[string]model.AuthScopeEntry{
		challengeAuthScope: {AuthClaims: []claimpath.Pointer{
			claimpath.Keys("given_name"), claimpath.Keys("family_name"), claimpath.Keys("birth_date"),
			claimpath.Keys("roles"), claimpath.Keys("address", "country"),
		}},
		"mdl_auth": {AuthClaims: []claimpath.Pointer{
			claimpath.Keys("org.iso.18013.5.1", "given_name"), claimpath.Keys("org.iso.18013.5.1", "family_name"),
		}},
		"pid_mdoc_auth": {AuthClaims: []claimpath.Pointer{claimpath.Keys("eu.europa.ec.eudi.pid.1", "family_name")}},
	}
	client.cfg.APIGW.DataSources.Datastore.Scopes[challengeScope] = scopes

	for name, vector := range legacyMatchVectors {
		t.Run(name, func(t *testing.T) {
			claims := make(map[string]openid4vci.ClaimTest, len(vector.claims))
			for claim, value := range vector.claims {
				claims[claim] = openid4vci.ClaimTest{Equals: value}
			}
			reply, err := client.PrepareLegacyIssuance(t.Context(), &LegacyPrepareIssuanceRequest{
				Scope:         challengeScope,
				IdentityMatch: &openid4vci.LegacyIdentityMatch{Claims: claims},
			})
			require.NoError(t, err)

			stored, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{IssuerState: reply.IssuerState})
			require.NoError(t, err)
			data, err := bson.Marshal(stored)
			require.NoError(t, err)
			var authCtx cache.AuthorizationContext
			require.NoError(t, bson.Unmarshal(data, &authCtx))
			require.Equal(t, vector.matches, matchingPresentations(t, client, authCtx.IdentityMatch))
		})
	}
}
