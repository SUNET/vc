package apiv1

import (
	"testing"

	"github.com/SUNET/vc/internal/wallet/credential"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// held is the shape selectCredentialQueries reads: query id -> what the
// wallet can answer it with. Only presence matters to the selection.
func held(ids ...string) map[string][]*credential.StoredCredential {
	m := map[string][]*credential.StoredCredential{}
	for _, id := range ids {
		m[id] = []*credential.StoredCredential{{RawCredential: "cred-for-" + id}}
	}
	return m
}

func query(id string) openid4vp.CredentialQuery {
	return openid4vp.CredentialQuery{ID: id, Format: "dc+sd-jwt"}
}

// With no credential_sets every query is required: that is the OpenID4VP
// 1.0 §6.2 default and the behaviour a request without sets asks for.
func TestSelectCredentialQueries_NoSetsRequiresEveryQuery(t *testing.T) {
	dcql := &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{query("pid"), query("mdl")}}

	selected, err := selectCredentialQueries(dcql, held("pid", "mdl"))
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{"pid": true, "mdl": true}, selected)

	_, err = selectCredentialQueries(dcql, held("pid"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"mdl"`)
}

// The options of a credential set are ALTERNATIVES. Our own issuer builds
// exactly this - buildIssuanceAuthDCQL puts each authentication scope in
// its own option - so a deployment offering two ways to authenticate
// produced a request this wallet refused unless the Holder carried both.
func TestSelectCredentialQueries_OneSatisfiedOptionSatisfiesTheSet(t *testing.T) {
	dcql := &openid4vp.DCQL{
		Credentials: []openid4vp.CredentialQuery{query("pid"), query("mdl")},
		CredentialSets: []openid4vp.CredentialSetQuery{{
			Options: [][]string{{"pid"}, {"mdl"}},
		}},
	}

	selected, err := selectCredentialQueries(dcql, held("mdl"))
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{"mdl": true}, selected,
		"the one alternative this wallet holds is the one it answers")

	// The first satisfiable option wins, which is the Verifier's own
	// stated order of preference.
	selected, err = selectCredentialQueries(dcql, held("pid", "mdl"))
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{"pid": true}, selected)
}

// An option is all-or-nothing: half an alternative satisfies nothing.
func TestSelectCredentialQueries_PartialOptionDoesNotCount(t *testing.T) {
	dcql := &openid4vp.DCQL{
		Credentials: []openid4vp.CredentialQuery{query("pid"), query("photo"), query("mdl")},
		CredentialSets: []openid4vp.CredentialSetQuery{{
			Options: [][]string{{"pid", "photo"}, {"mdl"}},
		}},
	}

	selected, err := selectCredentialQueries(dcql, held("pid", "mdl"))
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{"mdl": true}, selected)
}

// A required set nothing satisfies is reported; an optional one is
// skipped, which is what optional means.
func TestSelectCredentialQueries_RequiredAndOptionalSets(t *testing.T) {
	required := &openid4vp.DCQL{
		Credentials:    []openid4vp.CredentialQuery{query("pid")},
		CredentialSets: []openid4vp.CredentialSetQuery{{Options: [][]string{{"pid"}}}},
	}
	_, err := selectCredentialQueries(required, held())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required credential set")

	optional := &openid4vp.DCQL{
		Credentials: []openid4vp.CredentialQuery{query("pid"), query("bonus")},
		CredentialSets: []openid4vp.CredentialSetQuery{
			{Options: [][]string{{"pid"}}},
			{Options: [][]string{{"bonus"}}, Required: new(false)},
		},
	}
	selected, err := selectCredentialQueries(optional, held("pid"))
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{"pid": true}, selected)
}

// A query no set references stays required: nothing else would ever ask
// for it, so treating it as optional would silently drop it.
func TestSelectCredentialQueries_UnreferencedQueryStaysRequired(t *testing.T) {
	dcql := &openid4vp.DCQL{
		Credentials:    []openid4vp.CredentialQuery{query("pid"), query("always")},
		CredentialSets: []openid4vp.CredentialSetQuery{{Options: [][]string{{"pid"}}}},
	}

	selected, err := selectCredentialQueries(dcql, held("pid", "always"))
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{"pid": true, "always": true}, selected)

	_, err = selectCredentialQueries(dcql, held("pid"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"always"`)
}

// Answering nothing is not an answer: a response with an empty vp_token
// tells the Issuer the wallet complied when it did not.
func TestSelectCredentialQueries_AllOptionalAndNoneSatisfiedIsAnError(t *testing.T) {
	dcql := &openid4vp.DCQL{
		Credentials: []openid4vp.CredentialQuery{query("pid")},
		CredentialSets: []openid4vp.CredentialSetQuery{
			{Options: [][]string{{"pid"}}, Required: new(false)},
		},
	}

	_, err := selectCredentialQueries(dcql, held())
	require.Error(t, err)
}
