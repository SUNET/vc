package openid4vp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func claimPath(segments ...string) []*string {
	out := make([]*string, len(segments))
	for i := range segments {
		s := segments[i]
		out[i] = &s
	}
	return out
}

func TestNeverDisclose_Blocks(t *testing.T) {
	n := NewNeverDisclose(DefaultNeverDisclose)

	for name, tc := range map[string]struct {
		path    []*string
		blocked bool
	}{
		"a bare claim name":                      {claimPath("ssc"), true},
		"the other default":                      {claimPath("psc"), true},
		"namespace-qualified, as mdoc writes it": {claimPath("eu.europa.ec.eudi.nym_auth.1", "ssc"), true},
		"nested under something else":            {claimPath("credentialSubject", "ssc"), true},
		"an ordinary claim":                      {claimPath("birth_date"), false},
		"a name that merely contains it":         {claimPath("sscx"), false},
		"a name it is a suffix of":               {claimPath("my_ssc"), false},
		"empty":                                  {nil, false},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.blocked, n.Blocks(tc.path))
		})
	}

	t.Run("a wildcard segment names nothing", func(t *testing.T) {
		// DCQL uses a null path segment for "every element of this
		// array". Treating it as a match would block unrelated queries.
		assert.False(t, n.Blocks([]*string{nil}))
	})
}

// An empty claims list in DCQL means "any claims", so a credential query
// whose every claim was blocked must be dropped rather than emptied -
// emptying it would turn a request for one forbidden claim into a request
// for all of them.
func TestNeverDisclose_FilterDCQL_DropsAQueryItWouldOtherwiseWiden(t *testing.T) {
	n := NewNeverDisclose(DefaultNeverDisclose)

	query := &DCQL{
		Credentials: []CredentialQuery{
			{ID: "only_blocked", Claims: []ClaimQuery{{Path: claimPath("ssc")}}},
			{ID: "mixed", Claims: []ClaimQuery{
				{Path: claimPath("birth_date")},
				{Path: claimPath("eu.europa.ec.eudi.nym_auth.1", "ssc")},
			}},
			{ID: "untouched", Claims: []ClaimQuery{{Path: claimPath("given_name")}}},
		},
		CredentialSets: []CredentialSetQuery{
			{Options: [][]string{{"only_blocked"}, {"mixed"}}},
			{Options: [][]string{{"only_blocked"}}},
		},
	}

	n.FilterDCQL(query)

	require.Len(t, query.Credentials, 2, "the all-blocked query must be dropped, not emptied")
	assert.Equal(t, "mixed", query.Credentials[0].ID)
	require.Len(t, query.Credentials[0].Claims, 1)
	assert.Equal(t, "birth_date", *query.Credentials[0].Claims[0].Path[0])
	assert.Equal(t, "untouched", query.Credentials[1].ID)

	// An option naming a dropped query cannot be satisfied, and a set
	// left with no options at all is not a choice.
	require.Len(t, query.CredentialSets, 1)
	assert.Equal(t, [][]string{{"mixed"}}, query.CredentialSets[0].Options)
}

// A credential query that asks for no claims already means "any claims".
// It is left alone: narrowing it here would change what an operator
// deliberately requested, and it cannot name a blocked claim anyway.
func TestNeverDisclose_FilterDCQL_LeavesAnUnconstrainedQuery(t *testing.T) {
	query := &DCQL{Credentials: []CredentialQuery{{ID: "anything"}}}
	NewNeverDisclose(DefaultNeverDisclose).FilterDCQL(query)
	assert.Len(t, query.Credentials, 1)
}

func TestNeverDisclose_FilterClaims(t *testing.T) {
	n := NewNeverDisclose(DefaultNeverDisclose)

	claims := map[string]any{
		"birth_date": "1970-01-01",
		"ssc":        "d424c706",
		"psc":        "deadbeef",
		// mdoc keeps a namespace-qualified claim as one dotted key.
		"eu.europa.ec.eudi.nym_auth.1.ssc": "d424c706",
		"nested": map[string]any{
			"given_name": "Anna",
			"ssc":        "d424c706",
		},
	}

	filtered := n.FilterClaims(claims)

	assert.Equal(t, "1970-01-01", filtered["birth_date"])
	assert.NotContains(t, filtered, "ssc")
	assert.NotContains(t, filtered, "psc")
	assert.NotContains(t, filtered, "eu.europa.ec.eudi.nym_auth.1.ssc")

	nested, ok := filtered["nested"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "Anna", nested["given_name"])
	assert.NotContains(t, nested, "ssc", "a blocked claim is blocked at any depth")

	// The caller's map is not emptied under them.
	assert.Contains(t, claims, "ssc", "FilterClaims must not mutate its input")
}

func TestNeverDisclose_FilterNamed(t *testing.T) {
	n := NewNeverDisclose(DefaultNeverDisclose)

	filtered := FilterNamed(n, map[string]int{
		"birth_date":                       1,
		"ssc":                              2,
		"eu.europa.ec.eudi.nym_auth.1.psc": 3,
	})

	assert.Equal(t, map[string]int{"birth_date": 1}, filtered)
}

// Clearing the list is allowed and means what it says. A deployment that
// does it has made a decision; a deployment that never configured one
// gets the default, which is handled by Cfg.NeverDisclose.
func TestNeverDisclose_EmptyListFiltersNothing(t *testing.T) {
	n := NewNeverDisclose(nil)
	require.True(t, n.Empty())

	claims := map[string]any{"ssc": "x"}
	assert.Equal(t, claims, n.FilterClaims(claims))

	query := &DCQL{Credentials: []CredentialQuery{
		{ID: "c", Claims: []ClaimQuery{{Path: claimPath("ssc")}}},
	}}
	n.FilterDCQL(query)
	assert.Len(t, query.Credentials[0].Claims, 1)
}
