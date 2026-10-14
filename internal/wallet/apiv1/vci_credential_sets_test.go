package apiv1

import (
	"encoding/json"
	"testing"

	"github.com/SUNET/vc/internal/wallet/credential"
	"github.com/SUNET/vc/pkg/openid4vci"
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

// An Issuer may advertise several Authorization Servers, and an
// issuer-initiated offer's grant says which one its issuer_state belongs
// to. Keeping the handle while dropping the server sends a one-shot
// handle to an endpoint that has never heard of it.
func TestAuthorizationServerFor(t *testing.T) {
	metadata := &openid4vci.CredentialIssuerMetadataParameters{
		AuthorizationServers: []string{"https://as-one.example", "https://as-two.example"},
	}

	t.Run("the grant decides when it names a server", func(t *testing.T) {
		flow := &vciFlow{}
		flow.adoptOfferGrants(map[string]any{
			"authorization_code": map[string]any{
				"issuer_state":         "handle",
				"authorization_server": "https://as-two.example",
			},
		})

		got, err := flow.authorizationServerFor(metadata, "https://issuer.example")
		require.NoError(t, err)
		assert.Equal(t, "https://as-two.example", got,
			"the handle belongs to the server the grant named, not to the first advertised one")
	})

	t.Run("the first advertised server otherwise", func(t *testing.T) {
		got, err := (&vciFlow{}).authorizationServerFor(metadata, "https://issuer.example")
		require.NoError(t, err)
		assert.Equal(t, "https://as-one.example", got)
	})

	t.Run("the issuer itself when it advertises none", func(t *testing.T) {
		got, err := (&vciFlow{}).authorizationServerFor(
			&openid4vci.CredentialIssuerMetadataParameters{}, "https://issuer.example")
		require.NoError(t, err)
		assert.Equal(t, "https://issuer.example", got)
	})

	// The offer arrives as a QR code, so it is the least trustworthy input
	// in this flow. Following it to a server the Issuer never vouched for
	// is how a wallet is talked into sending a handle, and then a DPoP
	// proof, somewhere of an attacker's choosing.
	t.Run("a server the issuer does not advertise is refused", func(t *testing.T) {
		flow := &vciFlow{}
		flow.adoptOfferGrants(map[string]any{
			"authorization_code": map[string]any{
				"issuer_state":         "handle",
				"authorization_server": "https://attacker.example",
			},
		})

		_, err := flow.authorizationServerFor(metadata, "https://issuer.example")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "attacker.example")
	})

	// An offer may carry both grants, describing two ways to be
	// authorized, and they may live on different servers. The run redeems
	// the pre-authorized code in preference to anything else, so taking
	// the authorization-code grant's server would send that code to a
	// token endpoint it is not a secret for.
	t.Run("both grants, and the one being redeemed decides", func(t *testing.T) {
		flow := &vciFlow{}
		flow.adoptOfferGrants(map[string]any{
			"authorization_code": map[string]any{
				"issuer_state":         "handle",
				"authorization_server": "https://as-one.example",
			},
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]any{
				"pre-authorized_code":  "code",
				"authorization_server": "https://as-two.example",
			},
		})

		got, err := flow.authorizationServerFor(metadata, "https://issuer.example")
		require.NoError(t, err)
		assert.Equal(t, "https://as-two.example", got,
			"the pre-authorized code is what gets redeemed, so its grant's server is the one to talk to")
	})

	// A pre-authorized-only offer names its server on the only grant it
	// has, which was being ignored entirely.
	t.Run("a pre-authorized-only offer names its own server", func(t *testing.T) {
		flow := &vciFlow{}
		flow.adoptOfferGrants(map[string]any{
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]any{
				"pre-authorized_code":  "code",
				"authorization_server": "https://as-two.example",
			},
		})

		got, err := flow.authorizationServerFor(metadata, "https://issuer.example")
		require.NoError(t, err)
		assert.Equal(t, "https://as-two.example", got)
	})

	// And the validation holds on that grant too.
	t.Run("a pre-authorized grant naming an unadvertised server is refused", func(t *testing.T) {
		flow := &vciFlow{}
		flow.adoptOfferGrants(map[string]any{
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]any{
				"pre-authorized_code":  "code",
				"authorization_server": "https://attacker.example",
			},
		})

		_, err := flow.authorizationServerFor(metadata, "https://issuer.example")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "attacker.example")
	})
}

// The member is "authorization_server" in both grants - OpenID4VCI 1.0
// §4.1.1 - and the authorization_code one was tagged "authorization",
// so it was written and read under a name no other implementation uses.
func TestGrantAuthorizationCodeNamesTheServerTheSpecWay(t *testing.T) {
	encoded, err := json.Marshal(openid4vci.GrantAuthorizationCode{
		IssuerState:         "handle",
		AuthorizationServer: "https://as-two.example",
	})
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	assert.Equal(t, "https://as-two.example", decoded["authorization_server"])
	assert.NotContains(t, decoded, "authorization")
}
