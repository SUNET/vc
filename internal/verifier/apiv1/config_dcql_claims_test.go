package apiv1

import (
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// claimsScope is a dc+sd-jwt scope that asks for the given claim paths. A nil
// element is a claims path pointer's null, which selects every element of an
// array (OpenID4VP 1.0 6.4.1), so it has to survive into the query unchanged.
func claimsScope(vct string, paths ...[]*string) *model.CredentialMetadata {
	meta := &model.CredentialMetadata{
		Format: "dc+sd-jwt",
		VCTM:   &sdjwtvc.VCTM{VCT: vct},
	}
	for _, p := range paths {
		meta.DCQLClaims = append(meta.DCQLClaims, openid4vp.ClaimQuery{Path: p})
	}
	return meta
}

func claimPath(parts ...string) []*string {
	out := make([]*string, 0, len(parts))
	for _, part := range parts {
		out = append(out, &part)
	}
	return out
}

// elementPath is a path whose last element is null: ["nationalities", null].
func elementPath(parent string) []*string {
	return append(claimPath(parent), nil)
}

func claimsClient(t *testing.T, credMeta map[string]*model.CredentialMetadata) *Client {
	t.Helper()
	client, _ := CreateTestClientWithMock(t, &model.Cfg{
		Common: &model.Common{CredentialMetadata: credMeta},
	})
	return client
}

func TestConfiguredClaimsReachTheQuery(t *testing.T) {
	client := claimsClient(t, map[string]*model.CredentialMetadata{
		"pid": claimsScope("urn:eudi:pid:1", claimPath("given_name"), claimPath("address", "locality"), elementPath("nationalities")),
	})

	dcql, err := client.buildDCQLQueryFromConfig([]string{"pid"})
	require.NoError(t, err)
	require.Len(t, dcql.Credentials, 1)

	assert.Equal(t,
		[]openid4vp.ClaimQuery{
			{Path: claimPath("given_name")},
			{Path: claimPath("address", "locality")},
			{Path: elementPath("nationalities")},
		},
		dcql.Credentials[0].Claims,
		"a scope's configured claims are what the wallet is asked for")
}

func TestClaimsStayWithTheScopeThatConfiguredThem(t *testing.T) {
	client := claimsClient(t, map[string]*model.CredentialMetadata{
		"pid":  claimsScope("urn:eudi:pid:1", claimPath("given_name")),
		"ehic": claimsScope("urn:eudi:ehic:1"),
	})

	dcql, err := client.buildDCQLQueryFromConfig([]string{"pid", "ehic"})
	require.NoError(t, err)
	require.Len(t, dcql.Credentials, 2)

	byID := map[string][]openid4vp.ClaimQuery{}
	for _, cred := range dcql.Credentials {
		byID[cred.ID] = cred.Claims
	}
	assert.Equal(t, []openid4vp.ClaimQuery{{Path: claimPath("given_name")}}, byID["pid"])
	assert.Nil(t, byID["ehic"],
		"a scope that configures no claims keeps the member absent, as before")
}

// A query is built per request from one shared config map. Handing out the
// config's own slice let augmentDCQLFromVCTM's in-place rewrite edit the
// configuration, so the second request would be built from the first one's
// leftovers.
func TestBuildingAQueryDoesNotEditTheConfig(t *testing.T) {
	credMeta := map[string]*model.CredentialMetadata{
		"pid": claimsScope("urn:eudi:pid:1", claimPath("given_name")),
	}
	client := claimsClient(t, credMeta)

	first, err := client.buildDCQLQueryFromConfig([]string{"pid"})
	require.NoError(t, err)
	require.Len(t, first.Credentials[0].Claims, 1)

	// What augmentDCQLFromVCTM does to a query it is given.
	first.Credentials[0].Claims[0] = openid4vp.ClaimQuery{Path: claimPath("family_name")}

	assert.Equal(t, []openid4vp.ClaimQuery{{Path: claimPath("given_name")}}, credMeta["pid"].DCQLClaims,
		"the configuration a query was built from is unchanged")

	second, err := client.buildDCQLQueryFromConfig([]string{"pid"})
	require.NoError(t, err)
	assert.Equal(t, []openid4vp.ClaimQuery{{Path: claimPath("given_name")}}, second.Credentials[0].Claims,
		"the next request asks for what is configured, not what the last one was mutated into")
}
