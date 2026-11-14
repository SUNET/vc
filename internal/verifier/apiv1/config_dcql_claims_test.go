package apiv1

import (
	"encoding/json"
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/creasty/defaults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
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

// Every test above builds CredentialMetadata in Go, which proves the query is
// built from the field but not that an operator can ever fill it. Removing or
// misspelling the yaml tag on DCQLClaims would leave them all green while
// recreating #920's silent discard exactly - the loader deliberately does not
// UnmarshalStrict (pkg/configuration/shipped_configs_test.go:42), so a key the
// model does not declare is accepted and dropped without a word.
//
// So run the loader's own two steps - yaml.Unmarshal then defaults.Set, the
// pair in pkg/configuration/config.go - over the real model, with the real
// yaml.v2 that ClaimQuery's custom unmarshaller is written against, and follow
// the claims all the way to the query that goes on the wire.
func TestConfiguredClaimsSurviveTheYAMLLoader(t *testing.T) {
	raw := []byte(`
common:
  credential_metadata:
    pid:
      format: dc+sd-jwt
      claims:
        - path: ["given_name"]
        - path: ["address", "locality"]
        - path: ["nationalities", null]
`)

	cfg := &model.Cfg{}
	require.NoError(t, yaml.Unmarshal(raw, cfg))
	require.NoError(t, defaults.Set(cfg))

	require.NotNil(t, cfg.Common, "common must survive the loader")
	require.Contains(t, cfg.Common.CredentialMetadata, "pid")
	require.Len(t, cfg.Common.CredentialMetadata["pid"].DCQLClaims, 3,
		"claims written under credential_metadata.<scope>.claims must reach the model, not be dropped as an unknown key")

	// The vct identifier is never configured directly: VCTM and VCTURL both
	// carry yaml:"-" and are filled at startup from vctm_file_path, vctm_url
	// or the credential registry. Attach it the way startup does, so the
	// query can be built and the claims under test are the only thing the
	// YAML had to supply.
	cfg.Common.CredentialMetadata["pid"].VCTM = &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"}

	dcql, err := claimsClient(t, cfg.Common.CredentialMetadata).buildDCQLQueryFromConfig([]string{"pid"})
	require.NoError(t, err)
	require.Len(t, dcql.Credentials, 1)

	// Asserted on the serialized form, because that is what the wallet reads:
	// the null element has to arrive as JSON null - the claims path pointer
	// that selects every element of an array (OpenID4VP 1.0 6.4.1) - rather
	// than as "" or a silently shortened path.
	serialized, err := json.Marshal(dcql.Credentials[0].Claims)
	require.NoError(t, err)
	assert.JSONEq(t, `[
		{"path": ["given_name"]},
		{"path": ["address", "locality"]},
		{"path": ["nationalities", null]}
	]`, string(serialized), "the configured claim paths are what the wallet is asked for")
}
