package apiv1

import (
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBuildIssuanceAuthDCQL exercises the DCQL query built for OpenID4VP-based
// issuance authentication: one CredentialQuery per auth scope, each carrying
// that scope's single canonical VCTM.VCT in meta.vct_values (see
// (*model.Cfg).VCTIdentifiersForScopes), per-scope auth_claims mapped to
// StringPath, and a CredentialSets Options entry so the wallet may pick any
// of the acceptable credential types.
func TestBuildIssuanceAuthDCQL(t *testing.T) {
	cfg := &model.Cfg{
		Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				"pid": {
					Format: "dc+sd-jwt",
					VCTM:   &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"},
				},
				"eduid": {
					Format: "vc+sd-jwt",
					VCTM:   &sdjwtvc.VCTM{VCT: "urn:sunet:eduid:1"},
				},
			},
		},
	}
	vpAuth := &model.OpenID4VPCredentialAuth{
		AuthScopes: map[string]model.AuthScopeEntry{
			"pid":   {AuthClaims: []string{"given_name", "family_name"}},
			"eduid": {AuthClaims: []string{"eduPersonPrincipalName"}},
		},
	}

	dcql := buildIssuanceAuthDCQL(vpAuth, cfg)
	require.NotNil(t, dcql)
	require.Len(t, dcql.Credentials, 2)

	byID := map[string]openid4vp.CredentialQuery{}
	for _, cq := range dcql.Credentials {
		byID[cq.ID] = cq
	}

	assert.Equal(t, "dc+sd-jwt", byID["pid"].Format)
	assert.Equal(t, []string{"urn:eudi:pid:1"}, byID["pid"].Meta.VCTValues)
	require.Len(t, byID["pid"].Claims, 2)
	assert.Equal(t, openid4vp.StringPath("given_name"), byID["pid"].Claims[0].Path)
	assert.Equal(t, openid4vp.StringPath("family_name"), byID["pid"].Claims[1].Path)

	assert.Equal(t, "vc+sd-jwt", byID["eduid"].Format)
	assert.Equal(t, []string{"urn:sunet:eduid:1"}, byID["eduid"].Meta.VCTValues)
	require.Len(t, byID["eduid"].Claims, 1)
	assert.Equal(t, openid4vp.StringPath("eduPersonPrincipalName"), byID["eduid"].Claims[0].Path)

	// CredentialSets Options list one entry per auth scope, sorted
	// alphabetically for deterministic iteration.
	require.Len(t, dcql.CredentialSets, 1)
	assert.Equal(t, [][]string{{"eduid"}, {"pid"}}, dcql.CredentialSets[0].Options)
}
