package apiv1

import (
	"testing"

	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBuildAuthDCQLOffersBothVCTIdentifiers pins the fix for SUNET/vc#673 on
// the path that actually regressed.
//
// This call site flip-flopped between the two identifiers a wallet might match
// a credential type by: 9d2106c5 (finding 16) sent the VCTM's own vct, which
// wwWallet matches; b30f7442 (finding 18) reverted it to the type-metadata URL,
// which the EUDI reference wallet matches. Each position broke the wallets of
// the other kind. 5aa1c50e fixed the verifier UI to send both but never reached
// here, which is exactly what the issue reports.
//
// meta.vct_values is an acceptable-value list (OpenID4VP 1.0 6.4.1), so the
// query carries both and this test fails if anyone picks a winner again.
func TestBuildAuthDCQLOffersBothVCTIdentifiers(t *testing.T) {
	cfg := &model.Cfg{
		Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				// VCTURL is not hand-set: ResolveVCTUrls derives it below
				// exactly as the server does at startup.
				"pid": {
					Format:       "dc+sd-jwt",
					VCTMFilePath: "/path/to/vctm_pid",
					VCTM:         &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"},
				},
				"eduid": {
					Format:       "dc+sd-jwt",
					VCTMFilePath: "/path/to/vctm_eduid",
					VCTM:         &sdjwtvc.VCTM{VCT: "urn:credential:eduid:1"},
				},
			},
		},
	}
	require.NoError(t, cfg.ResolveVCTUrls("https://apigw.example"))

	c := &Client{cfg: cfg}
	dcql := c.buildAuthDCQL(&model.OpenID4VPCredentialAuth{
		AuthScopes: map[string]model.AuthScopeEntry{
			"pid":   {AuthClaims: []string{"given_name", "family_name"}},
			"eduid": {AuthClaims: []string{"given_name"}},
		},
	})

	require.Len(t, dcql.Credentials, 2)
	// slices.Sorted over the scope keys: eduid before pid.
	assert.Equal(t, "eduid", dcql.Credentials[0].ID)
	assert.Equal(t, "pid", dcql.Credentials[1].ID)

	assert.Equal(t,
		[]string{"urn:credential:eduid:1", "https://apigw.example/type-metadata/eduid"},
		dcql.Credentials[0].Meta.VCTValues,
	)
	assert.Equal(t,
		[]string{"urn:eudi:pid:1", "https://apigw.example/type-metadata/pid"},
		dcql.Credentials[1].Meta.VCTValues,
	)

	for _, cred := range dcql.Credentials {
		assert.NoError(t, openid4vp.ValidateCredentialQuery(cred))
	}

	// One option per auth scope, so the wallet can satisfy the request with
	// any one of the acceptable credential types.
	require.Len(t, dcql.CredentialSets, 1)
	assert.Equal(t, [][]string{{"eduid"}, {"pid"}}, dcql.CredentialSets[0].Options)
}

// TestBuildAuthDCQLMdocScopeUsesDoctype covers the format branch: an mso_mdoc
// auth scope has no VCTM at all, and DCQL constrains it by doctype_value rather
// than vct_values (OpenID4VP 1.0 6.4.1). Without the branch this emitted an
// empty vct_values and no doctype - a query no wallet can match, and one
// ValidateCredentialQuery rejects.
func TestBuildAuthDCQLMdocScopeUsesDoctype(t *testing.T) {
	cfg := &model.Cfg{
		Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				"pid_mdoc": {
					Format: "mso_mdoc",
					MDDL:   &mdoc.MDDLSchema{DocType: "eu.europa.ec.eudi.pid.1"},
				},
			},
		},
	}

	c := &Client{cfg: cfg}
	dcql := c.buildAuthDCQL(&model.OpenID4VPCredentialAuth{
		AuthScopes: map[string]model.AuthScopeEntry{
			"pid_mdoc": {AuthClaims: []string{"given_name"}},
		},
	})

	require.Len(t, dcql.Credentials, 1)
	cred := dcql.Credentials[0]
	assert.Equal(t, "eu.europa.ec.eudi.pid.1", cred.Meta.DoctypeValue)
	assert.Empty(t, cred.Meta.VCTValues, "mdoc query must not carry vct_values")
	assert.NoError(t, openid4vp.ValidateCredentialQuery(cred))
}
