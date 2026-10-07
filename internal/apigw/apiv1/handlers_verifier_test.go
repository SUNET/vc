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

	dcql, err := buildIssuanceAuthDCQL(vpAuth, cfg)
	require.NoError(t, err)
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

// TestBuildIssuanceAuthDCQLByFormat pins the constraint to the credential's
// format. An mso_mdoc auth scope carries no vct, so vct_values matches nothing
// in any wallet - it has to go out as doctype_value (OpenID4VP 1.0 6.4.1).
func TestBuildIssuanceAuthDCQLByFormat(t *testing.T) {
	cfg := &model.Cfg{
		Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				// Registry-backed: a doctype and no MDDL document, the shape
				// that a "has an MDDL?" test gets wrong.
				"pid_mdoc": {Format: "mso_mdoc", Doctype: "eu.europa.ec.eudi.pid.1"},
				"pid":      {Format: "dc+sd-jwt", VCTM: &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"}},
			},
		},
	}
	vpAuth := &model.OpenID4VPCredentialAuth{
		AuthScopes: map[string]model.AuthScopeEntry{
			"pid_mdoc": {AuthClaims: []string{"family_name"}},
			"pid":      {AuthClaims: []string{"given_name"}},
		},
	}

	dcql, err := buildIssuanceAuthDCQL(vpAuth, cfg)
	require.NoError(t, err)
	require.Len(t, dcql.Credentials, 2)

	byID := map[string]openid4vp.CredentialQuery{}
	for _, cq := range dcql.Credentials {
		byID[cq.ID] = cq
	}

	assert.Equal(t, "eu.europa.ec.eudi.pid.1", byID["pid_mdoc"].Meta.DoctypeValue)
	assert.Empty(t, byID["pid_mdoc"].Meta.VCTValues, "an mdoc credential has no vct to be matched by")

	assert.Equal(t, []string{"urn:eudi:pid:1"}, byID["pid"].Meta.VCTValues)
	assert.Empty(t, byID["pid"].Meta.DoctypeValue)
}

// TestBuildIssuanceAuthDCQLRejectsUnusableScope covers an auth_scopes key that
// names no configured credential. GetCredentialMetadata returns nil for it, and
// the request must be refused rather than sent out with an empty constraint
// that matches every credential in the wallet.
func TestBuildIssuanceAuthDCQLRejectsUnusableScope(t *testing.T) {
	cfg := &model.Cfg{Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{}}}
	vpAuth := &model.OpenID4VPCredentialAuth{
		AuthScopes: map[string]model.AuthScopeEntry{"nosuch": {AuthClaims: []string{"given_name"}}},
	}

	var dcql *openid4vp.DCQL
	var err error
	require.NotPanics(t, func() { dcql, err = buildIssuanceAuthDCQL(vpAuth, cfg) })
	require.Error(t, err)
	assert.Nil(t, dcql)
	assert.Contains(t, err.Error(), "nosuch")
}

// TestBuildIssuanceAuthDCQLRefusesW3C pins the boundary between the two
// direct-post flows.
//
// This package's VerificationDirectPost validates the response as an SD-JWT
// and has no format dispatch, so a W3C auth scope would produce a query the
// wallet can satisfy and this flow then cannot read - failing after the user
// has already been sent to their wallet. The verifier service verifies W3C;
// issuance auth is a separate flow that has not been taught to.
func TestBuildIssuanceAuthDCQLRefusesW3C(t *testing.T) {
	cfg := &model.Cfg{Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{
		"diploma": {
			Format:               openid4vp.FormatLdpVCDCQL,
			CredentialTypeValues: [][]string{{openid4vp.BaseVCTypeIRI, "https://example.org/degree#DiplomaCredential"}},
		},
		"pid": {
			Format: openid4vp.FormatSDJWTVC,
			VCTM:   &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"},
		},
	}}}

	_, err := buildIssuanceAuthDCQL(&model.OpenID4VPCredentialAuth{
		AuthScopes: map[string]model.AuthScopeEntry{
			"diploma": {AuthClaims: []string{"given_name"}},
		},
	}, cfg)
	require.Error(t, err, "a W3C auth scope must be refused at build time, not at response time")
	assert.Contains(t, err.Error(), "issuance auth cannot verify")

	// An SD-JWT auth scope is unaffected.
	dcql, err := buildIssuanceAuthDCQL(&model.OpenID4VPCredentialAuth{
		AuthScopes: map[string]model.AuthScopeEntry{
			"pid": {AuthClaims: []string{"given_name"}},
		},
	}, cfg)
	require.NoError(t, err)
	require.Len(t, dcql.Credentials, 1)
	assert.Equal(t, []string{"urn:eudi:pid:1"}, dcql.Credentials[0].Meta.VCTValues)
}
