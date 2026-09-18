package apiv1

import (
	"testing"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sdJWTScope is a dc+sd-jwt credential_metadata entry whose VCTM declares its
// own vct. VCTURL is deliberately left unset: authDCQLFor runs ResolveVCTUrls,
// which derives it exactly as the server does at startup, so these fixtures
// exercise the real resolution rather than a hand-built approximation of it.
func sdJWTScope(vct string) *model.CredentialMetadata {
	return &model.CredentialMetadata{
		Format:       "dc+sd-jwt",
		VCTMFilePath: "/path/to/vctm",
		VCTM:         &sdjwtvc.VCTM{VCT: vct},
	}
}

// authDCQLFor builds the pre-issuance authentication query for the given
// credential_metadata, requesting every configured scope as an auth scope.
func authDCQLFor(t *testing.T, credMeta map[string]*model.CredentialMetadata) *openid4vp.DCQL {
	t.Helper()

	cfg := &model.Cfg{Common: &model.Common{CredentialMetadata: credMeta}}
	require.NoError(t, cfg.ResolveVCTUrls("https://apigw.example"))

	authScopes := make(map[string]model.AuthScopeEntry, len(credMeta))
	for scope := range credMeta {
		authScopes[scope] = model.AuthScopeEntry{AuthClaims: []string{"given_name"}}
	}

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	c := &Client{cfg: cfg, log: log}
	return c.buildAuthDCQL(&model.OpenID4VPCredentialAuth{AuthScopes: authScopes})
}

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
	dcql := authDCQLFor(t, map[string]*model.CredentialMetadata{
		"pid":   sdJWTScope("urn:eudi:pid:1"),
		"eduid": sdJWTScope("urn:credential:eduid:1"),
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
	dcql := authDCQLFor(t, map[string]*model.CredentialMetadata{
		"pid_mdoc": {
			Format: "mso_mdoc",
			MDDL:   &mdoc.MDDLSchema{DocType: "eu.europa.ec.eudi.pid.1"},
		},
	})

	require.Len(t, dcql.Credentials, 1)
	cred := dcql.Credentials[0]
	assert.Equal(t, "eu.europa.ec.eudi.pid.1", cred.Meta.DoctypeValue)
	assert.Empty(t, cred.Meta.VCTValues, "mdoc query must not carry vct_values")
	assert.NoError(t, openid4vp.ValidateCredentialQuery(cred))
}

// TestBuildAuthDCQLUnknownScopeDoesNotPanic covers a Copilot review finding on
// this PR: config validation checks that auth_scopes is non-empty and does not
// self-reference, but never that its keys resolve to a configured credential
// (pkg/helpers/validate.go). GetCredentialMetadata then returns nil, and every
// CredentialMetadata accessor takes c.mu.RLock() without a nil-receiver guard -
// so reading the scope's metadata here panicked on a config that passes
// validation. DCQLMetaQuery's nil check plus the skip keeps it a logged
// configuration error.
func TestBuildAuthDCQLUnknownScopeDoesNotPanic(t *testing.T) {
	cfg := &model.Cfg{Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{
		"pid": sdJWTScope("urn:eudi:pid:1"),
	}}}
	require.NoError(t, cfg.ResolveVCTUrls("https://apigw.example"))

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	// The auth scopes deliberately name a credential the config never defines,
	// which authDCQLFor cannot express (it derives them from credMeta).
	c := &Client{cfg: cfg, log: log}
	dcql := c.buildAuthDCQL(&model.OpenID4VPCredentialAuth{
		AuthScopes: map[string]model.AuthScopeEntry{
			"pid":              {AuthClaims: []string{"given_name"}},
			"nosuchcredential": {AuthClaims: []string{"given_name"}},
		},
	})

	// The unknown scope is dropped from both the queries and the options,
	// rather than emitted as a query no wallet can match.
	require.Len(t, dcql.Credentials, 1)
	assert.Equal(t, "pid", dcql.Credentials[0].ID)
	require.Len(t, dcql.CredentialSets, 1)
	assert.Equal(t, [][]string{{"pid"}}, dcql.CredentialSets[0].Options)
}

// TestBuildAuthDCQLW3CScopeIsSkipped covers the second Copilot finding: the
// branch used to key off "is an MDDL loaded", so a configured ldp_vc or
// jwt_vc_json scope - both of which this stack can issue, see issueVC20 -
// fell through to the SD-JWT branch and got vct_values. ValidateCredentialQuery
// requires type_values for those formats, so the query was invalid by this
// repo's own validator.
//
// Nothing in credential_metadata configures a W3C type list, so the scope is
// skipped rather than given a constraint that would be either invalid or (with
// the issuer metadata's bare "VerifiableCredential") broad enough to match
// every W3C credential in the wallet.
func TestBuildAuthDCQLW3CScopeIsSkipped(t *testing.T) {
	ldp := sdJWTScope("urn:credential:diploma:1")
	ldp.Format = "ldp_vc"

	dcql := authDCQLFor(t, map[string]*model.CredentialMetadata{"diploma_ldp": ldp})

	assert.Empty(t, dcql.Credentials, "an ldp_vc scope must not be sent with vct_values")
	assert.Empty(t, dcql.CredentialSets[0].Options)
}
