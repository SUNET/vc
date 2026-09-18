package apiv1

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_generateSubjectIdentifier_Public(t *testing.T) {
	client, _ := CreateTestClientWithMock(t, nil)
	client.cfg.Verifier.Outbound.OIDCProvider.SubjectType = "public"
	client.cfg.Verifier.Outbound.OIDCProvider.SubjectSalt = "test-salt"

	walletID := "wallet-123"
	clientID1 := "client-1"
	clientID2 := "client-2"

	// Public subject type: same sub for different clients
	sub1 := client.generateSubjectIdentifier(walletID, clientID1)
	sub2 := client.generateSubjectIdentifier(walletID, clientID2)

	assert.NotEmpty(t, sub1)
	assert.NotEmpty(t, sub2)
	assert.Equal(t, sub1, sub2, "public subject type should return same sub for different clients")
}

func TestClient_generateSubjectIdentifier_Pairwise(t *testing.T) {
	client, _ := CreateTestClientWithMock(t, nil)
	client.cfg.Verifier.Outbound.OIDCProvider.SubjectType = "pairwise"
	client.cfg.Verifier.Outbound.OIDCProvider.SubjectSalt = "test-salt"

	walletID := "wallet-123"
	clientID1 := "client-1"
	clientID2 := "client-2"

	// Pairwise subject type: different sub for different clients
	sub1 := client.generateSubjectIdentifier(walletID, clientID1)
	sub2 := client.generateSubjectIdentifier(walletID, clientID2)

	assert.NotEmpty(t, sub1)
	assert.NotEmpty(t, sub2)
	assert.NotEqual(t, sub1, sub2, "pairwise subject type should return different sub for different clients")

	// Same client should get same sub
	sub1Again := client.generateSubjectIdentifier(walletID, clientID1)
	assert.Equal(t, sub1, sub1Again, "same wallet+client should always get same sub")
}

func TestClient_generateSubjectIdentifier_DifferentWallets(t *testing.T) {
	client, _ := CreateTestClientWithMock(t, nil)
	client.cfg.Verifier.Outbound.OIDCProvider.SubjectType = "pairwise"
	client.cfg.Verifier.Outbound.OIDCProvider.SubjectSalt = "test-salt"

	walletID1 := "wallet-1"
	walletID2 := "wallet-2"
	clientID := "client-1"

	sub1 := client.generateSubjectIdentifier(walletID1, clientID)
	sub2 := client.generateSubjectIdentifier(walletID2, clientID)

	assert.NotEqual(t, sub1, sub2, "different wallets should get different subs")
}

func TestClient_containsOIDC(t *testing.T) {
	client, _ := CreateTestClientWithMock(t, nil)

	tests := []struct {
		name     string
		slice    []string
		value    string
		expected bool
	}{
		{
			name:     "value exists",
			slice:    []string{"openid", "profile", "email"},
			value:    "profile",
			expected: true,
		},
		{
			name:     "value does not exist",
			slice:    []string{"openid", "profile", "email"},
			value:    "admin",
			expected: false,
		},
		{
			name:     "empty slice",
			slice:    []string{},
			value:    "openid",
			expected: false,
		},
		{
			name:     "first element",
			slice:    []string{"openid", "profile"},
			value:    "openid",
			expected: true,
		},
		{
			name:     "last element",
			slice:    []string{"openid", "profile"},
			value:    "profile",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.containsOIDC(tt.slice, tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestClient_parseScopes(t *testing.T) {
	tests := []struct {
		name     string
		scopeStr string
		expected []string
	}{
		{
			name:     "single scope",
			scopeStr: "openid",
			expected: []string{"openid"},
		},
		{
			name:     "multiple scopes",
			scopeStr: "openid profile email",
			expected: []string{"openid", "profile", "email"},
		},
		{
			name:     "empty string",
			scopeStr: "",
			expected: []string{},
		},
		{
			name:     "extra spaces",
			scopeStr: "openid  profile   email",
			expected: []string{"openid", "", "profile", "", "", "email"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseScopes(tt.scopeStr)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestClient_Health(t *testing.T) {
	ctx := t.Context()
	client, _ := CreateTestClientWithMock(t, nil)

	// Note: Health requires db to be set, which may fail in mock
	// This test verifies the method exists and can be called
	_, err := client.Health(ctx, nil)
	// May return error due to nil db, that's expected in test
	_ = err
}

// TestPKCE_S256 verifies PKCE S256 code challenge method
func TestPKCE_S256(t *testing.T) {
	// Standard PKCE test vectors from RFC 7636 Appendix B
	// code_verifier: dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
	// code_challenge (S256): E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	// Compute S256 challenge
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	assert.Equal(t, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", challenge)
}

func TestClient_buildDCQLQueryFromConfig(t *testing.T) {
	tests := []struct {
		name              string
		scopes            []string
		credMeta          map[string]*model.CredentialMetadata
		expectError       bool
		expectedCredCount int
	}{
		{
			name:   "single valid scope",
			scopes: []string{"diploma"},
			credMeta: map[string]*model.CredentialMetadata{
				"diploma": {
					Format: "dc+sd-jwt",
					VCTM: &sdjwtvc.VCTM{
						VCT: "urn:credential:diploma",
					},
				},
			},
			expectError:       false,
			expectedCredCount: 1,
		},
		{
			name:   "multiple valid scopes",
			scopes: []string{"diploma", "ehic"},
			credMeta: map[string]*model.CredentialMetadata{
				"diploma": {
					Format: "dc+sd-jwt",
					VCTM: &sdjwtvc.VCTM{
						VCT: "urn:credential:diploma",
					},
				},
				"ehic": {
					Format: "dc+sd-jwt",
					VCTM: &sdjwtvc.VCTM{
						VCT: "urn:credential:ehic",
					},
				},
			},
			expectError:       false,
			expectedCredCount: 2,
		},
		{
			name:   "scopes with openid (should be skipped)",
			scopes: []string{"openid", "diploma"},
			credMeta: map[string]*model.CredentialMetadata{
				"diploma": {
					Format: "dc+sd-jwt",
					VCTM: &sdjwtvc.VCTM{
						VCT: "urn:credential:diploma",
					},
				},
			},
			expectError:       false,
			expectedCredCount: 1,
		},
		{
			name:              "no matching scopes",
			scopes:            []string{"unknown_scope"},
			credMeta:          map[string]*model.CredentialMetadata{},
			expectError:       true,
			expectedCredCount: 0,
		},
		{
			name:   "all scopes are openid or unmatched",
			scopes: []string{"openid"},
			credMeta: map[string]*model.CredentialMetadata{
				"diploma": {
					VCTM: &sdjwtvc.VCTM{
						VCT: "urn:credential:diploma",
					},
				},
			},
			expectError:       true,
			expectedCredCount: 0,
		},
		{
			name:   "scope with VCTM containing claims",
			scopes: []string{"diploma"},
			credMeta: map[string]*model.CredentialMetadata{
				"diploma": {
					Format: "dc+sd-jwt",
					VCTM: &sdjwtvc.VCTM{
						VCT:  "urn:credential:diploma",
						Name: "Diploma Credential",
						Claims: []sdjwtvc.Claim{
							{
								Path: []*string{new("given_name")},
								Display: []sdjwtvc.ClaimDisplay{
									{Locale: "en", Label: "Given Name"},
								},
							},
							{
								Path: []*string{new("family_name")},
								Display: []sdjwtvc.ClaimDisplay{
									{Locale: "en", Label: "Family Name"},
								},
							},
						},
					},
				},
			},
			expectError:       false,
			expectedCredCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &model.Cfg{
				Common: &model.Common{
					CredentialMetadata: tt.credMeta,
				},
			}
			client, _ := CreateTestClientWithMock(t, cfg)

			dcql, err := client.buildDCQLQueryFromConfig(tt.scopes)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, dcql)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, dcql)
				assert.Equal(t, tt.expectedCredCount, len(dcql.Credentials))

				// Verify credential format matches config
				for _, cred := range dcql.Credentials {
					assert.Equal(t, "dc+sd-jwt", cred.Format)
					// Claims should not be populated in fallback mode —
					// let the wallet decide what to disclose
					assert.Nil(t, cred.Claims, "fallback DCQL should not enumerate individual claims")
				}
			}
		})
	}
}

func TestClient_createDCQLQuery(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name        string
		scopes      []string
		credMeta    map[string]*model.CredentialMetadata
		expectError bool
	}{
		{
			name:   "creates DCQL from credential config (no presentation builder)",
			scopes: []string{"diploma"},
			credMeta: map[string]*model.CredentialMetadata{
				"diploma": {
					VCTM: &sdjwtvc.VCTM{
						VCT: "urn:credential:diploma",
					},
				},
			},
			expectError: false,
		},
		{
			name:        "falls back to legacy with empty config",
			scopes:      []string{"unknown_scope"},
			credMeta:    map[string]*model.CredentialMetadata{},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &model.Cfg{
				Common: &model.Common{
					CredentialMetadata: tt.credMeta,
				},
			}
			client, _ := CreateTestClientWithMock(t, cfg)

			dcql, err := client.createDCQLQuery(ctx, tt.scopes)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, dcql)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, dcql)
			}
		})
	}
}

// TestBuildDCQLQueryFromConfigMetaConstraints pins the two things this builder
// got wrong before SUNET/vc#673: it sent only one of the two vct identifiers a
// wallet might match on, and it sent vct_values for mso_mdoc scopes, which are
// constrained by doctype_value instead (OpenID4VP 1.0 6.4.1).
//
// The sibling assertion lives in handlers_ui_test.go's
// TestUIMetadataOffersBothVCTIdentifiers; this is the OIDC-RP fallback path,
// which the original "offer both" fix never reached.
func TestBuildDCQLQueryFromConfigMetaConstraints(t *testing.T) {
	cfg := &model.Cfg{
		Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				// VCTURL is not hand-set: ResolveVCTUrls below derives it
				// exactly as production does, so this exercises the real path.
				"pid": {
					Format:       "dc+sd-jwt",
					VCTMFilePath: "/path/to/vctm",
					VCTM:         &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"},
				},
				"pid_mdoc": {
					Format: "mso_mdoc",
					MDDL:   &mdoc.MDDLSchema{DocType: "eu.europa.ec.eudi.pid.1"},
				},
			},
		},
	}
	require.NoError(t, cfg.ResolveVCTUrls("https://apigw.example"))

	client, _ := CreateTestClientWithMock(t, cfg)
	dcql, err := client.buildDCQLQueryFromConfig([]string{"pid", "pid_mdoc"})
	require.NoError(t, err)
	require.Len(t, dcql.Credentials, 2)

	byID := map[string]openid4vp.CredentialQuery{}
	for _, cred := range dcql.Credentials {
		byID[cred.ID] = cred
	}

	// Both identifiers, credential's own vct first. Sending only
	// "urn:eudi:pid:1" is what no multipaz-derived wallet can match; sending
	// only the URL is what wwWallet can't match.
	pid := byID["pid"]
	assert.Equal(t, []string{"urn:eudi:pid:1", "https://apigw.example/type-metadata/pid"}, pid.Meta.VCTValues)
	assert.Empty(t, pid.Meta.DoctypeValue, "sd-jwt query must not carry a doctype_value")
	assert.NoError(t, openid4vp.ValidateCredentialQuery(pid))

	// The mdoc scope has no VCTM at all, so the old code emitted
	// {"vct_values": [""]} with no doctype_value: unmatched by every wallet
	// and rejected by ValidateCredentialQuery.
	mdocCred := byID["pid_mdoc"]
	assert.Equal(t, "eu.europa.ec.eudi.pid.1", mdocCred.Meta.DoctypeValue)
	assert.Empty(t, mdocCred.Meta.VCTValues, "mdoc query must not carry vct_values")
	assert.NoError(t, openid4vp.ValidateCredentialQuery(mdocCred))
}

// TestBuildDCQLQueryFromConfigSkipsW3CScope is the verifier-side half of the
// Copilot finding covered by TestBuildAuthDCQLW3CScopeIsSkipped: a configured
// ldp_vc scope used to fall through to the SD-JWT branch and go out with
// vct_values, which ValidateCredentialQuery rejects for W3C formats.
//
// With the only requested scope skipped, the builder fails loudly rather than
// returning a query that matches nothing.
func TestBuildDCQLQueryFromConfigSkipsW3CScope(t *testing.T) {
	cfg := &model.Cfg{
		Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				"diploma_ldp": {
					Format:       "ldp_vc",
					VCTMFilePath: "/path/to/vctm_diploma",
					VCTM:         &sdjwtvc.VCTM{VCT: "urn:credential:diploma:1"},
				},
				"pid": {
					Format:       "dc+sd-jwt",
					VCTMFilePath: "/path/to/vctm_pid",
					VCTM:         &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"},
				},
			},
		},
	}
	require.NoError(t, cfg.ResolveVCTUrls("https://apigw.example"))
	client, _ := CreateTestClientWithMock(t, cfg)

	// Mixed with a usable scope is still an error, not a partial query. A
	// dropped scope would stay in the OIDC request's scope list
	// (handler_oidc.go -> authCtx.Scopes), and VerificationDirectPost requires
	// a VP token for every entry there - so a partial query fails with
	// "VP token not found for scope" only after the user has completed a
	// presentation. Better to say what is wrong before anything reaches a
	// wallet.
	_, err := client.buildDCQLQueryFromConfig([]string{"pid", "diploma_ldp"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "diploma_ldp")

	_, err = client.buildDCQLQueryFromConfig([]string{"diploma_ldp"})
	assert.Error(t, err)

	// An UNCONFIGURED scope stays a silent skip: that is an ordinary OIDC
	// scope like "profile", not a credential anyone asked for.
	dcql, err := client.buildDCQLQueryFromConfig([]string{"pid", "profile"})
	require.NoError(t, err)
	require.Len(t, dcql.Credentials, 1)
	assert.Equal(t, "pid", dcql.Credentials[0].ID)
}

// TestBuildDCQLQueryFromConfigNilMetadataValue covers a Copilot review finding:
// credential_metadata can hold a nil VALUE for a present key (an entry written
// with no fields), which is distinct from the key being absent and survives the
// map lookup. DCQLMetaQuery is nil-safe and reports !ok, but the skip log then
// read credInfo.Format directly and panicked while reporting the very config
// error it was reporting.
func TestBuildDCQLQueryFromConfigNilMetadataValue(t *testing.T) {
	cfg := &model.Cfg{
		Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				"broken": nil,
				"pid": {
					Format:       "dc+sd-jwt",
					VCTMFilePath: "/path/to/vctm_pid",
					VCTM:         &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"},
				},
			},
		},
	}
	require.NoError(t, cfg.ResolveVCTUrls("https://apigw.example"))
	client, _ := CreateTestClientWithMock(t, cfg)

	// Must not panic. A nil entry is a CONFIGURED scope that cannot be
	// expressed, so it is reported rather than dropped - the key is present,
	// which is what distinguishes it from an ordinary unknown OIDC scope.
	_, err := client.buildDCQLQueryFromConfig([]string{"pid", "broken"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "broken")

	_, err = client.buildDCQLQueryFromConfig([]string{"broken"})
	assert.Error(t, err)
}

// TestUIMetadataDropsPresetWithUnconstrainableScope covers a Copilot review
// finding on the preset path: when DCQLMetaQuery reports !ok the credential was
// still emitted, with an EMPTY meta. The UI schema accepts that and sends it, so
// the wallet saw a query with no type constraint and could match any credential
// of that format. An unconstrained query over-discloses silently, which is worse
// than a missing one.
func TestUIMetadataDropsPresetWithUnconstrainableScope(t *testing.T) {
	cfg := &model.Cfg{
		Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				"pid": {
					Format:       "dc+sd-jwt",
					VCTMFilePath: "/path/to/vctm_pid",
					VCTM:         &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"},
				},
				// No DCQL constraint is expressible for a W3C VC scope.
				"diploma_ldp": {
					Format:       "ldp_vc",
					VCTMFilePath: "/path/to/vctm_diploma",
					VCTM:         &sdjwtvc.VCTM{VCT: "urn:eudi:diploma:1"},
				},
			},
		},
		Verifier: &model.Verifier{
			Presets: map[string]model.PresetDefinition{
				// Mixed: keeps the usable scope, drops the other.
				"MIXED": {Credentials: model.VerificationPreset{"pid": nil, "diploma_ldp": nil}},
				// Nothing usable at all: the whole preset goes.
				"LDP_ONLY": {Credentials: model.VerificationPreset{"diploma_ldp": nil}},
			},
		},
	}
	require.NoError(t, cfg.ResolveVCTUrls("https://apigw.example"))
	client, _ := CreateTestClientWithMock(t, cfg)

	reply, err := client.UIMetadata(t.Context())
	require.NoError(t, err)

	mixed, present := reply.Presets["MIXED"]
	require.True(t, present, "a preset with one usable scope is still offered")
	require.Len(t, mixed.Credentials, 1)
	assert.Equal(t, "pid", mixed.Credentials[0].ID)
	assert.NotEmpty(t, mixed.Credentials[0].Meta.VCTValues)

	_, present = reply.Presets["LDP_ONLY"]
	assert.False(t, present, "a preset whose every scope is unconstrainable must not be advertised")
}

// TestAugmentVCTValuesFromConfig covers the path that actually ships.
//
// createDCQLQuery tries the presentation templates FIRST and returns their
// query as-is when one matches, so buildDCQLQueryFromConfig - where the
// SUNET/vc#673 fix lives - is never reached by a deployment that configures
// presentation_requests/. Each shipped template names exactly one vct, so those
// requests kept asking for a single identifier and kept missing the wallets
// that match the other one.
//
// The operator's own value stays first; the scope's remaining identifiers are
// appended, since meta.vct_values is an acceptable-value list.
func TestAugmentVCTValuesFromConfig(t *testing.T) {
	cfg := &model.Cfg{
		Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				"pid": {
					Format:       "dc+sd-jwt",
					VCTMFilePath: "/path/to/vctm_pid",
					VCTM:         &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"},
				},
				"pid_mdoc": {
					Format: "mso_mdoc",
					MDDL:   &mdoc.MDDLSchema{DocType: "eu.europa.ec.eudi.pid.1"},
				},
			},
		},
	}
	require.NoError(t, cfg.ResolveVCTUrls("https://apigw.example"))
	client, _ := CreateTestClientWithMock(t, cfg)

	dcql := &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{
		// Shaped like presentation_requests/eudi_pid.yaml: the query id is a
		// template name, not a configured scope, so the pairing has to be made
		// on the vct value itself.
		{ID: "eudi_pid", Format: "dc+sd-jwt", Meta: openid4vp.MetaQuery{VCTValues: []string{"urn:eudi:pid:1"}}},
		// A template written the other way round - naming the served URL -
		// should gain the credential's own vct instead.
		{ID: "pid_by_url", Format: "dc+sd-jwt", Meta: openid4vp.MetaQuery{VCTValues: []string{"https://apigw.example/type-metadata/pid"}}},
		// Constrained by doctype: nothing to add, and nothing to guess at.
		{ID: "mdl", Format: "mso_mdoc", Meta: openid4vp.MetaQuery{DoctypeValue: "eu.europa.ec.eudi.pid.1"}},
		// Names a type this verifier has no credential_metadata for: left as
		// the operator wrote it.
		{ID: "foreign", Format: "dc+sd-jwt", Meta: openid4vp.MetaQuery{VCTValues: []string{"urn:example:unknown:1"}}},
	}}

	client.augmentVCTValuesFromConfig(dcql)

	assert.Equal(t, []string{"urn:eudi:pid:1", "https://apigw.example/type-metadata/pid"}, dcql.Credentials[0].Meta.VCTValues)
	assert.Equal(t, []string{"https://apigw.example/type-metadata/pid", "urn:eudi:pid:1"}, dcql.Credentials[1].Meta.VCTValues)
	assert.Empty(t, dcql.Credentials[2].Meta.VCTValues)
	assert.Equal(t, "eu.europa.ec.eudi.pid.1", dcql.Credentials[2].Meta.DoctypeValue)
	assert.Equal(t, []string{"urn:example:unknown:1"}, dcql.Credentials[3].Meta.VCTValues)

	// Idempotent: running twice must not duplicate anything.
	client.augmentVCTValuesFromConfig(dcql)
	assert.Equal(t, []string{"urn:eudi:pid:1", "https://apigw.example/type-metadata/pid"}, dcql.Credentials[0].Meta.VCTValues)

	assert.NotPanics(t, func() { client.augmentVCTValuesFromConfig(nil) })
}
