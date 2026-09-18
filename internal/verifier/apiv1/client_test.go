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

// sdJWTScope is a dc+sd-jwt credential_metadata entry whose VCTM declares its
// own vct. VCTURL is deliberately left unset: dcqlClientFor runs ResolveVCTUrls,
// which derives it exactly as the server does at startup, so these fixtures
// exercise the real resolution rather than a hand-built approximation of it.
func sdJWTScope(vct string) *model.CredentialMetadata {
	return &model.CredentialMetadata{
		Format:       "dc+sd-jwt",
		VCTMFilePath: "/path/to/vctm",
		VCTM:         &sdjwtvc.VCTM{VCT: vct},
	}
}

// w3cScope is the same thing in a format DCQL has no expressible constraint for.
func w3cScope(vct string) *model.CredentialMetadata {
	cm := sdJWTScope(vct)
	cm.Format = "ldp_vc"
	return cm
}

// dcqlClientFor builds a verifier client over the given credential_metadata and
// presets, with VCT URLs resolved as the server resolves them at startup.
func dcqlClientFor(t *testing.T, credMeta map[string]*model.CredentialMetadata, presets map[string]model.PresetDefinition) *Client {
	t.Helper()

	cfg := &model.Cfg{
		Common:   &model.Common{CredentialMetadata: credMeta},
		Verifier: &model.Verifier{Presets: presets},
	}
	require.NoError(t, cfg.ResolveVCTUrls("https://apigw.example"))

	client, _ := CreateTestClientWithMock(t, cfg)
	client.cfg = cfg
	return client
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
	client := dcqlClientFor(t, map[string]*model.CredentialMetadata{
		"pid":      sdJWTScope("urn:eudi:pid:1"),
		"pid_mdoc": {Format: "mso_mdoc", MDDL: &mdoc.MDDLSchema{DocType: "eu.europa.ec.eudi.pid.1"}},
	}, nil)

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
	client := dcqlClientFor(t, map[string]*model.CredentialMetadata{
		"diploma_ldp": w3cScope("urn:credential:diploma:1"),
		"pid":         sdJWTScope("urn:eudi:pid:1"),
	}, nil)

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
	client := dcqlClientFor(t, map[string]*model.CredentialMetadata{
		"broken": nil,
		"pid":    sdJWTScope("urn:eudi:pid:1"),
	}, nil)

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
	client := dcqlClientFor(t, map[string]*model.CredentialMetadata{
		"pid": sdJWTScope("urn:eudi:pid:1"),
		// No DCQL constraint is expressible for a W3C VC scope.
		"diploma_ldp": w3cScope("urn:eudi:diploma:1"),
	}, map[string]model.PresetDefinition{
		// Mixed: keeps the usable scope, drops the other.
		"MIXED": {Credentials: model.VerificationPreset{"pid": nil, "diploma_ldp": nil}},
		// Nothing usable at all: the whole preset goes.
		"LDP_ONLY": {Credentials: model.VerificationPreset{"diploma_ldp": nil}},
	})

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
	client := dcqlClientFor(t, map[string]*model.CredentialMetadata{
		"pid":      sdJWTScope("urn:eudi:pid:1"),
		"pid_mdoc": {Format: "mso_mdoc", MDDL: &mdoc.MDDLSchema{DocType: "eu.europa.ec.eudi.pid.1"}},
	}, nil)

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

	client.augmentVCTValuesFromConfig(dcql, []string{"pid", "pid_mdoc", "profile"})

	assert.Equal(t, []string{"urn:eudi:pid:1", "https://apigw.example/type-metadata/pid"}, dcql.Credentials[0].Meta.VCTValues)
	assert.Equal(t, []string{"https://apigw.example/type-metadata/pid", "urn:eudi:pid:1"}, dcql.Credentials[1].Meta.VCTValues)
	assert.Empty(t, dcql.Credentials[2].Meta.VCTValues)
	assert.Equal(t, "eu.europa.ec.eudi.pid.1", dcql.Credentials[2].Meta.DoctypeValue)
	assert.Equal(t, []string{"urn:example:unknown:1"}, dcql.Credentials[3].Meta.VCTValues)

	// Idempotent: running twice must not duplicate anything.
	client.augmentVCTValuesFromConfig(dcql, []string{"pid", "pid_mdoc", "profile"})
	assert.Equal(t, []string{"urn:eudi:pid:1", "https://apigw.example/type-metadata/pid"}, dcql.Credentials[0].Meta.VCTValues)

	assert.NotPanics(t, func() { client.augmentVCTValuesFromConfig(nil, []string{"pid"}) })
}

// TestAugmentVCTValuesOnlyUsesRequestedScopes covers a review finding: scanning
// every configured scope, rather than the requested ones, widens the query.
//
// ResolveVCTUrls derives VCTURL per SCOPE, so two scopes backed by the same
// VCTM - aliases sharing a vct - get different type-metadata URLs. Matching
// against all of credential_metadata would augment a query for one of them with
// the other's URL, so the verifier would accept a credential configuration it
// never asked for.
func TestAugmentVCTValuesOnlyUsesRequestedScopes(t *testing.T) {
	client := dcqlClientFor(t, map[string]*model.CredentialMetadata{
		"pid":       sdJWTScope("urn:eudi:pid:1"),
		"pid_alias": sdJWTScope("urn:eudi:pid:1"),
	}, nil)

	// Sanity: the two scopes really do resolve to distinct URLs.
	pidURL := "https://apigw.example/type-metadata/pid"
	aliasURL := "https://apigw.example/type-metadata/pid_alias"
	require.Equal(t, []string{"urn:eudi:pid:1", aliasURL},
		client.cfg.Common.CredentialMetadata["pid_alias"].VCTQueryValues())

	query := func() *openid4vp.DCQL {
		return &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{{
			ID: "eudi_pid", Format: "dc+sd-jwt",
			Meta: openid4vp.MetaQuery{VCTValues: []string{"urn:eudi:pid:1"}},
		}}}
	}

	// Requesting "pid_alias" must not pull in "pid"'s URL, even though "pid"
	// sorts first and shares the vct.
	alias := query()
	client.augmentVCTValuesFromConfig(alias, []string{"pid_alias"})
	assert.Equal(t, []string{"urn:eudi:pid:1", aliasURL}, alias.Credentials[0].Meta.VCTValues)
	assert.NotContains(t, alias.Credentials[0].Meta.VCTValues, pidURL)

	// And the converse.
	pid := query()
	client.augmentVCTValuesFromConfig(pid, []string{"pid"})
	assert.Equal(t, []string{"urn:eudi:pid:1", pidURL}, pid.Credentials[0].Meta.VCTValues)
	assert.NotContains(t, pid.Credentials[0].Meta.VCTValues, aliasURL)

	// A request naming no configured credential scope augments nothing.
	none := query()
	client.augmentVCTValuesFromConfig(none, []string{"profile", "openid"})
	assert.Equal(t, []string{"urn:eudi:pid:1"}, none.Credentials[0].Meta.VCTValues)

	// Both aliases requested: both contribute, rather than sort order silently
	// dropping one the caller asked for. Nothing here was not requested.
	both := query()
	client.augmentVCTValuesFromConfig(both, []string{"pid", "pid_alias"})
	assert.Equal(t, []string{"urn:eudi:pid:1", pidURL, aliasURL}, both.Credentials[0].Meta.VCTValues)

	// Order of the requested scopes must not change the result.
	reversed := query()
	client.augmentVCTValuesFromConfig(reversed, []string{"pid_alias", "pid"})
	assert.Equal(t, both.Credentials[0].Meta.VCTValues, reversed.Credentials[0].Meta.VCTValues)

	// Neither alias requested: the identifier has two owners and nothing
	// distinguishes them, so guessing would widen the query. Left untouched.
	ambiguous := query()
	client.augmentVCTValuesFromConfig(ambiguous, []string{"pid_full"})
	assert.Equal(t, []string{"urn:eudi:pid:1"}, ambiguous.Credentials[0].Meta.VCTValues)
}

// TestAugmentVCTValuesTemplateAliasScope covers the shape half the shipped
// templates actually have, and which a requested-scope-only rule silently left
// un-augmented - the bug this augmentation exists to remove.
//
// eudi_pid_full triggers on the OIDC scope "pid_full" while the credential is
// configured as "pid"; the eduID full/age templates do the same. The requested
// scope is therefore not a credential_metadata key at all, so the query has to
// be paired with the sole configured owner of the identifier it names.
func TestAugmentVCTValuesTemplateAliasScope(t *testing.T) {
	client := dcqlClientFor(t, map[string]*model.CredentialMetadata{
		"pid": sdJWTScope("urn:eudi:pid:1"),
	}, nil)

	dcql := &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{{
		ID: "eudi_pid", Format: "dc+sd-jwt",
		Meta: openid4vp.MetaQuery{VCTValues: []string{"urn:eudi:pid:1"}},
	}}}

	// "pid_full" is an OIDC scope, not a configured credential scope.
	client.augmentVCTValuesFromConfig(dcql, []string{"pid_full"})
	assert.Equal(t,
		[]string{"urn:eudi:pid:1", "https://apigw.example/type-metadata/pid"},
		dcql.Credentials[0].Meta.VCTValues,
	)
}

// TestCreateDCQLQueryRejectsUnusableConfiguredScope covers the guard that runs
// before either builder.
//
// The template path used to return successfully whenever a template matched one
// requested scope, without looking at the others: a request for "pid" plus a
// configured ldp_vc scope produced a PID-only query while authCtx.Scopes kept
// both, so VerificationDirectPost waited for a VP token nobody had been asked
// for and failed only after the user completed a presentation.
func TestCreateDCQLQueryRejectsUnusableConfiguredScope(t *testing.T) {
	client := dcqlClientFor(t, map[string]*model.CredentialMetadata{
		"pid":         sdJWTScope("urn:eudi:pid:1"),
		"diploma_ldp": w3cScope("urn:eudi:diploma:1"),
	}, nil)

	_, err := client.createDCQLQuery(t.Context(), []string{"pid", "diploma_ldp"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "diploma_ldp")

	// Unconfigured scopes are not this check's business.
	dcql, err := client.createDCQLQuery(t.Context(), []string{"pid", "profile", "openid"})
	require.NoError(t, err)
	require.Len(t, dcql.Credentials, 1)
}

// TestCreateDCQLQueryFallsBackWhenNoTemplateMatches covers a review finding
// about the presentation-builder branch.
//
// BuildDCQLQuery cannot say "no template matched" through its signature: it
// returns a non-nil generic placeholder that constrains nothing (empty
// vct_values) and hardcodes format vc+sd-jwt. A plain nil check therefore
// accepted it, which made the config fallback unreachable for every deployment
// with presentation_requests configured - so a configured mso_mdoc scope with
// no template of its own was asked for with an unconstrained vc+sd-jwt query
// instead of its doctype.
func TestCreateDCQLQueryFallsBackWhenNoTemplateMatches(t *testing.T) {
	client := dcqlClientFor(t, map[string]*model.CredentialMetadata{
		"pid_mdoc": {Format: "mso_mdoc", MDDL: &mdoc.MDDLSchema{DocType: "eu.europa.ec.eudi.pid.1"}},
	}, nil)

	// A builder with no templates at all: nothing can match.
	builder := openid4vp.NewPresentationBuilder([]openid4vp.PresentationRequestTemplate(nil))
	client.presentationBuilder = builder

	// The two builder entry points disagree on purpose, and that disagreement
	// is the bug: BuildDCQLQuery hands back a non-nil placeholder that reads
	// like success, while TemplateDCQLQuery says plainly that nothing matched.
	generic, err := builder.BuildDCQLQuery(t.Context(), []string{"pid_mdoc"})
	require.NoError(t, err)
	require.NotNil(t, generic, "the placeholder is non-nil, which is what made a nil check insufficient")
	_, matched := builder.TemplateDCQLQuery(t.Context(), []string{"pid_mdoc"})
	require.False(t, matched)

	dcql, err := client.createDCQLQuery(t.Context(), []string{"pid_mdoc"})
	require.NoError(t, err)
	require.Len(t, dcql.Credentials, 1)
	assert.Equal(t, "pid_mdoc", dcql.Credentials[0].ID)
	assert.Equal(t, "eu.europa.ec.eudi.pid.1", dcql.Credentials[0].Meta.DoctypeValue)
	assert.Empty(t, dcql.Credentials[0].Meta.VCTValues)
	assert.NoError(t, openid4vp.ValidateCredentialQuery(dcql.Credentials[0]))
}
