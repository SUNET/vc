package apiv1

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUIMetadata tests the UIMetadata handler
func TestUIMetadata(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name              string
		credentials       map[string]*model.CredentialMetadata
		supportedWallets  map[string]string
		dcAPIEnabled      bool
		expectCredentials int
		expectWallets     int
	}{
		{
			name:         "with credentials and wallets",
			dcAPIEnabled: true,
			credentials: map[string]*model.CredentialMetadata{
				"pid": {
					VCTMFilePath: "/path/to/vctm",
					VCTM:         &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"},
					Attributes: map[string]map[string][]*string{
						"en-US": {"given_name": {new("given_name")}},
					},
				},
				"diploma": {
					VCTMFilePath: "/path/to/diploma_vctm",
					VCTM:         &sdjwtvc.VCTM{VCT: "urn:eudi:diploma:1"},
				},
			},
			supportedWallets: map[string]string{
				"eudiw":    "https://eudiw.example.com",
				"wwwallet": "https://wwwallet.example.com",
			},
			expectCredentials: 2,
			expectWallets:     2,
		},
		{
			name:              "empty credentials and wallets",
			credentials:       nil,
			supportedWallets:  nil,
			expectCredentials: 0,
			expectWallets:     0,
		},
		{
			name:         "credentials only",
			dcAPIEnabled: true,
			credentials: map[string]*model.CredentialMetadata{
				"ehic": {
					VCTM: &sdjwtvc.VCTM{VCT: "urn:eudi:ehic:1"},
				},
			},
			supportedWallets:  nil,
			expectCredentials: 1,
			expectWallets:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &model.Cfg{
				Common: &model.Common{
					CredentialMetadata: tt.credentials,
				},
				Verifier: &model.Verifier{
					SupportedWallets:   tt.supportedWallets,
					DigitalCredentials: model.DigitalCredentialsConfig{Enable: tt.dcAPIEnabled},
				},
			}

			client, _ := CreateTestClientWithMock(cfg)
			// Override cfg with our test config
			client.cfg = cfg

			reply, err := client.UIMetadata(ctx)

			assert.NoError(t, err)
			require.NotNil(t, reply)

			assert.Equal(t, tt.dcAPIEnabled, reply.DCAPIEnabled, "DCAPIEnabled should mirror verifier.digital_credentials.enable")

			if tt.expectCredentials == 0 {
				assert.Len(t, reply.Credentials, 0)
			} else {
				assert.Len(t, reply.Credentials, tt.expectCredentials)
				for scope, cred := range reply.Credentials {
					srcCred := tt.credentials[scope]
					if srcCred != nil {
						assert.Equal(t, srcCred.Format, cred.Format, "Format should be populated from credential metadata")
						if srcCred.VCTM != nil {
							assert.Equal(t, srcCred.VCTM.VCT, cred.VCT, "VCT should be populated from VCTM")
						}
					}
				}
			}

			if tt.expectWallets == 0 {
				assert.Len(t, reply.SupportedWallets, 0)
			} else {
				assert.Len(t, reply.SupportedWallets, tt.expectWallets)
			}
		})
	}
}

// TestUIMetadata_MsoMdocScope verifies that mso_mdoc scopes (which have no
// VCTM) still surface a usable VCT (the doctype) and non-empty Attributes,
// derived from the loaded MDDL schema rather than being left empty.
func TestUIMetadata_MsoMdocScope(t *testing.T) {
	ctx := t.Context()

	schema := &mdoc.MDDLSchema{
		Format:  "mso_mdoc",
		DocType: "org.iso.18013.5.1.mDL",
		Claims: map[string]mdoc.NamespaceClaims{
			"org.iso.18013.5.1": {
				"family_name": {Mandatory: true, ValueType: "tstr"},
			},
		},
	}

	cfg := &model.Cfg{
		Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				"mdl": {
					Format:     "mso_mdoc",
					MDDL:       schema,
					Attributes: schema.Attributes(),
				},
			},
		},
		Verifier: &model.Verifier{},
	}

	client, _ := CreateTestClientWithMock(cfg)
	client.cfg = cfg

	reply, err := client.UIMetadata(ctx)
	require.NoError(t, err)
	require.NotNil(t, reply)

	info, ok := reply.Credentials["mdl"]
	require.True(t, ok, "mdl scope should be present")
	assert.Equal(t, "org.iso.18013.5.1.mDL", info.VCT, "VCT should fall back to the MDDL doctype")
	assert.NotEmpty(t, info.Attributes, "Attributes should be derived from the MDDL schema, not left empty")
}

// TestUIMetadataPresetValidationsPerScope verifies that validations are attached
// to the correct credential within a preset, not flattened across all credentials.
func TestUIMetadataPresetValidationsPerScope(t *testing.T) {
	ctx := t.Context()

	cfg := &model.Cfg{
		Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				"pid": {
					Format: "dc+sd-jwt",
					VCTM: &sdjwtvc.VCTM{
						VCT: "urn:eudi:pid:1",
						Claims: []sdjwtvc.Claim{
							{Path: []*string{new("given_name")}},
							{Path: []*string{new("family_name")}},
							{Path: []*string{new("birthdate")}},
						},
					},
				},
				"ehic": {
					Format: "dc+sd-jwt",
					VCTM: &sdjwtvc.VCTM{
						VCT: "urn:eudi:ehic:1",
						Claims: []sdjwtvc.Claim{
							{Path: []*string{new("card_number")}},
							{Path: []*string{new("expiry_date")}},
						},
					},
				},
			},
		},
		Verifier: &model.Verifier{
			Presets: map[string]model.VerificationPreset{
				"PID Age Over 18": {
					"pid": &model.VerificationPresetScope{
						Claims: []model.VerificationPresetClaim{
							{Path: []string{"birthdate"}},
						},
						Validations: []openid4vp.ClaimValidation{
							{Rule: "age_over", Path: []string{"birthdate"}, Value: 18},
						},
					},
				},
				"PID + EHIC": {
					"pid": &model.VerificationPresetScope{
						ExcludeClaims: []model.VerificationPresetClaim{
							{Path: []string{"family_name"}},
						},
						Validations: []openid4vp.ClaimValidation{
							{Rule: "age_over", Path: []string{"birthdate"}, Value: 21},
						},
					},
					"ehic": nil, // no overrides, no validations
				},
			},
		},
	}

	client, _ := CreateTestClientWithMock(cfg)
	client.cfg = cfg

	reply, err := client.UIMetadata(ctx)
	require.NoError(t, err)
	require.NotNil(t, reply)

	t.Run("single scope preset has validations on credential", func(t *testing.T) {
		preset := reply.Presets["PID Age Over 18"]
		require.NotNil(t, preset)
		require.Len(t, preset.Credentials, 1)

		pidCred := preset.Credentials[0]
		assert.Equal(t, "pid", pidCred.ID)
		require.Len(t, pidCred.Validations, 1)
		assert.Equal(t, "age_over", pidCred.Validations[0].Rule)
		assert.Equal(t, 18, pidCred.Validations[0].Value)

		// Only explicit claims should be included (birthdate), others excluded
		require.Len(t, pidCred.Claims, 1)
		require.Len(t, pidCred.Claims[0].Path, 1)
		require.NotNil(t, pidCred.Claims[0].Path[0])
		assert.Equal(t, "birthdate", *pidCred.Claims[0].Path[0])
	})

	t.Run("multi scope preset scopes validations correctly", func(t *testing.T) {
		preset := reply.Presets["PID + EHIC"]
		require.NotNil(t, preset)
		require.Len(t, preset.Credentials, 2)

		// Find PID and EHIC credentials
		var pidCred, ehicCred *UIPresetCredential
		for i := range preset.Credentials {
			switch preset.Credentials[i].ID {
			case "pid":
				pidCred = &preset.Credentials[i]
			case "ehic":
				ehicCred = &preset.Credentials[i]
			}
		}
		require.NotNil(t, pidCred, "PID credential should exist")
		require.NotNil(t, ehicCred, "EHIC credential should exist")

		// PID should have validations
		require.Len(t, pidCred.Validations, 1)
		assert.Equal(t, "age_over", pidCred.Validations[0].Rule)
		assert.Equal(t, 21, pidCred.Validations[0].Value)

		// EHIC should have NO validations
		assert.Empty(t, ehicCred.Validations)
	})

	t.Run("multi scope preset excludes claims only from target scope", func(t *testing.T) {
		preset := reply.Presets["PID + EHIC"]
		require.NotNil(t, preset)

		var pidCred, ehicCred *UIPresetCredential
		for i := range preset.Credentials {
			switch preset.Credentials[i].ID {
			case "pid":
				pidCred = &preset.Credentials[i]
			case "ehic":
				ehicCred = &preset.Credentials[i]
			}
		}

		// PID should exclude family_name, have given_name and birthdate
		pidPaths := make([]string, 0, len(pidCred.Claims))
		for _, c := range pidCred.Claims {
			if c.Path[0] != nil {
				pidPaths = append(pidPaths, *c.Path[0])
			}
		}
		assert.Contains(t, pidPaths, "given_name")
		assert.Contains(t, pidPaths, "birthdate")
		assert.NotContains(t, pidPaths, "family_name")

		// EHIC should have all its claims (no exclusions)
		ehicPaths := make([]string, 0, len(ehicCred.Claims))
		for _, c := range ehicCred.Claims {
			if c.Path[0] != nil {
				ehicPaths = append(ehicPaths, *c.Path[0])
			}
		}
		assert.Contains(t, ehicPaths, "card_number")
		assert.Contains(t, ehicPaths, "expiry_date")
	})
}

// TestUIMetadataPresetFormatFromMetadata verifies that the preset credential
// format is taken from credential_metadata (which is normalized at load time).
func TestUIMetadataPresetFormatFromMetadata(t *testing.T) {
	ctx := t.Context()

	cfg := &model.Cfg{
		Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				"pid": {
					Format: openid4vp.FormatSDJWTVC, // already normalized by LoadCredentialSchema
					VCTM:   &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"},
				},
			},
		},
		Verifier: &model.Verifier{
			Presets: map[string]model.VerificationPreset{
				"PID": {
					"pid": nil,
				},
			},
		},
	}

	client, _ := CreateTestClientWithMock(cfg)
	client.cfg = cfg

	reply, err := client.UIMetadata(ctx)
	require.NoError(t, err)
	require.NotNil(t, reply)

	preset := reply.Presets["PID"]
	require.NotNil(t, preset)
	require.Len(t, preset.Credentials, 1)
	assert.Equal(t, openid4vp.FormatSDJWTVC, preset.Credentials[0].Format)
}

// TestUIMetadataCredentialFormatFromMetadata verifies that each credential
// advertised to the UI carries the format from credential_metadata, so custom
// presentation requests can use the correct DCQL format (e.g. mso_mdoc).
func TestUIMetadataCredentialFormatFromMetadata(t *testing.T) {
	ctx := t.Context()

	cfg := &model.Cfg{
		Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				"pid": {
					Format: openid4vp.FormatSDJWTVC,
					VCTM:   &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"},
				},
				"mdl": {
					Format: openid4vp.FormatMsoMdoc,
					VCTM:   &sdjwtvc.VCTM{VCT: "org.iso.18013.5.1.mDL"},
				},
			},
		},
		Verifier: &model.Verifier{},
	}

	client, _ := CreateTestClientWithMock(cfg)
	client.cfg = cfg

	reply, err := client.UIMetadata(ctx)
	require.NoError(t, err)
	require.NotNil(t, reply)

	require.Len(t, reply.Credentials, 2)
	assert.Equal(t, openid4vp.FormatSDJWTVC, reply.Credentials["pid"].Format)
	assert.Equal(t, openid4vp.FormatMsoMdoc, reply.Credentials["mdl"].Format)
}

// TestAugmentDCQLFromVCTM_ArraySelectiveDisclosure verifies that augmentDCQLFromVCTM
// removes the parent path when an array-element path (with null) is also present,
// so the wallet discloses individual array elements instead of only the opaque parent.
func TestAugmentDCQLFromVCTM_ArraySelectiveDisclosure(t *testing.T) {
	tests := []struct {
		name          string
		vctmClaims    []sdjwtvc.Claim
		inputClaims   []openid4vp.ClaimQuery
		expectedPaths [][]*string
		removedPaths  [][]*string
	}{
		{
			name: "parent removed when array-element path present",
			vctmClaims: []sdjwtvc.Claim{
				{Path: []*string{new("nationalities")}},
				{Path: []*string{new("nationalities"), nil}},
			},
			inputClaims: []openid4vp.ClaimQuery{
				{Path: []*string{new("nationalities")}},
				{Path: []*string{new("nationalities"), nil}},
			},
			expectedPaths: [][]*string{
				{new("nationalities"), nil},
			},
			removedPaths: [][]*string{
				{new("nationalities")},
			},
		},
		{
			name: "array-element path only - no change",
			vctmClaims: []sdjwtvc.Claim{
				{Path: []*string{new("nationalities")}},
				{Path: []*string{new("nationalities"), nil}},
			},
			inputClaims: []openid4vp.ClaimQuery{
				{Path: []*string{new("nationalities"), nil}},
			},
			expectedPaths: [][]*string{
				{new("nationalities"), nil},
			},
		},
		{
			name: "parent only without array-element path - no change",
			vctmClaims: []sdjwtvc.Claim{
				{Path: []*string{new("nationalities")}},
				{Path: []*string{new("nationalities"), nil}},
			},
			inputClaims: []openid4vp.ClaimQuery{
				{Path: []*string{new("nationalities")}},
			},
			expectedPaths: [][]*string{
				{new("nationalities")},
			},
		},
		{
			name: "nested object parent replaced with children",
			vctmClaims: []sdjwtvc.Claim{
				{Path: []*string{new("address")}},
				{Path: []*string{new("address"), new("street")}},
				{Path: []*string{new("address"), new("city")}},
			},
			inputClaims: []openid4vp.ClaimQuery{
				{Path: []*string{new("address")}},
			},
			expectedPaths: [][]*string{
				{new("address"), new("street")},
				{new("address"), new("city")},
			},
			removedPaths: [][]*string{
				{new("address")},
			},
		},
		{
			name: "mixed: array and simple claims coexist",
			vctmClaims: []sdjwtvc.Claim{
				{Path: []*string{new("given_name")}},
				{Path: []*string{new("nationalities")}},
				{Path: []*string{new("nationalities"), nil}},
			},
			inputClaims: []openid4vp.ClaimQuery{
				{Path: []*string{new("given_name")}},
				{Path: []*string{new("nationalities")}},
				{Path: []*string{new("nationalities"), nil}},
			},
			expectedPaths: [][]*string{
				{new("given_name")},
				{new("nationalities"), nil},
			},
			removedPaths: [][]*string{
				{new("nationalities")},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &model.Cfg{
				Common: &model.Common{
					CredentialMetadata: map[string]*model.CredentialMetadata{
						"pid": {
							VCTM: &sdjwtvc.VCTM{
								VCT:    "urn:eudi:pid:1",
								Claims: tt.vctmClaims,
							},
						},
					},
				},
				Verifier: &model.Verifier{},
			}

			client, _ := CreateTestClientWithMock(cfg)
			client.cfg = cfg

			dcql := &openid4vp.DCQL{
				Credentials: []openid4vp.CredentialQuery{
					{
						ID:     "pid",
						Format: "dc+sd-jwt",
						Claims: tt.inputClaims,
					},
				},
			}

			client.augmentDCQLFromVCTM(dcql)

			resultPaths := make([][]*string, 0, len(dcql.Credentials[0].Claims))
			for _, claim := range dcql.Credentials[0].Claims {
				resultPaths = append(resultPaths, claim.Path)
			}

			// Check expected paths are present
			require.Len(t, resultPaths, len(tt.expectedPaths), "unexpected number of claims")
			for i, expected := range tt.expectedPaths {
				require.Len(t, resultPaths[i], len(expected), "path %d has wrong length", i)
				for j, seg := range expected {
					if seg == nil {
						assert.Nil(t, resultPaths[i][j], "path[%d][%d] should be nil", i, j)
					} else {
						require.NotNil(t, resultPaths[i][j], "path[%d][%d] should not be nil", i, j)
						assert.Equal(t, *seg, *resultPaths[i][j], "path[%d][%d] mismatch", i, j)
					}
				}
			}

			// Check removed paths are absent
			for _, removed := range tt.removedPaths {
				for _, resultPath := range resultPaths {
					if len(resultPath) != len(removed) {
						continue
					}
					match := true
					for j, seg := range removed {
						if seg == nil && resultPath[j] != nil {
							match = false
						} else if seg != nil && (resultPath[j] == nil || *seg != *resultPath[j]) {
							match = false
						}
					}
					assert.False(t, match, "path %v should have been removed", removed)
				}
			}
		})
	}
}

// TestPerScopeValidationApplication tests that the verification handler
// applies validations only to the credential that matches the scope.
func TestPerScopeValidationApplication(t *testing.T) {
	// Simulate: PID credential has birthdate, EHIC does not.
	// age_over validation is scoped to PID only — should pass/fail based on PID claims only.
	tests := []struct {
		name             string
		scopes           []string
		validations      map[string][]openid4vp.ClaimValidation
		scopeCredentials map[string][]sdjwtvc.CredentialCache
		wantErr          bool
		errContains      string
	}{
		{
			name:   "validation passes for matching scope",
			scopes: []string{"pid", "ehic"},
			validations: map[string][]openid4vp.ClaimValidation{
				"pid": {{Rule: "age_over", Path: []string{"birthdate"}, Value: 18}},
			},
			scopeCredentials: map[string][]sdjwtvc.CredentialCache{
				"pid":  {{Credential: map[string]any{"birthdate": time.Now().UTC().AddDate(-25, 0, 0).Format("2006-01-02")}}},
				"ehic": {{Credential: map[string]any{"card_number": "12345"}}},
			},
			wantErr: false,
		},
		{
			name:   "validation fails for matching scope",
			scopes: []string{"pid", "ehic"},
			validations: map[string][]openid4vp.ClaimValidation{
				"pid": {{Rule: "age_over", Path: []string{"birthdate"}, Value: 18}},
			},
			scopeCredentials: map[string][]sdjwtvc.CredentialCache{
				"pid":  {{Credential: map[string]any{"birthdate": time.Now().UTC().AddDate(-16, 0, 0).Format("2006-01-02")}}},
				"ehic": {{Credential: map[string]any{"card_number": "12345"}}},
			},
			wantErr:     true,
			errContains: "scope pid",
		},
		{
			name:   "no validation on EHIC even though claim missing",
			scopes: []string{"pid", "ehic"},
			validations: map[string][]openid4vp.ClaimValidation{
				"pid": {{Rule: "age_over", Path: []string{"birthdate"}, Value: 18}},
			},
			scopeCredentials: map[string][]sdjwtvc.CredentialCache{
				"pid":  {{Credential: map[string]any{"birthdate": time.Now().UTC().AddDate(-20, 0, 0).Format("2006-01-02")}}},
				"ehic": {{Credential: map[string]any{"card_number": "12345"}}}, // no birthdate — would fail if validated
			},
			wantErr: false,
		},
		{
			name:        "empty validations map does nothing",
			scopes:      []string{"pid"},
			validations: map[string][]openid4vp.ClaimValidation{},
			scopeCredentials: map[string][]sdjwtvc.CredentialCache{
				"pid": {{Credential: map[string]any{"birthdate": "not-a-date"}}},
			},
			wantErr: false,
		},
		{
			name:   "validation on second scope only",
			scopes: []string{"pid", "ehic"},
			validations: map[string][]openid4vp.ClaimValidation{
				"ehic": {{Rule: "age_over", Path: []string{"birthdate"}, Value: 18}},
			},
			scopeCredentials: map[string][]sdjwtvc.CredentialCache{
				"pid":  {{Credential: map[string]any{"given_name": "John"}}},
				"ehic": {{Credential: map[string]any{"birthdate": time.Now().UTC().AddDate(-30, 0, 0).Format("2006-01-02")}}},
			},
			wantErr: false,
		},
		{
			name:   "multiple credentials per scope all pass",
			scopes: []string{"pid"},
			validations: map[string][]openid4vp.ClaimValidation{
				"pid": {{Rule: "age_over", Path: []string{"birthdate"}, Value: 18}},
			},
			scopeCredentials: map[string][]sdjwtvc.CredentialCache{
				"pid": {
					{Credential: map[string]any{"birthdate": time.Now().UTC().AddDate(-25, 0, 0).Format("2006-01-02")}},
					{Credential: map[string]any{"birthdate": time.Now().UTC().AddDate(-30, 0, 0).Format("2006-01-02")}},
				},
			},
			wantErr: false,
		},
		{
			name:   "multiple credentials per scope second fails",
			scopes: []string{"pid"},
			validations: map[string][]openid4vp.ClaimValidation{
				"pid": {{Rule: "age_over", Path: []string{"birthdate"}, Value: 18}},
			},
			scopeCredentials: map[string][]sdjwtvc.CredentialCache{
				"pid": {
					{Credential: map[string]any{"birthdate": time.Now().UTC().AddDate(-25, 0, 0).Format("2006-01-02")}},
					{Credential: map[string]any{"birthdate": time.Now().UTC().AddDate(-10, 0, 0).Format("2006-01-02")}},
				},
			},
			wantErr:     true,
			errContains: "scope pid",
		},
		{
			name:   "multiple credentials per scope validation scoped correctly",
			scopes: []string{"pid", "ehic"},
			validations: map[string][]openid4vp.ClaimValidation{
				"pid": {{Rule: "age_over", Path: []string{"birthdate"}, Value: 18}},
			},
			scopeCredentials: map[string][]sdjwtvc.CredentialCache{
				"pid": {
					{Credential: map[string]any{"birthdate": time.Now().UTC().AddDate(-20, 0, 0).Format("2006-01-02")}},
					{Credential: map[string]any{"birthdate": time.Now().UTC().AddDate(-40, 0, 0).Format("2006-01-02")}},
				},
				"ehic": {
					{Credential: map[string]any{"card_number": "111"}},
					{Credential: map[string]any{"card_number": "222"}},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := applyPerScopeValidations(tt.scopes, tt.validations, tt.scopeCredentials)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestAugmentDCQLFromVCTM_ComplexCredential tests augmentDCQLFromVCTM with a credential
// containing nested objects, arrays of objects, and simple arrays — verifying correct
// path handling for each DCQL claim type.
func TestAugmentDCQLFromVCTM_ComplexCredential(t *testing.T) {
	// VCTM claims model a credential like:
	// {
	//   "name": "Arthur Dent",
	//   "address": { "street_address": "42 Market Street", "locality": "Milliways", "postal_code": "12345" },
	//   "degrees": [{ "type": "...", "university": "..." }, ...],
	//   "nationalities": ["British", "Betelgeusian"]
	// }
	vctmClaims := []sdjwtvc.Claim{
		{Path: []*string{new("name")}},
		{Path: []*string{new("address")}},
		{Path: []*string{new("address"), new("street_address")}},
		{Path: []*string{new("address"), new("locality")}},
		{Path: []*string{new("address"), new("postal_code")}},
		{Path: []*string{new("degrees")}},
		{Path: []*string{new("degrees"), nil}},
		{Path: []*string{new("degrees"), nil, new("type")}},
		{Path: []*string{new("degrees"), nil, new("university")}},
		{Path: []*string{new("nationalities")}},
		{Path: []*string{new("nationalities"), nil}},
	}

	// The credential that the DCQL paths will be resolved against.
	credential := map[string]any{
		"name": "Arthur Dent",
		"address": map[string]any{
			"street_address": "42 Market Street",
			"locality":       "Milliways",
			"postal_code":    "12345",
		},
		"degrees": []any{
			map[string]any{"type": "Bachelor of Science", "university": "University of Betelgeuse"},
			map[string]any{"type": "Master of Science", "university": "University of Betelgeuse"},
		},
		"nationalities": []any{"British", "Betelgeusian"},
	}

	tests := []struct {
		name             string
		inputClaims      []openid4vp.ClaimQuery
		expectedPaths    [][]*string
		expectedDCQLJSON []string // expected JSON for each claim after marshal
		expectedValues   []any    // expected resolved values from the credential
	}{
		{
			name: "array of objects element field: degrees null type",
			inputClaims: []openid4vp.ClaimQuery{
				{Path: []*string{new("degrees"), nil, new("type")}},
			},
			expectedPaths: [][]*string{
				{new("degrees"), nil, new("type")},
			},
			expectedDCQLJSON: []string{
				`{"path":["degrees",null,"type"]}`,
			},
			expectedValues: []any{
				[]any{"Bachelor of Science", "Master of Science"},
			},
		},
		{
			name: "simple array element: nationalities 1",
			inputClaims: []openid4vp.ClaimQuery{
				{Path: []*string{new("nationalities"), new("1")}},
			},
			expectedPaths: [][]*string{
				{new("nationalities"), new("1")},
			},
			expectedDCQLJSON: []string{
				`{"path":["nationalities","1"]}`,
			},
			expectedValues: []any{
				"Betelgeusian",
			},
		},
		{
			name: "simple scalar: name",
			inputClaims: []openid4vp.ClaimQuery{
				{Path: []*string{new("name")}},
			},
			expectedPaths: [][]*string{
				{new("name")},
			},
			expectedDCQLJSON: []string{
				`{"path":["name"]}`,
			},
			expectedValues: []any{
				"Arthur Dent",
			},
		},
		{
			name: "object parent replaced with children: address",
			inputClaims: []openid4vp.ClaimQuery{
				{Path: []*string{new("address")}},
			},
			expectedPaths: [][]*string{
				{new("address"), new("street_address")},
				{new("address"), new("locality")},
				{new("address"), new("postal_code")},
			},
			expectedDCQLJSON: []string{
				`{"path":["address","street_address"]}`,
				`{"path":["address","locality"]}`,
				`{"path":["address","postal_code"]}`,
			},
			expectedValues: []any{
				"42 Market Street",
				"Milliways",
				"12345",
			},
		},
		{
			name: "object child directly: address street_address",
			inputClaims: []openid4vp.ClaimQuery{
				{Path: []*string{new("address"), new("street_address")}},
			},
			expectedPaths: [][]*string{
				{new("address"), new("street_address")},
			},
			expectedDCQLJSON: []string{
				`{"path":["address","street_address"]}`,
			},
			expectedValues: []any{
				"42 Market Street",
			},
		},
		{
			name: "all five claims together",
			inputClaims: []openid4vp.ClaimQuery{
				{Path: []*string{new("degrees"), nil, new("type")}},
				{Path: []*string{new("nationalities"), new("1")}},
				{Path: []*string{new("name")}},
				{Path: []*string{new("address")}},
				{Path: []*string{new("address"), new("street_address")}},
			},
			expectedPaths: [][]*string{
				{new("degrees"), nil, new("type")},
				{new("nationalities"), new("1")},
				{new("name")},
				// "address" parent replaced by children from VCTM
				{new("address"), new("street_address")},
				{new("address"), new("locality")},
				{new("address"), new("postal_code")},
			},
			expectedDCQLJSON: []string{
				`{"path":["degrees",null,"type"]}`,
				`{"path":["nationalities","1"]}`,
				`{"path":["name"]}`,
				`{"path":["address","street_address"]}`,
				`{"path":["address","locality"]}`,
				`{"path":["address","postal_code"]}`,
			},
			expectedValues: []any{
				[]any{"Bachelor of Science", "Master of Science"},
				"Betelgeusian",
				"Arthur Dent",
				"42 Market Street",
				"Milliways",
				"12345",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &model.Cfg{
				Common: &model.Common{
					CredentialMetadata: map[string]*model.CredentialMetadata{
						"complex": {
							VCTM: &sdjwtvc.VCTM{
								VCT:    "urn:test:complex:1",
								Claims: vctmClaims,
							},
						},
					},
				},
				Verifier: &model.Verifier{},
			}

			client, _ := CreateTestClientWithMock(cfg)
			client.cfg = cfg

			dcql := &openid4vp.DCQL{
				Credentials: []openid4vp.CredentialQuery{
					{
						ID:     "complex",
						Format: "dc+sd-jwt",
						Claims: tt.inputClaims,
					},
				},
			}

			client.augmentDCQLFromVCTM(dcql)

			resultPaths := make([][]*string, 0, len(dcql.Credentials[0].Claims))
			for _, claim := range dcql.Credentials[0].Claims {
				resultPaths = append(resultPaths, claim.Path)
			}

			require.Len(t, resultPaths, len(tt.expectedPaths), "unexpected number of claims")
			for i, expected := range tt.expectedPaths {
				require.Len(t, resultPaths[i], len(expected), "path %d has wrong length", i)
				for j, seg := range expected {
					if seg == nil {
						assert.Nil(t, resultPaths[i][j], "path[%d][%d] should be nil", i, j)
					} else {
						require.NotNil(t, resultPaths[i][j], "path[%d][%d] should not be nil", i, j)
						assert.Equal(t, *seg, *resultPaths[i][j], "path[%d][%d] mismatch", i, j)
					}
				}
			}

			// Verify JSON serialization produces correct output (null vs "null", etc.)
			for i, claim := range dcql.Credentials[0].Claims {
				got, err := json.Marshal(claim)
				require.NoError(t, err, "claim[%d] marshal error", i)
				assert.Equal(t, tt.expectedDCQLJSON[i], string(got), "claim[%d] JSON mismatch", i)
			}

			// Verify resolved values from the credential match expectations
			for i, claim := range dcql.Credentials[0].Claims {
				resolved := openid4vp.ResolveDCQLPath(credential, claim.Path)
				assert.Equal(t, tt.expectedValues[i], resolved, "claim[%d] resolved value mismatch", i)
			}
		})
	}
}

// applyPerScopeValidations mirrors the verification handler's per-scope validation loop
// (handlers_verification.go) for isolated unit testing without a full client setup.
// Each scope maps to zero or more credentials; validations are applied against the verified
// credential claims (cc.Credential), not raw disclosures which may contain decoy entries.
func applyPerScopeValidations(scopes []string, validations map[string][]openid4vp.ClaimValidation, scopeCredentials map[string][]sdjwtvc.CredentialCache) error {
	if len(validations) == 0 {
		return nil
	}
	for _, scope := range scopes {
		scopeValidations := validations[scope]
		if len(scopeValidations) == 0 {
			continue
		}
		entries := scopeCredentials[scope]
		if len(entries) == 0 {
			return fmt.Errorf("validations configured for scope %s but no credentials were extracted", scope)
		}
		for _, cc := range entries {
			if err := openid4vp.ValidateClaims(cc.Credential, scopeValidations); err != nil {
				return fmt.Errorf("claim validation failed for scope %s: %w", scope, err)
			}
		}
	}
	return nil
}

// TestUIMetadataPrefersVCTMOverVCTURL pins the identifier the UI advertises and
// queries for to the VCTM's own vct, not the URL the VCTM is served from.
//
// These are different things and must not be conflated: a credential's vct
// claim is built from the VCTM (BuildCredentialWithSigner sets
// body["vct"] = vctm.VCT), so that is what a wallet matches a DCQL
// meta.vct_values against, whereas VCTURL is a location ResolveVCTUrls derives
// as apigwPublicURL + /type-metadata/{scope}.
//
// The existing TestUIMetadata already asserts "VCT should be populated from
// VCTM", but could not catch this: it builds CredentialMetadata directly and
// never sets VCTURL, so the empty-URL path was the only one exercised. In
// production ResolveVCTUrls guarantees VCTURL is non-empty for every
// VCTM-backed scope, which is exactly the case that regressed - the UI
// advertised https://apigw.example/type-metadata/pid for a credential whose
// vct is urn:eudi:pid:1, so every presentation started from the UI matched
// nothing.
func TestUIMetadataOffersBothVCTIdentifiers(t *testing.T) {
	ctx := t.Context()

	cfg := &model.Cfg{
		Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				// Both set, as they always are in production.
				"pid": {
					Format:       "dc+sd-jwt",
					VCTMFilePath: "/path/to/vctm",
					VCTURL:       "https://apigw.example/type-metadata/pid",
					VCTM:         &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"},
				},
				// A VCTM file with no vct: ResolveVCTUrls back-fills VCTM.VCT
				// from the URL, so both agree and the URL is still correct.
				"novct": {
					Format:       "dc+sd-jwt",
					VCTMFilePath: "/path/to/novct",
					VCTURL:       "https://apigw.example/type-metadata/novct",
					VCTM:         &sdjwtvc.VCTM{VCT: ""},
				},
			},
		},
		Verifier: &model.Verifier{
			Presets: map[string]model.VerificationPreset{
				"PID": {"pid": nil},
			},
		},
	}

	client, _ := CreateTestClientWithMock(cfg)
	client.cfg = cfg

	reply, err := client.UIMetadata(ctx)
	require.NoError(t, err)
	require.NotNil(t, reply)

	t.Run("credential info uses the VCTM vct", func(t *testing.T) {
		assert.Equal(t, "urn:eudi:pid:1", reply.Credentials["pid"].VCT,
			"the identifier a wallet matches against is the VCTM's vct, not where the VCTM is served")
	})

	t.Run("credential info offers both identifiers, VCTM vct first", func(t *testing.T) {
		assert.Equal(t,
			[]string{"urn:eudi:pid:1", "https://apigw.example/type-metadata/pid"},
			reply.Credentials["pid"].VCTValues,
			"wallets disagree on which identifier names a credential type: multipaz "+
				"matches the metadata URL, wwWallet the credential's own vct - so offer both")
	})

	t.Run("preset vct_values offer both identifiers", func(t *testing.T) {
		preset := reply.Presets["PID"]
		require.NotNil(t, preset)
		require.Len(t, preset.Credentials, 1)
		assert.Equal(t,
			[]string{"urn:eudi:pid:1", "https://apigw.example/type-metadata/pid"},
			preset.Credentials[0].Meta.VCTValues,
			"DCQL meta.vct_values is an acceptable-value list, so both forms belong in it")
	})

	t.Run("falls back to the URL when the VCTM has no vct", func(t *testing.T) {
		assert.Equal(t, "https://apigw.example/type-metadata/novct", reply.Credentials["novct"].VCT,
			"a VCTM with no vct still needs a usable identifier")
		assert.Equal(t, []string{"https://apigw.example/type-metadata/novct"},
			reply.Credentials["novct"].VCTValues,
			"ResolveVCTUrls back-fills VCTM.VCT from the URL, so the two collapse to one value")
	})
}
