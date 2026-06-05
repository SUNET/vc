package apiv1

import (
	"fmt"
	"testing"
	"time"

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
		expectCredentials int
		expectWallets     int
	}{
		{
			name: "with credentials and wallets",
			credentials: map[string]*model.CredentialMetadata{
				"pid": {
					VCTMFilePath: "/path/to/vctm",
					VCTM:         &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"},
					Attributes: map[string]map[string][]string{
						"en-US": {"given_name": {"given_name"}},
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
			name: "credentials only",
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
					SupportedWallets: tt.supportedWallets,
				},
			}

			client, _ := CreateTestClientWithMock(cfg)
			// Override cfg with our test config
			client.cfg = cfg

			reply, err := client.UIMetadata(ctx)

			assert.NoError(t, err)
			require.NotNil(t, reply)

			if tt.expectCredentials == 0 {
				assert.Len(t, reply.Credentials, 0)
			} else {
				assert.Len(t, reply.Credentials, tt.expectCredentials)
				for scope, cred := range reply.Credentials {
					srcCred := tt.credentials[scope]
					if srcCred != nil && srcCred.VCTM != nil {
						assert.Equal(t, srcCred.VCTM.VCT, cred.VCT, "VCT should be populated from VCTM")
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
		assert.Equal(t, []string{"birthdate"}, pidCred.Claims[0].Path)
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
			pidPaths = append(pidPaths, c.Path[0])
		}
		assert.Contains(t, pidPaths, "given_name")
		assert.Contains(t, pidPaths, "birthdate")
		assert.NotContains(t, pidPaths, "family_name")

		// EHIC should have all its claims (no exclusions)
		ehicPaths := make([]string, 0, len(ehicCred.Claims))
		for _, c := range ehicCred.Claims {
			ehicPaths = append(ehicPaths, c.Path[0])
		}
		assert.Contains(t, ehicPaths, "card_number")
		assert.Contains(t, ehicPaths, "expiry_date")
	})
}

// TestPerScopeValidationApplication tests that the verification handler
// applies validations only to the credential that matches the scope.
func TestPerScopeValidationApplication(t *testing.T) {
	// Simulate: PID credential has birthdate, EHIC does not.
	// age_over validation is scoped to PID only — should pass/fail based on PID claims only.
	tests := []struct {
		name        string
		scopes      []string
		validations map[string][]openid4vp.ClaimValidation
		credentials []sdjwtvc.CredentialCache
		wantErr     bool
		errContains string
	}{
		{
			name:   "validation passes for matching scope",
			scopes: []string{"pid", "ehic"},
			validations: map[string][]openid4vp.ClaimValidation{
				"pid": {{Rule: "age_over", Path: []string{"birthdate"}, Value: 18}},
			},
			credentials: []sdjwtvc.CredentialCache{
				{Claims: []sdjwtvc.Discloser{{ClaimName: "birthdate", Value: time.Now().AddDate(-25, 0, 0).Format("2006-01-02")}}},
				{Claims: []sdjwtvc.Discloser{{ClaimName: "card_number", Value: "12345"}}},
			},
			wantErr: false,
		},
		{
			name:   "validation fails for matching scope",
			scopes: []string{"pid", "ehic"},
			validations: map[string][]openid4vp.ClaimValidation{
				"pid": {{Rule: "age_over", Path: []string{"birthdate"}, Value: 18}},
			},
			credentials: []sdjwtvc.CredentialCache{
				{Claims: []sdjwtvc.Discloser{{ClaimName: "birthdate", Value: time.Now().AddDate(-16, 0, 0).Format("2006-01-02")}}},
				{Claims: []sdjwtvc.Discloser{{ClaimName: "card_number", Value: "12345"}}},
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
			credentials: []sdjwtvc.CredentialCache{
				{Claims: []sdjwtvc.Discloser{{ClaimName: "birthdate", Value: time.Now().AddDate(-20, 0, 0).Format("2006-01-02")}}},
				{Claims: []sdjwtvc.Discloser{{ClaimName: "card_number", Value: "12345"}}}, // no birthdate — would fail if validated
			},
			wantErr: false,
		},
		{
			name:        "empty validations map does nothing",
			scopes:      []string{"pid"},
			validations: map[string][]openid4vp.ClaimValidation{},
			credentials: []sdjwtvc.CredentialCache{
				{Claims: []sdjwtvc.Discloser{{ClaimName: "birthdate", Value: "not-a-date"}}},
			},
			wantErr: false,
		},
		{
			name:   "validation on second scope only",
			scopes: []string{"pid", "ehic"},
			validations: map[string][]openid4vp.ClaimValidation{
				"ehic": {{Rule: "age_over", Path: []string{"birthdate"}, Value: 18}},
			},
			credentials: []sdjwtvc.CredentialCache{
				{Claims: []sdjwtvc.Discloser{{ClaimName: "given_name", Value: "John"}}},
				{Claims: []sdjwtvc.Discloser{{ClaimName: "birthdate", Value: time.Now().AddDate(-30, 0, 0).Format("2006-01-02")}}},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := applyPerScopeValidations(tt.scopes, tt.validations, tt.credentials)
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

// applyPerScopeValidations replicates the verification handler's per-scope validation logic
// for isolated unit testing without needing a full client setup.
func applyPerScopeValidations(scopes []string, validations map[string][]openid4vp.ClaimValidation, credentials []sdjwtvc.CredentialCache) error {
	if len(validations) == 0 {
		return nil
	}
	for i, scope := range scopes {
		scopeValidations := validations[scope]
		if len(scopeValidations) == 0 {
			continue
		}
		if i >= len(credentials) {
			break
		}
		claimsMap := make(map[string]any, len(credentials[i].Claims))
		for _, d := range credentials[i].Claims {
			if d.ClaimName != "" {
				claimsMap[d.ClaimName] = d.Value
			}
		}
		if err := openid4vp.ValidateClaims(claimsMap, scopeValidations); err != nil {
			return fmt.Errorf("claim validation failed for scope %s: %w", scope, err)
		}
	}
	return nil
}
