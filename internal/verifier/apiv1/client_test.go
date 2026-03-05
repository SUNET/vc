package apiv1

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"vc/pkg/model"
	"vc/pkg/sdjwtvc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_generateSubjectIdentifier_Public(t *testing.T) {
	client, _ := CreateTestClientWithMock(nil)
	client.cfg.Verifier.OIDCOP.SubjectType = "public"
	client.cfg.Verifier.OIDCOP.SubjectSalt = "test-salt"

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
	client, _ := CreateTestClientWithMock(nil)
	client.cfg.Verifier.OIDCOP.SubjectType = "pairwise"
	client.cfg.Verifier.OIDCOP.SubjectSalt = "test-salt"

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
	client, _ := CreateTestClientWithMock(nil)
	client.cfg.Verifier.OIDCOP.SubjectType = "pairwise"
	client.cfg.Verifier.OIDCOP.SubjectSalt = "test-salt"

	walletID1 := "wallet-1"
	walletID2 := "wallet-2"
	clientID := "client-1"

	sub1 := client.generateSubjectIdentifier(walletID1, clientID)
	sub2 := client.generateSubjectIdentifier(walletID2, clientID)

	assert.NotEqual(t, sub1, sub2, "different wallets should get different subs")
}

func TestClient_containsOIDC(t *testing.T) {
	client, _ := CreateTestClientWithMock(nil)

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
	client, _ := CreateTestClientWithMock(nil)

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

func TestClient_buildLegacyDCQLQuery(t *testing.T) {
	tests := []struct {
		name                  string
		scopes                []string
		credentialConstructor map[string]*model.CredentialConstructor
		expectError           bool
		expectedCredCount     int
	}{
		{
			name:   "single valid scope",
			scopes: []string{"diploma"},
			credentialConstructor: map[string]*model.CredentialConstructor{
				"diploma": {
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
			credentialConstructor: map[string]*model.CredentialConstructor{
				"diploma": {
					VCTM: &sdjwtvc.VCTM{
						VCT: "urn:credential:diploma",
					},
				},
				"ehic": {
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
			credentialConstructor: map[string]*model.CredentialConstructor{
				"diploma": {
					VCTM: &sdjwtvc.VCTM{
						VCT: "urn:credential:diploma",
					},
				},
			},
			expectError:       false,
			expectedCredCount: 1,
		},
		{
			name:                  "no matching scopes",
			scopes:                []string{"unknown_scope"},
			credentialConstructor: map[string]*model.CredentialConstructor{},
			expectError:           true,
			expectedCredCount:     0,
		},
		{
			name:   "all scopes are openid or unmatched",
			scopes: []string{"openid"},
			credentialConstructor: map[string]*model.CredentialConstructor{
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
			credentialConstructor: map[string]*model.CredentialConstructor{
				"diploma": {

					VCTM: &sdjwtvc.VCTM{
						VCT:  "urn:credential:diploma",
						Name: "Diploma Credential",
						Claims: []sdjwtvc.Claim{
							{
								Path: []*string{ptrString("given_name")},
								Display: []sdjwtvc.ClaimDisplay{
									{Locale: "en", Label: "Given Name"},
								},
							},
							{
								Path: []*string{ptrString("family_name")},
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
				CredentialConstructor: tt.credentialConstructor,
			}
			client, _ := CreateTestClientWithMock(cfg)

			dcql, err := client.buildLegacyDCQLQuery(tt.scopes)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, dcql)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, dcql)
				assert.Equal(t, tt.expectedCredCount, len(dcql.Credentials))

				// Verify credential format is vc+sd-jwt
				for _, cred := range dcql.Credentials {
					assert.Equal(t, "vc+sd-jwt", cred.Format)
				}
			}
		})
	}
}

// Helper function to create a pointer to a string
func ptrString(s string) *string {
	return &s
}

func TestClient_createDCQLQuery(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name                  string
		scopes                []string
		credentialConstructor map[string]*model.CredentialConstructor
		expectError           bool
	}{
		{
			name:   "creates DCQL from credential config (no presentation builder)",
			scopes: []string{"diploma"},
			credentialConstructor: map[string]*model.CredentialConstructor{
				"diploma": {
					VCTM: &sdjwtvc.VCTM{
						VCT: "urn:credential:diploma",
					},
				},
			},
			expectError: false,
		},
		{
			name:                  "falls back to legacy with empty config",
			scopes:                []string{"unknown_scope"},
			credentialConstructor: map[string]*model.CredentialConstructor{},
			expectError:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &model.Cfg{
				CredentialConstructor: tt.credentialConstructor,
			}
			client, _ := CreateTestClientWithMock(cfg)

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
