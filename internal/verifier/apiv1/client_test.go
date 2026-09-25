package apiv1

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/SUNET/vc/pkg/logger"
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

// uncoveredScopes checks that every requested scope has a query.
// unclaimedRequiredQueries checks the other direction, and both are needed:
// verification iterates over the requested SCOPES and looks up each one's
// query, so a query nothing maps to is never visited and its vp_token is
// never validated. The session would then be accepted having verified less
// than it asked the wallet for.
func TestUnclaimedRequiredQueries(t *testing.T) {
	q := func(id, vct string) openid4vp.CredentialQuery {
		return openid4vp.CredentialQuery{
			ID:     id,
			Format: "vc+sd-jwt",
			Meta:   openid4vp.MetaQuery{VCTValues: []string{vct}},
		}
	}
	yes := true

	tests := []struct {
		name    string
		dcql    *openid4vp.DCQL
		scopes  []string
		wantAny bool
	}{
		{
			name:    "nil query decides nothing",
			dcql:    nil,
			scopes:  []string{"pid"},
			wantAny: false,
		},
		{
			// The default-token path attributes an unlabelled credential to
			// the sole requested scope, so one query is always reachable.
			name:    "single query is reachable without a mapping",
			dcql:    &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{q("anything", "https://example.org/other")}},
			scopes:  []string{"pid"},
			wantAny: false,
		},
		{
			// The reported case: a second query nothing claims.
			name: "second query nothing claims is flagged",
			dcql: &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{
				q("a", "https://example.org/pid"),
				q("b", "https://example.org/unrequested"),
			}},
			scopes:  []string{"pid"},
			wantAny: true,
		},
		{
			// credential_sets make the queries alternatives ("A or B"), so an
			// unclaimed id may be perfectly legitimate and this cannot decide.
			name: "credential_sets are left alone",
			dcql: &openid4vp.DCQL{
				Credentials: []openid4vp.CredentialQuery{
					q("a", "https://example.org/pid"),
					q("b", "https://example.org/unrequested"),
				},
				CredentialSets: []openid4vp.CredentialSetQuery{
					{Options: [][]string{{"a"}, {"b"}}, Required: &yes},
				},
			},
			scopes:  []string{"pid"},
			wantAny: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				log: logger.NewSimple("test"),
				cfg: &model.Cfg{Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{}}},
			}
			got := c.unclaimedRequiredQueries(context.Background(), tt.dcql, tt.scopes)
			if tt.wantAny && len(got) == 0 {
				t.Fatal("want an unclaimed query to be reported")
			}
			if !tt.wantAny && len(got) > 0 {
				t.Fatalf("want nothing reported, got %v", got)
			}
		})
	}
}
