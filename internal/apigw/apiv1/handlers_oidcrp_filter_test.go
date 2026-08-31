package apiv1

import (
	"testing"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/sdjwtvc"
	"github.com/stretchr/testify/assert"
)

func claimPath(s string) *string { return &s }

func filterTestClient(t *testing.T, scope string, metadata *model.CredentialMetadata) *Client {
	t.Helper()
	md := map[string]*model.CredentialMetadata{}
	if metadata != nil {
		md[scope] = metadata
	}
	return &Client{
		log: logger.NewSimple("test"),
		cfg: &model.Cfg{Common: &model.Common{CredentialMetadata: md}},
	}
}

// idTokenClaims is what an OIDC provider actually hands back: a few claims the
// credential wants, wrapped in envelope claims it does not.
func idTokenClaims() map[string]any {
	return map[string]any{
		"given_name":  "Helen",
		"family_name": "Nilsson",
		"iss":         "https://idp.example",
		"aud":         "vc-apigw",
		"exp":         1893456000,
		"iat":         1893452400,
		"nonce":       "n-0S6_WzA2Mj",
		"at_hash":     "abc",
		"sid":         "session-1",
		"email":       "helen@example.org",
	}
}

// TestFilterClaims_DropsUndeclared is issue #623: claims the credential type
// does not declare can never be selectively disclosed, so a wallet has to
// present them every time.
func TestFilterClaims_DropsUndeclared(t *testing.T) {
	c := filterTestClient(t, "pid", &model.CredentialMetadata{VCTM: &sdjwtvc.VCTM{Claims: []sdjwtvc.Claim{
		{Path: []*string{claimPath("given_name")}},
		{Path: []*string{claimPath("family_name")}},
	}}})

	got := c.filterClaimsByCredentialType("pid", idTokenClaims())

	assert.Equal(t, map[string]any{"given_name": "Helen", "family_name": "Nilsson"}, got)

	// Called out individually: these collide with the envelope the issuer
	// fills in at signing time (see sdjwtvc.isIssuerSuppliedClaim), so
	// letting them through is a correctness problem as well as a privacy one.
	for _, envelope := range []string{"iss", "aud", "exp", "iat"} {
		assert.NotContains(t, got, envelope, "envelope claim must not survive")
	}
	assert.NotContains(t, got, "email", "an undeclared claim must not survive")
}

// TestFilterClaims_NoMetadataPassesThrough pins the deliberate conservatism:
// with nothing to filter against, emptying the credential would be worse than
// the over-sharing this exists to prevent.
func TestFilterClaims_NoMetadataPassesThrough(t *testing.T) {
	t.Run("scope not configured", func(t *testing.T) {
		c := filterTestClient(t, "pid", nil)
		assert.Equal(t, idTokenClaims(), c.filterClaimsByCredentialType("pid", idTokenClaims()))
	})

	t.Run("configured but neither VCTM nor MDDL loaded", func(t *testing.T) {
		c := filterTestClient(t, "pid", &model.CredentialMetadata{})
		assert.Equal(t, idTokenClaims(), c.filterClaimsByCredentialType("pid", idTokenClaims()))
	})
}

// TestFilterClaims_LoadedButEmptyDropsEverything is the other side of that
// distinction: a credential type that genuinely declares no claims is not the
// same as one whose metadata never loaded.
func TestFilterClaims_LoadedButEmptyDropsEverything(t *testing.T) {
	c := filterTestClient(t, "pid", &model.CredentialMetadata{VCTM: &sdjwtvc.VCTM{}})
	assert.Empty(t, c.filterClaimsByCredentialType("pid", idTokenClaims()))
}

func TestFilterClaims_NoClaims(t *testing.T) {
	c := filterTestClient(t, "pid", &model.CredentialMetadata{VCTM: &sdjwtvc.VCTM{}})
	assert.Empty(t, c.filterClaimsByCredentialType("pid", map[string]any{}))
	assert.Nil(t, c.filterClaimsByCredentialType("pid", nil))
}
