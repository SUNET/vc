package apiv1

import (
	"testing"
	"time"

	apigwcache "github.com/SUNET/vc/internal/apigw/cache"
	pkgcache "github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/claimpath"
	"github.com/SUNET/vc/pkg/credential/primitives"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClaimValueMatches covers scalar strings, []string and []any
// allow-list membership.
func TestClaimValueMatches(t *testing.T) {
	allowed := []string{
		"https://refeds.org/assurance/IAP/medium",
		"https://refeds.org/assurance/IAP/high",
	}

	assert.True(t, claimValueMatches("https://refeds.org/assurance/IAP/high", allowed))
	assert.False(t, claimValueMatches("https://refeds.org/assurance/IAP/low", allowed))

	assert.True(t, claimValueMatches([]string{"a", "https://refeds.org/assurance/IAP/medium"}, allowed))
	assert.False(t, claimValueMatches([]string{"a", "b"}, allowed))

	assert.True(t, claimValueMatches([]any{"a", "https://refeds.org/assurance/IAP/medium"}, allowed))
	assert.False(t, claimValueMatches([]any{"a", "b"}, allowed))
	assert.False(t, claimValueMatches([]any{1, 2}, allowed))

	assert.False(t, claimValueMatches(42, allowed))
}

// TestEnforceScopeCredentialType_SDJWT covers the SD-JWT branch:
// matching vct passes, missing/non-string/mismatched vct fails with the
// documented status codes.
func TestEnforceScopeCredentialType_SDJWT(t *testing.T) {
	c := &Client{
		log: logger.NewSimple("test"),
		cfg: &model.Cfg{Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{
			"eduid": {
				Format: openid4vp.FormatSDJWTVC,
				VCTM:   &sdjwtvc.VCTM{VCT: "urn:credential:eduid:1"},
			},
			"eduid_age": {
				Format: openid4vp.FormatSDJWTVC,
				VCTM:   &sdjwtvc.VCTM{VCT: "urn:credential:eduid_age:1"},
			},
		}}},
	}

	err := c.enforceScopeCredentialType("eduid", map[string]any{"vct": "urn:credential:eduid:1"})
	assert.NoError(t, err)

	err = c.enforceScopeCredentialType("eduid", map[string]any{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no vct")

	err = c.enforceScopeCredentialType("eduid", map[string]any{"vct": "urn:other:1"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not match")
}

// TestEnforceScopeCredentialType_ZKRejected documents that an mso_mdoc_zk
// presentation scope must not slip through as if it were plain mdoc — the
// bound verifier doesn't support ZK yet and the DCQL dispatch would reject
// a valid ZK presentation.
func TestEnforceScopeCredentialType_ZKRejected(t *testing.T) {
	c := &Client{
		log: logger.NewSimple("test"),
		cfg: &model.Cfg{Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{
			"eduid_zk": {Format: openid4vp.FormatMsoMdocZk},
		}}},
	}
	err := c.enforceScopeCredentialType("eduid_zk", map[string]any{"docType": "something"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mso_mdoc_zk")
}

// TestEnforceScopeCredentialType_UnknownScope ensures a scope with no
// credential_metadata entry is refused rather than silently accepted.
func TestEnforceScopeCredentialType_UnknownScope(t *testing.T) {
	c := &Client{
		log: logger.NewSimple("test"),
		cfg: &model.Cfg{Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{}}},
	}
	err := c.enforceScopeCredentialType("nope", map[string]any{"vct": "x"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no credential_metadata entry")
}

// newPresentationTestClient wires a Client with the minimum state
// finalisePresentationVerification touches: cfg with an SD-JWT eduid scope,
// an in-memory AuthContext store, and an in-memory Document cache.
func newPresentationTestClient(t *testing.T) *Client {
	t.Helper()
	return &Client{
		log: logger.NewSimple("test"),
		cfg: &model.Cfg{Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{
			"eduid": {
				Format: openid4vp.FormatSDJWTVC,
				VCTM:   &sdjwtvc.VCTM{VCT: "urn:credential:eduid:1"},
			},
			"eduid_age": {
				Format: openid4vp.FormatSDJWTVC,
				VCTM:   &sdjwtvc.VCTM{VCT: "urn:credential:eduid_age:1"},
			},
		}}},
		cacheService: &apigwcache.Service{
			AuthContext: apigwcache.NewTestMemoryStore(10 * time.Minute),
			Document:    apigwcache.NewTestMemoryCache[map[string]*model.CompleteDocument](10 * time.Minute),
		},
	}
}

func seedAuthCtx(t *testing.T, c *Client, sessionID string) *pkgcache.AuthorizationContext {
	t.Helper()
	authCtx := &pkgcache.AuthorizationContext{SessionID: sessionID}
	require.NoError(t, c.cacheService.AuthContext.Create(t.Context(), authCtx))
	return authCtx
}

// TestFinalisePresentationVerification_Success covers the happy path: a
// presented eduID credential carries the required birthdate and an
// assurance_level inside the allow-list, VerifiedClaims lands on
// authCtx, and a preview document (with derived age_over_* claims) is
// cached under the presented credential's scope so UserLookup has something
// to render.
func TestFinalisePresentationVerification_Success(t *testing.T) {
	c := newPresentationTestClient(t)
	authCtx := seedAuthCtx(t, c, "sess-ok")

	pScope := model.PresentationScope{
		From: map[string]model.PresentedCredential{"eduid": {
			RequiredClaims: model.RequiredClaims{{Path: claimpath.Keys("birthdate")}, {Path: claimpath.Keys("assurance_level"), Values: []string{
				"http://www.swamid.se/policy/assurance/al3",
			}}},
			Derivations: []primitives.Derivation{
				{AgeOverThresholds: &primitives.AgeOverThresholdsArgs{
					Input: claimpath.Keys("birthdate"), Thresholds: []int{18},
				}},
			},
		}},
	}

	presented := map[string]any{
		"vct":             "urn:credential:eduid:1",
		"birthdate":       "1990-01-15",
		"assurance_level": "http://www.swamid.se/policy/assurance/al3",
	}

	require.NoError(t, c.finalisePresentationVerification(t.Context(), authCtx, "eduid_age", pScope, "eduid", presented))

	assert.Equal(t, "1990-01-15", authCtx.VerifiedClaims["birthdate"])
	assert.Equal(t, "http://www.swamid.se/policy/assurance/al3", authCtx.VerifiedClaims["assurance_level"])

	docs, ok := c.cacheService.Document.Get(t.Context(), "sess-ok")
	require.True(t, ok, "preview document must be cached under session id")
	preview, ok := docs["eduid"]
	require.True(t, ok, "preview document must be keyed by the presented scope")
	require.NotNil(t, preview.Meta)
	assert.Equal(t, "eduid", preview.Meta.AuthenticSource)
	assert.Equal(t, true, preview.DocumentData["age_over_18"], "derivation must populate preview")
	// Raw verified claims should also survive on the preview so UserLookup
	// can render them before VCTM filtering happens in VCICredential.
	assert.Equal(t, "1990-01-15", preview.DocumentData["birthdate"])
}

// TestFinalisePresentationVerification_MissingRequiredClaim rejects a
// presentation that omits a required claim with the documented 400 /
// missing_required_claim error and leaves VerifiedClaims unset.
func TestFinalisePresentationVerification_MissingRequiredClaim(t *testing.T) {
	c := newPresentationTestClient(t)
	authCtx := seedAuthCtx(t, c, "sess-miss")

	pScope := model.PresentationScope{
		From: map[string]model.PresentedCredential{"eduid": {
			RequiredClaims: model.RequiredClaims{{Path: claimpath.Keys("birthdate")}, {Path: claimpath.Keys("assurance_level")}},
		}},
	}
	presented := map[string]any{
		"vct":       "urn:credential:eduid:1",
		"birthdate": "1990-01-15",
	}

	err := c.finalisePresentationVerification(t.Context(), authCtx, "eduid_age", pScope, "eduid", presented)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "assurance_level")
	assert.Contains(t, err.Error(), "not present")
	assert.Nil(t, authCtx.VerifiedClaims)
	_, cached := c.cacheService.Document.Get(t.Context(), "sess-miss")
	assert.False(t, cached, "no preview must be cached on validation failure")
}

// TestFinalisePresentationVerification_ScalarAllowList rejects a scalar
// claim whose value is not in the allow-list with claim_value_not_allowed.
func TestFinalisePresentationVerification_ScalarAllowList(t *testing.T) {
	c := newPresentationTestClient(t)
	authCtx := seedAuthCtx(t, c, "sess-scalar")

	pScope := model.PresentationScope{
		From: map[string]model.PresentedCredential{"eduid": {
			RequiredClaims: model.RequiredClaims{{Path: claimpath.Keys("assurance_level"), Values: []string{
				"http://www.swamid.se/policy/assurance/al3",
			}}},
		}},
	}
	presented := map[string]any{
		"vct":             "urn:credential:eduid:1",
		"assurance_level": "http://www.swamid.se/policy/assurance/al1",
	}

	err := c.finalisePresentationVerification(t.Context(), authCtx, "eduid_age", pScope, "eduid", presented)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not in allow-list")
	assert.Nil(t, authCtx.VerifiedClaims)
}

// TestFinalisePresentationVerification_ArrayAllowList accepts an array
// claim when at least one element is in the allow-list and rejects when
// none match.
func TestFinalisePresentationVerification_ArrayAllowList(t *testing.T) {
	c := newPresentationTestClient(t)
	authCtx := seedAuthCtx(t, c, "sess-array-ok")

	pScope := model.PresentationScope{
		From: map[string]model.PresentedCredential{"eduid": {
			RequiredClaims: model.RequiredClaims{{Path: claimpath.Keys("assurance_level"), Values: []string{
				"http://www.swamid.se/policy/assurance/al3",
			}}},
		}},
	}
	presentedOK := map[string]any{
		"vct": "urn:credential:eduid:1",
		"assurance_level": []any{
			"http://www.swamid.se/policy/assurance/al1",
			"http://www.swamid.se/policy/assurance/al3",
		},
	}
	require.NoError(t, c.finalisePresentationVerification(t.Context(), authCtx, "eduid_age", pScope, "eduid", presentedOK))

	authCtxBad := seedAuthCtx(t, c, "sess-array-bad")
	presentedBad := map[string]any{
		"vct": "urn:credential:eduid:1",
		"assurance_level": []any{
			"http://www.swamid.se/policy/assurance/al1",
		},
	}
	err := c.finalisePresentationVerification(t.Context(), authCtxBad, "eduid_age", pScope, "eduid", presentedBad)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not in allow-list")
}

// TestFinalisePresentationVerification_WrongVCT refuses a presented
// credential whose vct does not match the presented scope's canonical VCT —
// a different trusted credential that happens to carry the required
// claims must not be minted from.
func TestFinalisePresentationVerification_WrongVCT(t *testing.T) {
	c := newPresentationTestClient(t)
	authCtx := seedAuthCtx(t, c, "sess-wrongvct")

	pScope := model.PresentationScope{
		From: map[string]model.PresentedCredential{"eduid": {
			RequiredClaims: model.RequiredClaims{{Path: claimpath.Keys("birthdate")}},
		}},
	}
	presented := map[string]any{
		"vct":       "urn:credential:other:1",
		"birthdate": "1990-01-15",
	}

	err := c.finalisePresentationVerification(t.Context(), authCtx, "eduid_age", pScope, "eduid", presented)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match")
	assert.Nil(t, authCtx.VerifiedClaims)
}
