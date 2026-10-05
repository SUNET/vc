package apiv1

import (
	"testing"
	"time"

	apigwcache "github.com/SUNET/vc/internal/apigw/cache"
	pkgcache "github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/credential/primitives"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLookupClaimPath_SDJWTFormat covers the format-aware literal/nested
// resolution for SD-JWT: a flat dotted key MUST NOT satisfy a required
// nested path, nested walking succeeds, and plain top-level keys are
// resolved by direct lookup.
func TestLookupClaimPath_SDJWTFormat(t *testing.T) {
	nested := map[string]any{
		"identity": map[string]any{
			"birthdate": "1990-01-15",
		},
		"vct": "urn:example:1",
	}
	v, ok := lookupClaimPath(openid4vp.FormatSDJWTVC, nested, "identity.birthdate")
	require.True(t, ok)
	assert.Equal(t, "1990-01-15", v)

	v, ok = lookupClaimPath(openid4vp.FormatSDJWTVC, nested, "vct")
	require.True(t, ok)
	assert.Equal(t, "urn:example:1", v)

	flat := map[string]any{"identity.birthdate": "1990-01-15"}
	_, ok = lookupClaimPath(openid4vp.FormatSDJWTVC, flat, "identity.birthdate")
	assert.False(t, ok, "SD-JWT lookup must not satisfy a nested path with a flat dotted literal key")

	_, ok = lookupClaimPath(openid4vp.FormatSDJWTVC, nested, "identity.street")
	assert.False(t, ok)
}

// TestLookupClaimPath_MDocFormat covers the format-aware literal/nested
// resolution for mdoc: a namespace-qualified key stored flat is accepted
// as-is, nested walking also works for primary-namespace short keys.
func TestLookupClaimPath_MDocFormat(t *testing.T) {
	flat := map[string]any{
		"eu.europa.ec.eudi.pid.1.birth_date": "1990-01-15",
		"birth_date":                         "1990-01-15",
	}
	v, ok := lookupClaimPath(openid4vp.FormatMsoMdoc, flat, "eu.europa.ec.eudi.pid.1.birth_date")
	require.True(t, ok)
	assert.Equal(t, "1990-01-15", v)

	v, ok = lookupClaimPath(openid4vp.FormatMsoMdoc, flat, "birth_date")
	require.True(t, ok)
	assert.Equal(t, "1990-01-15", v)

	// ZK counterpart uses the same literal-first contract.
	v, ok = lookupClaimPath(openid4vp.FormatMsoMdocZk, flat, "eu.europa.ec.eudi.pid.1.birth_date")
	require.True(t, ok)
	assert.Equal(t, "1990-01-15", v)
}

// TestSetClaimPath_SDJWTFormat verifies that SD-JWT output always nests
// dotted paths — a flat source literal must not leak into the issued
// document as a flat literal.
func TestSetClaimPath_SDJWTFormat(t *testing.T) {
	src := map[string]any{"identity.given_name": "Alice"}
	dst := map[string]any{}
	setClaimPath(openid4vp.FormatSDJWTVC, dst, src, "identity.given_name", "Alice")
	id, ok := dst["identity"].(map[string]any)
	require.True(t, ok, "SD-JWT path must materialise as a nested map")
	assert.Equal(t, "Alice", id["given_name"])
	_, flat := dst["identity.given_name"]
	assert.False(t, flat, "SD-JWT path must not leak as a flat literal key")
}

// TestSetClaimPath_MDocFormat verifies that an mdoc namespace-qualified
// literal is preserved as-is, while short keys still nest when dotted.
func TestSetClaimPath_MDocFormat(t *testing.T) {
	src := map[string]any{"eu.europa.ec.eudi.pid.1.birth_date": "1990"}
	dst := map[string]any{}
	setClaimPath(openid4vp.FormatMsoMdoc, dst, src, "eu.europa.ec.eudi.pid.1.birth_date", "1990")
	assert.Equal(t, "1990", dst["eu.europa.ec.eudi.pid.1.birth_date"])
}

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
// cached under FromScope so UserLookup has something to render.
func TestFinalisePresentationVerification_Success(t *testing.T) {
	c := newPresentationTestClient(t)
	authCtx := seedAuthCtx(t, c, "sess-ok")

	pScope := model.PresentationScope{
		FromScope: "eduid",
		RequiredClaims: map[string][]string{
			"birthdate": nil,
			"assurance_level": {
				"http://www.swamid.se/policy/assurance/al3",
			},
		},
		Derivations: []primitives.Derivation{
			{AgeOverThresholds: &primitives.AgeOverThresholdsArgs{
				Input: "birthdate", Thresholds: []int{18},
			}},
		},
	}

	presented := map[string]any{
		"vct":             "urn:credential:eduid:1",
		"birthdate":       "1990-01-15",
		"assurance_level": "http://www.swamid.se/policy/assurance/al3",
	}

	require.NoError(t, c.finalisePresentationVerification(t.Context(), authCtx, pScope, presented))

	assert.Equal(t, "1990-01-15", authCtx.VerifiedClaims["birthdate"])
	assert.Equal(t, "http://www.swamid.se/policy/assurance/al3", authCtx.VerifiedClaims["assurance_level"])

	docs, ok := c.cacheService.Document.Get(t.Context(), "sess-ok")
	require.True(t, ok, "preview document must be cached under session id")
	preview, ok := docs["eduid"]
	require.True(t, ok, "preview document must be keyed by FromScope")
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
		FromScope: "eduid",
		RequiredClaims: map[string][]string{
			"birthdate":       nil,
			"assurance_level": nil,
		},
	}
	presented := map[string]any{
		"vct":       "urn:credential:eduid:1",
		"birthdate": "1990-01-15",
	}

	err := c.finalisePresentationVerification(t.Context(), authCtx, pScope, presented)
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
		FromScope: "eduid",
		RequiredClaims: map[string][]string{
			"assurance_level": {
				"http://www.swamid.se/policy/assurance/al3",
			},
		},
	}
	presented := map[string]any{
		"vct":             "urn:credential:eduid:1",
		"assurance_level": "http://www.swamid.se/policy/assurance/al1",
	}

	err := c.finalisePresentationVerification(t.Context(), authCtx, pScope, presented)
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
		FromScope: "eduid",
		RequiredClaims: map[string][]string{
			"assurance_level": {
				"http://www.swamid.se/policy/assurance/al3",
			},
		},
	}
	presentedOK := map[string]any{
		"vct": "urn:credential:eduid:1",
		"assurance_level": []any{
			"http://www.swamid.se/policy/assurance/al1",
			"http://www.swamid.se/policy/assurance/al3",
		},
	}
	require.NoError(t, c.finalisePresentationVerification(t.Context(), authCtx, pScope, presentedOK))

	authCtxBad := seedAuthCtx(t, c, "sess-array-bad")
	presentedBad := map[string]any{
		"vct": "urn:credential:eduid:1",
		"assurance_level": []any{
			"http://www.swamid.se/policy/assurance/al1",
		},
	}
	err := c.finalisePresentationVerification(t.Context(), authCtxBad, pScope, presentedBad)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not in allow-list")
}

// TestFinalisePresentationVerification_WrongVCT refuses a presented
// credential whose vct does not match pScope.FromScope's canonical VCT —
// a different trusted credential that happens to carry the required
// claims must not be minted from.
func TestFinalisePresentationVerification_WrongVCT(t *testing.T) {
	c := newPresentationTestClient(t)
	authCtx := seedAuthCtx(t, c, "sess-wrongvct")

	pScope := model.PresentationScope{
		FromScope:      "eduid",
		RequiredClaims: map[string][]string{"birthdate": nil},
	}
	presented := map[string]any{
		"vct":       "urn:credential:other:1",
		"birthdate": "1990-01-15",
	}

	err := c.finalisePresentationVerification(t.Context(), authCtx, pScope, presented)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match")
	assert.Nil(t, authCtx.VerifiedClaims)
}
