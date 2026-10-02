package apiv1

import (
	"testing"

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
