package apiv1

import (
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/credential"
	"github.com/SUNET/vc/pkg/credential/primitives"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The consent preview used maps.Copy on the verified claims, which shares
// every nested map with them. MergeNestedClaims writes INTO an existing
// nested map, so a derivation targeting a dotted path wrote its result into
// authCtx.VerifiedClaims - the holder's own presented claims, which were
// just persisted and which issuance rebuilds the real document from.
//
// This reproduces the merge the preview performs, so the isolation is
// pinned at the operation that broke it rather than through a cache.
func TestPreviewDerivationsDoNotMutateVerifiedClaims(t *testing.T) {
	verified := map[string]any{
		"identity": map[string]any{"given_name": "Ada"},
	}

	previewData := credential.CloneNestedClaims(verified)

	derived, err := credential.ApplyDerivations([]primitives.Derivation{
		{Random: &primitives.RandomArgs{Output: "identity.document_id"}},
	}, verified, time.Now())
	require.NoError(t, err)
	credential.MergeNestedClaims(previewData, derived)

	// The preview sees it.
	identity, ok := previewData["identity"].(map[string]any)
	require.True(t, ok)
	assert.NotEmpty(t, identity["document_id"], "the preview should render the generated value")

	// The verified claims do not.
	verifiedIdentity, ok := verified["identity"].(map[string]any)
	require.True(t, ok)
	assert.NotContains(t, verifiedIdentity, "document_id",
		"a derivation must not write into the holder's verified claims")
	assert.Equal(t, "Ada", verifiedIdentity["given_name"])
}

// The same isolation with a deterministic primitive, so the test does not
// depend on the random primitive existing - this is a property of the
// preview path, not of one primitive.
func TestPreviewDerivationsDoNotMutateVerifiedClaimsForAnyPrimitive(t *testing.T) {
	verified := map[string]any{
		"identity": map[string]any{"email": "  ADA@Example.COM  "},
	}

	previewData := credential.CloneNestedClaims(verified)

	derived, err := credential.ApplyDerivations([]primitives.Derivation{
		{Trim: &primitives.TrimArgs{Input: "identity.email", Output: "identity.email_trimmed"}},
	}, verified, time.Now())
	require.NoError(t, err)
	credential.MergeNestedClaims(previewData, derived)

	verifiedIdentity := verified["identity"].(map[string]any)
	assert.NotContains(t, verifiedIdentity, "email_trimmed")
	assert.Equal(t, "  ADA@Example.COM  ", verifiedIdentity["email"])
}
