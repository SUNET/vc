package openid4vp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExpandedTypesTakesOnlyTheCredentialNode pins the constraint against a
// decoy.
//
// Expanding the whole document collects @type from every top-level node, so an
// expanded-form response could carry a second node holding the requested type
// and satisfy a constraint the credential itself does not meet. Only the
// identified credential node's types are the credential's.
func TestExpandedTypesTakesOnlyTheCredentialNode(t *testing.T) {
	const decoy = "https://example.org/degree#UniversityDegreeCredential"

	var credNode map[string]any
	require.NoError(t, json.Unmarshal([]byte(
		`{"@type":["https://www.w3.org/2018/credentials#VerifiableCredential"]}`), &credNode))

	iris, err := expandedTypes(credNode)
	require.NoError(t, err)
	assert.NotContains(t, iris, decoy, "a sibling node's type is not the credential's")
	assert.Contains(t, iris, "https://www.w3.org/2018/credentials#VerifiableCredential")
}

// TestExpandedTypesDropsRelativeIRIs pins the other half: a term no context
// defines expands to itself, which identifies nothing and must never satisfy a
// constraint.
func TestExpandedTypesDropsRelativeIRIs(t *testing.T) {
	var credNode map[string]any
	require.NoError(t, json.Unmarshal([]byte(`{
		"@context":["https://www.w3.org/ns/credentials/v2"],
		"type":["VerifiableCredential","UniversityDegreeCredential"],
		"issuer":"did:example:issuer",
		"credentialSubject":{"degree":"MSc"}}`), &credNode))

	iris, err := expandedTypes(credNode)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://www.w3.org/2018/credentials#VerifiableCredential"}, iris,
		"the undefined term expands to a relative IRI and is dropped")
}

// TestExpandedPresentationRefusedWhenBindingRequired: extractCredentialFromExpanded
// discards the presentation wrapper and its proof, so the binding cannot be
// checked afterwards. Refuse plainly rather than report a presentation as a
// bare credential.
func TestExpandedPresentationRefusedWhenBindingRequired(t *testing.T) {
	h, err := NewVC20Handler(
		WithVC20StaticKey(nil),
		WithVC20PresentationBinding("nonce", "verifier"),
	)
	require.NoError(t, err)

	expandedVP := `[{"@type":["https://www.w3.org/2018/credentials#VerifiablePresentation"],
	  "https://www.w3.org/2018/credentials#verifiableCredential":[{"@type":["https://www.w3.org/2018/credentials#VerifiableCredential"]}]}]`

	_, err = h.VerifyAndExtract(t.Context(), expandedVP)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expanded-form presentations")
}
