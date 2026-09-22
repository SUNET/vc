package openid4vp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExpandedTypesIgnoresDecoyNodes pins type isolation against the realistic
// attack: a wallet sends expanded JSON-LD carrying a decoy node beside the
// credential, hoping its type satisfies the constraint.
//
// The test proves the hazard and the protection in one pass, so it cannot go
// vacuous: expanding the WHOLE document really does pick up the decoy, while
// the path the handler actually takes - extractCredentialFromExpanded, then
// expandedTypes on that node alone - does not.
func TestExpandedTypesIgnoresDecoyNodes(t *testing.T) {
	const decoy = "https://example.org/degree#UniversityDegreeCredential"
	const vcIRI = "https://www.w3.org/2018/credentials#VerifiableCredential"

	expanded := []any{
		map[string]any{
			"@type": []any{vcIRI},
			"https://www.w3.org/2018/credentials#credentialSubject": []any{
				map[string]any{"@id": "did:example:subject"},
			},
		},
		map[string]any{"@type": []any{decoy}},
	}

	h, err := NewVC20Handler()
	require.NoError(t, err)

	// credBytes is the WHOLE document, as the handler keeps it for signature
	// verification; credMap is the credential node it identified. buildResult
	// gets both, and which one it reads for types is the whole question -
	// reading the document picks up the decoy.
	credBytes, err := json.Marshal(expanded)
	require.NoError(t, err)
	credMap, err := h.extractCredentialFromExpanded(expanded)
	require.NoError(t, err)

	result, err := h.buildResult(credBytes, credMap, map[string]any{}, false)
	require.NoError(t, err)
	assert.Contains(t, result.TypeIRIs, vcIRI, "the credential's own type is read")
	assert.NotContains(t, result.TypeIRIs, decoy, "a sibling node's type is not the credential's")

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
