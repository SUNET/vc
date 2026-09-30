package eddsa

import (
	"encoding/json"
	"testing"

	"github.com/SUNET/vc/pkg/vc20/credential"

	"github.com/stretchr/testify/require"
)

// TestRootDocumentID covers the other half of the wiring: the selection can
// only follow the root's proof link if the root's own id is read out of the
// document the caller passed.
func TestRootDocumentID(t *testing.T) {
	withID := `{"@context":"https://www.w3.org/ns/credentials/v2","id":"urn:uuid:the-presentation","type":["VerifiablePresentation"],"holder":"did:example:holder"}`
	cred, err := credential.NewRDFCredentialFromJSON([]byte(withID), nil)
	require.NoError(t, err)
	require.Equal(t, "urn:uuid:the-presentation", rootDocumentID(cred))

	// No id: nothing to follow, and also nothing to be ambiguous about.
	withoutID := `{"@context":"https://www.w3.org/ns/credentials/v2","type":["VerifiablePresentation"],"holder":"did:example:holder"}`
	cred, err = credential.NewRDFCredentialFromJSON([]byte(withoutID), nil)
	require.NoError(t, err)
	require.Empty(t, rootDocumentID(cred))

	// Expanded JSON-LD is an array, so there is no root object to ask.
	expanded, err := json.Marshal(cred)
	require.NoError(t, err)
	reparsed, err := credential.NewRDFCredentialFromJSON(expanded, nil)
	require.NoError(t, err)
	require.Empty(t, rootDocumentID(reparsed))
}
