package openid4vci

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An extension member survives a round trip and sits at the top level.
func TestCredentialMetadataKeepsExtensions(t *testing.T) {
	const wire = `{"display":[{"name":"Nym","locale":"en"}],"org.siros.secret_seed":{"org.siros.nym_auth":"00112233445566778899aabbccddeeff"}}`

	var meta CredentialMetadata
	require.NoError(t, json.Unmarshal([]byte(wire), &meta))
	require.Len(t, meta.Display, 1)
	require.Contains(t, meta.Extensions, "org.siros.secret_seed",
		"a member this build does not model must be kept; a relay MUST preserve what it does not understand")

	again, err := json.Marshal(meta)
	require.NoError(t, err)
	assert.JSONEq(t, wire, string(again), "the member must come back out where it went in")
}

// The trap this split exists for: encoding/json matches struct field
// names CASE-INSENSITIVELY. A decode that filled the struct and then
// collected "everything else" would bind DISPLAY to Display AND keep it
// as an extension, and re-encoding would emit both - with the extension
// silently overriding the modelled member.
func TestCredentialMetadataDoesNotDoubleBindACaseVariant(t *testing.T) {
	const wire = `{"DISPLAY":[{"name":"Nym","locale":"en"}]}`

	var meta CredentialMetadata
	require.NoError(t, json.Unmarshal([]byte(wire), &meta))

	assert.Empty(t, meta.Display,
		"only the exact member name fills the modelled field")
	require.Contains(t, meta.Extensions, "DISPLAY",
		"and the case variant is kept as what it is: a member this build does not model")

	again, err := json.Marshal(meta)
	require.NoError(t, err)
	var members map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(again, &members))
	assert.NotContains(t, members, "display",
		"re-encoding must not invent a modelled member from a case variant")
	assert.Len(t, members, 1, "and must not emit the value twice")
}

// An extension that collides with a modelled member is refused. A
// document that says display twice means different things to different
// readers, and for a member that carries a secret that is not a
// formatting question.
func TestCredentialMetadataRefusesACollidingExtension(t *testing.T) {
	meta := CredentialMetadata{
		Display:    []CredentialMetadataDisplay{{Name: "Nym"}},
		Extensions: map[string]json.RawMessage{"display": json.RawMessage(`["other"]`)},
	}
	_, err := json.Marshal(meta)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "collides")

	_, err = json.Marshal(CredentialMetadata{Extensions: map[string]json.RawMessage{"": json.RawMessage(`1`)}})
	assert.Error(t, err, "an unnamed member is not a member")
}

// No extensions means the encoding is unchanged, so every existing
// consumer sees exactly what it saw before.
func TestCredentialMetadataWithoutExtensionsIsUnchanged(t *testing.T) {
	meta := CredentialMetadata{Display: []CredentialMetadataDisplay{{Name: "Nym", Locale: "en"}}}
	encoded, err := json.Marshal(meta)
	require.NoError(t, err)
	assert.JSONEq(t, `{"display":[{"name":"Nym","locale":"en"}]}`, string(encoded))

	empty, err := json.Marshal(CredentialMetadata{})
	require.NoError(t, err)
	assert.JSONEq(t, `{}`, string(empty))
}
