package mdoc

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBuildOID4VPDCAPISessionTranscript_Layout recomputes the structure
// independently of the function under test and compares bytes, the same way
// multipaz's own OpenID4VPDCAPIHandover test does.
//
// This pins the three things that make this handover incompatible with the
// redirect one: origin in place of the response URI and in first position,
// no clientID member, and the OpenID4VPDCAPIHandover label.
func TestBuildOID4VPDCAPISessionTranscript_Layout(t *testing.T) {
	const (
		origin = "https://verifier.example.com"
		nonce  = "n-0S6_WzA2Mj"
	)
	thumbprint := make([]byte, 32)
	for i := range thumbprint {
		thumbprint[i] = byte(i)
	}

	got, err := BuildOID4VPDCAPISessionTranscript(origin, nonce, thumbprint)
	require.NoError(t, err)

	// Recomputed here from the spec shape, not by calling the same helper.
	enc, err := cbor.CanonicalEncOptions().EncMode()
	require.NoError(t, err)
	handoverInfo, err := enc.Marshal([]any{origin, nonce, thumbprint})
	require.NoError(t, err)
	digest := sha256.Sum256(handoverInfo)
	want, err := enc.Marshal([]any{nil, nil, []any{"OpenID4VPDCAPIHandover", digest[:]}})
	require.NoError(t, err)

	assert.True(t, bytes.Equal(want, got), "transcript bytes must match the recomputed structure")

	// And it must not be the redirect handover: same inputs, different bytes.
	redirect, err := BuildOID4VPSessionTranscript("x509_san_dns:verifier.example.com", nonce, origin, thumbprint)
	require.NoError(t, err)
	assert.False(t, bytes.Equal(redirect, got),
		"the two handovers must produce different transcripts, or picking the wrong one would go unnoticed")
}

func TestBuildOID4VPDCAPISessionTranscript_NilThumbprintIsNull(t *testing.T) {
	// Three elements either way: a nil thumbprint encodes as CBOR null
	// rather than shortening the array.
	withNil, err := BuildOID4VPDCAPISessionTranscript("https://verifier.example.com", "n1", nil)
	require.NoError(t, err)

	enc, err := cbor.CanonicalEncOptions().EncMode()
	require.NoError(t, err)
	handoverInfo, err := enc.Marshal([]any{"https://verifier.example.com", "n1", nil})
	require.NoError(t, err)
	digest := sha256.Sum256(handoverInfo)
	want, err := enc.Marshal([]any{nil, nil, []any{"OpenID4VPDCAPIHandover", digest[:]}})
	require.NoError(t, err)

	assert.Equal(t, want, withNil)
}

// The origin is what this handover binds to, so an empty one is refused
// rather than hashed into something meaningless.
func TestBuildOID4VPDCAPISessionTranscript_RequiresOrigin(t *testing.T) {
	_, err := BuildOID4VPDCAPISessionTranscript("", "n1", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "calling origin")
}
