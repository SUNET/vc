package mdoc

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The values the OpenID4VCI 1.1 draft uses in its own worked example of
// the Interactive Authorization mdoc binding, and the bytes it publishes
// for each stage of it.
const (
	specIAEEndpoint = "https://example.com/iae"
	specIAENonce    = "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA"

	// The JWK thumbprint from the example's input key.
	specIAEThumbprintHex = "4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047"

	specIAEHandoverInfoHex = "837768747470733a2f2f6578616d706c652e636f6d2f696165782b" +
		"6578633767426b786a7831726463397564527276654b7653734a4971383061766c58654c4868477771744158" +
		"204283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047"

	specIAEHandoverHex = "82754f70656e49443456434949414548616e646f766572" +
		"5820df679426cc1bf8996e8eb549ee078815a87a97c5e95c1c5a8ec39eedca28a838"

	specIAETranscriptHex = "83f6f682754f70656e49443456434949414548616e646f766572" +
		"5820df679426cc1bf8996e8eb549ee078815a87a97c5e95c1c5a8ec39eedca28a838"
)

// The two handovers already in this file were written from a reference
// implementation and carry a note saying they have never been checked
// against real bytes. This one can do better: the draft publishes hex for
// the handover info, the handover and the finished transcript, so all
// three stages are reproduced here rather than only the result.
func TestIAESessionTranscriptMatchesTheSpecVectors(t *testing.T) {
	thumbprint, err := hex.DecodeString(specIAEThumbprintHex)
	require.NoError(t, err)

	t.Run("the finished transcript", func(t *testing.T) {
		got, err := BuildOID4VCIIAESessionTranscript(
			"OpenID4VCIIAEHandover", specIAEEndpoint, specIAENonce, thumbprint)
		require.NoError(t, err)
		assert.Equal(t, specIAETranscriptHex, hex.EncodeToString(got))
	})

	// Reproducing the intermediate stages is what makes a failure
	// diagnosable: a wrong transcript says only that something is wrong,
	// while a correct info and a wrong digest says exactly where.
	t.Run("the handover info, encoded", func(t *testing.T) {
		encoder, err := NewCBOREncoder()
		require.NoError(t, err)

		info, err := encoder.Marshal([]any{specIAEEndpoint, specIAENonce, thumbprint})
		require.NoError(t, err)
		assert.Equal(t, specIAEHandoverInfoHex, hex.EncodeToString(info))
	})

	// The ambiguity this settles: the CDDL calls the hashed value
	// OpenID4VCIIAEHandoverInfoBytes and defines it as `bstr .cbor
	// OpenID4VCIIAEHandoverInfo`, which reads as the byte-string-wrapped
	// form. The published digest is over the BARE encoding. Both candidates
	// are computed here so a future reader does not have to rediscover it.
	t.Run("the digest is over the bare CBOR, not the bstr-wrapped form", func(t *testing.T) {
		info, err := hex.DecodeString(specIAEHandoverInfoHex)
		require.NoError(t, err)

		encoder, err := NewCBOREncoder()
		require.NoError(t, err)
		wrapped, err := encoder.Marshal(info) // as a CBOR byte string
		require.NoError(t, err)

		bare := sha256.Sum256(info)
		wrappedDigest := sha256.Sum256(wrapped)

		handover, err := hex.DecodeString(specIAEHandoverHex)
		require.NoError(t, err)
		published := handover[len(handover)-32:]

		assert.Equal(t, published, bare[:], "the published digest is over the bare encoding")
		assert.NotEqual(t, published, wrappedDigest[:], "and not over the bstr-wrapped one")
	})
}

// For ia_post there is no response encryption key, and the third member is
// null rather than absent - the array is three elements either way.
func TestIAESessionTranscriptEncodesAMissingThumbprintAsNull(t *testing.T) {
	got, err := BuildOID4VCIIAESessionTranscript(
		"OpenID4VCIIAEHandover", specIAEEndpoint, specIAENonce, nil)
	require.NoError(t, err)

	encoder, err := NewCBOREncoder()
	require.NoError(t, err)
	info, err := encoder.Marshal([]any{specIAEEndpoint, specIAENonce, nil})
	require.NoError(t, err)

	digest := sha256.Sum256(info)
	want, err := encoder.Marshal([]any{nil, nil, []any{"OpenID4VCIIAEHandover", digest[:]}})
	require.NoError(t, err)

	assert.Equal(t, hex.EncodeToString(want), hex.EncodeToString(got))
	assert.NotEqual(t, specIAETranscriptHex, hex.EncodeToString(got),
		"dropping the thumbprint must change the transcript, or it was never bound to it")
}

// CS01_07: the label is hashed into the transcript, so if the working
// group settles the IAE/ia spelling the other way a deployment has to be
// able to follow without a release.
func TestIAESessionTranscriptLabelIsNotHardcoded(t *testing.T) {
	thumbprint, err := hex.DecodeString(specIAEThumbprintHex)
	require.NoError(t, err)

	normative, err := BuildOID4VCIIAESessionTranscript(
		"OpenID4VCIIAEHandover", specIAEEndpoint, specIAENonce, thumbprint)
	require.NoError(t, err)

	renamed, err := BuildOID4VCIIAESessionTranscript(
		"OpenID4VCIIAHandover", specIAEEndpoint, specIAENonce, thumbprint)
	require.NoError(t, err)

	assert.NotEqual(t, normative, renamed, "the label must reach the transcript")
	assert.Contains(t, string(renamed), "OpenID4VCIIAHandover")
}

// Every input is load-bearing: each one binds the presentation to
// something, so a missing one is refused rather than hashed as empty.
func TestIAESessionTranscriptRefusesEmptyInputs(t *testing.T) {
	for name, tc := range map[string]struct{ label, endpoint, nonce string }{
		"no label":    {"", specIAEEndpoint, specIAENonce},
		"no endpoint": {"OpenID4VCIIAEHandover", "", specIAENonce},
		"no nonce":    {"OpenID4VCIIAEHandover", specIAEEndpoint, ""},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := BuildOID4VCIIAESessionTranscript(tc.label, tc.endpoint, tc.nonce, nil)
			require.Error(t, err)
		})
	}
}
