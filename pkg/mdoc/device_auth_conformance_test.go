package mdoc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// DeviceAuthenticationBytes must have the shape ISO 18013-5 9.1.3.4
// defines, asserted by DECODING it rather than by comparing against what
// this package produces.
//
// That distinction is the whole point. The previous structure was wrong in
// three ways and no test noticed, because the verifier rebuilt the same
// wrong shape: builder and verifier agreed with each other and both
// disagreed with the specification. A test that asks "does the verifier
// accept what the builder made" cannot see that. This one asks what the
// bytes ARE.
func TestDeviceAuthenticationBytesMatchTheSpecification(t *testing.T) {
	encoder, err := NewCBOREncoder()
	require.NoError(t, err)
	namespaces, err := encoder.Marshal(map[string]any{})
	require.NoError(t, err)

	transcript := testSessionTranscript()
	got, err := buildDeviceAuthenticationBytes(transcript, "org.iso.18013.5.1.mDL", namespaces)
	require.NoError(t, err)

	// DeviceAuthenticationBytes = #6.24(bstr .cbor DeviceAuthentication)
	var outer cbor.Tag
	require.NoError(t, cbor.Unmarshal(got, &outer))
	assert.EqualValues(t, 24, outer.Number,
		"the signed content is DeviceAuthenticationBytes, which is an encoded CBOR data item")
	inner, ok := outer.Content.([]byte)
	require.True(t, ok, "the tag content is a byte string holding the encoded DeviceAuthentication")

	// DeviceAuthentication = ["DeviceAuthentication", SessionTranscript, DocType, DeviceNameSpacesBytes]
	var deviceAuth []cbor.RawMessage
	require.NoError(t, cbor.Unmarshal(inner, &deviceAuth))
	require.Len(t, deviceAuth, 4)

	var label string
	require.NoError(t, cbor.Unmarshal(deviceAuth[0], &label))
	assert.Equal(t, "DeviceAuthentication", label)

	t.Run("element 1 is the SessionTranscript array, not a byte string", func(t *testing.T) {
		var asBytes []byte
		assert.Error(t, cbor.Unmarshal(deviceAuth[1], &asBytes),
			"a byte string here is the defect this test exists for")

		var asArray []cbor.RawMessage
		require.NoError(t, cbor.Unmarshal(deviceAuth[1], &asArray))
		assert.Len(t, asArray, 3, "SessionTranscript = [DeviceEngagementBytes/null, EReaderKeyBytes/null, Handover]")
		assert.Equal(t, []byte(transcript), []byte(deviceAuth[1]),
			"and it is the caller's transcript spliced in unchanged")
	})

	t.Run("element 3 is #6.24-tagged", func(t *testing.T) {
		var tag cbor.Tag
		require.NoError(t, cbor.Unmarshal(deviceAuth[3], &tag))
		assert.EqualValues(t, 24, tag.Number,
			"DeviceNameSpacesBytes = #6.24(bstr .cbor DeviceNameSpaces)")
		content, ok := tag.Content.([]byte)
		require.True(t, ok)
		assert.Equal(t, namespaces, content)
	})
}

// A transcript that is not CBOR is refused rather than wrapped in a byte
// string, which is how arbitrary bytes used to pass through and produce a
// structure no reader could verify.
func TestDeviceAuthenticationRefusesANonCBORTranscript(t *testing.T) {
	for _, tc := range []struct {
		name  string
		bytes []byte
	}{
		// This is what the tests in this package used to pass, and it is
		// the realistic case: a plain string whose first byte happens to
		// be a CBOR header, leaving trailing bytes.
		{"a plain string with trailing bytes", []byte("test session transcript")},
		{"a break stop code, which is not a standalone item", []byte{0xff}},
		{"a truncated array header", []byte{0x83, 0x01}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := buildDeviceAuthenticationBytes(tc.bytes, "d", nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "not a CBOR item")
		})
	}

	// Note what is NOT refused: "not cbor at all" IS valid CBOR - 0x6E is a
	// 14-byte text-string header and exactly 14 bytes follow. This check is
	// about well-formedness, not about the transcript being sensible, and
	// claiming otherwise would overstate it.
	_, err := buildDeviceAuthenticationBytes([]byte("not cbor at all"), "d", nil)
	assert.NoError(t, err)
}

// The conformant and legacy encodings must differ - otherwise the
// compatibility path is meaningless and the fix changed nothing.
func TestLegacyAndConformantEncodingsDiffer(t *testing.T) {
	transcript := testSessionTranscript()
	conformant, err := buildDeviceAuthenticationBytes(transcript, "d", nil)
	require.NoError(t, err)
	legacy, err := buildLegacyDeviceAuthenticationBytes(transcript, "d", nil)
	require.NoError(t, err)
	assert.NotEqual(t, conformant, legacy)
}

// A presentation built by a pre-fix build of this code must still verify,
// so a wallet in the field keeps working while the fix propagates - and a
// forged one must still be refused, so the compatibility path is not a way
// in.
func TestLegacyPresentationsStillVerify(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	transcript := testSessionTranscript()
	encoder, err := NewCBOREncoder()
	require.NoError(t, err)
	namespaces, err := encoder.Marshal(map[string]any{})
	require.NoError(t, err)

	legacyBytes, err := buildLegacyDeviceAuthenticationBytes(transcript, DocType, namespaces)
	require.NoError(t, err)
	sign1, err := Sign1Detached(legacyBytes, key, AlgorithmES256, nil, nil)
	require.NoError(t, err)

	deviceSigned := &DeviceSignedMdoc{
		NameSpaces: cbor.Tag{Number: 24, Content: namespaces},
	}
	deviceSigned.DeviceAuth.DeviceSignature = []any{
		sign1.Protected, sign1.Unprotected, nil, sign1.Signature,
	}

	verifier := NewDeviceAuthVerifier(transcript, DocType)
	assert.NoError(t, verifier.VerifySignature(deviceSigned, &key.PublicKey),
		"a presentation from a pre-fix build must not stop working mid-rollout")

	t.Run("and a forgery is still refused", func(t *testing.T) {
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		assert.Error(t, verifier.VerifySignature(deviceSigned, &other.PublicKey),
			"the compatibility path must not accept a signature from the wrong key")
	})

	t.Run("and a different transcript is still refused", func(t *testing.T) {
		elsewhere, err := encoder.Marshal([]any{nil, nil, "a-different-handover"})
		require.NoError(t, err)
		assert.Error(t, NewDeviceAuthVerifier(elsewhere, DocType).VerifySignature(deviceSigned, &key.PublicKey),
			"legacy acceptance must still bind to the session")
	})
}

// A pre-fix DeviceMac carries the legacy DeviceAuthenticationBytes INLINE.
// Its MAC therefore verifies over the attached payload without the detached
// fallback ever running - so comparing the payload only against the
// conformant encoding rejected exactly the presentations the compatibility
// path exists for.
func TestLegacyAttachedMACStillVerifies(t *testing.T) {
	sessionKey := make([]byte, 32)
	_, err := rand.Read(sessionKey)
	require.NoError(t, err)

	transcript := testSessionTranscript()
	encoder, err := NewCBOREncoder()
	require.NoError(t, err)
	namespaces, err := encoder.Marshal(map[string]any{})
	require.NoError(t, err)

	legacyBytes, err := buildLegacyDeviceAuthenticationBytes(transcript, DocType, namespaces)
	require.NoError(t, err)
	mac0, err := Mac0(legacyBytes, sessionKey, AlgorithmHMAC256, nil)
	require.NoError(t, err)

	build := func(payload any) *DeviceSignedMdoc {
		d := &DeviceSignedMdoc{NameSpaces: cbor.Tag{Number: 24, Content: namespaces}}
		d.DeviceAuth.DeviceMac = []any{mac0.Protected, mac0.Unprotected, payload, mac0.Tag}
		return d
	}

	verifier := NewDeviceAuthVerifier(transcript, DocType)
	assert.NoError(t, verifier.VerifyMAC(build(legacyBytes), sessionKey),
		"the old attached-MAC layout is exactly what a pre-fix build produced")

	t.Run("a wrong session key is still refused", func(t *testing.T) {
		other := make([]byte, 32)
		_, err := rand.Read(other)
		require.NoError(t, err)
		assert.Error(t, verifier.VerifyMAC(build(legacyBytes), other))
	})

	t.Run("a wrong transcript is still refused", func(t *testing.T) {
		elsewhere, err := encoder.Marshal([]any{nil, nil, "a-different-handover"})
		require.NoError(t, err)
		assert.Error(t, NewDeviceAuthVerifier(elsewhere, DocType).VerifyMAC(build(legacyBytes), sessionKey),
			"compatibility must not cost the session binding")
	})

	t.Run("an attached payload that is neither encoding is refused", func(t *testing.T) {
		assert.Error(t, verifier.VerifyMAC(build([]byte("something else entirely")), sessionKey))
	})
}

// An empty byte string is valid COSE content and a DIFFERENT thing from an
// absent payload. Conflating them would reject a MAC legitimately computed
// over h”, and would let detached content silently stand in for an
// attached empty payload - a different message with a different tag.
func TestEmptyPayloadIsNotAnAbsentPayload(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	mac0, err := Mac0([]byte{}, key, AlgorithmHMAC256, nil)
	require.NoError(t, err)
	require.NotNil(t, mac0.Payload)
	require.Empty(t, mac0.Payload)

	assert.NoError(t, VerifyCOSEMac0(mac0, key, nil, nil),
		"a MAC over an empty payload verifies on its own terms")

	assert.NoError(t, VerifyCOSEMac0(mac0, key, []byte("detached"), nil),
		"and the attached empty payload wins over detached content rather than being replaced by it")

	t.Run("neither attached nor detached is refused", func(t *testing.T) {
		absent := &COSEMac0{Protected: mac0.Protected, Unprotected: mac0.Unprotected, Payload: nil, Tag: mac0.Tag}
		err := VerifyCOSEMac0(absent, key, nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "nothing it authenticates")
	})
}

// The built DeviceMac's payload must encode as CBOR null (0xf6).
//
// Asserted on the ENCODED byte because nothing else can see it. ISO 18013-5
// 9.1.3.4 requires a null payload with the content detached; the existing
// builder tests check only that a MAC is present, and verification
// deliberately accepts an attached payload for compatibility - so restoring
// the inline payload would satisfy every other test here while putting a
// non-conformant message on the wire.
//
// That is the same shape as the defect this whole change fixes: a check
// that cannot observe the thing it is meant to protect.
func TestBuiltDeviceMACPayloadIsCBORNull(t *testing.T) {
	sessionKey := make([]byte, 32)
	_, err := rand.Read(sessionKey)
	require.NoError(t, err)

	deviceSigned, err := NewDeviceAuthBuilder(DocType).
		WithSessionTranscript(testSessionTranscript()).
		WithSessionKey(sessionKey).
		Build()
	require.NoError(t, err)
	require.NotEmpty(t, deviceSigned.DeviceAuth.DeviceMac)

	encoder, err := NewCBOREncoder()
	require.NoError(t, err)
	encoded, err := encoder.Marshal(deviceSigned.DeviceAuth.DeviceMac)
	require.NoError(t, err)

	var elements []cbor.RawMessage
	require.NoError(t, cbor.Unmarshal(encoded, &elements))
	require.Len(t, elements, 4, "COSE_Mac0 = [protected, unprotected, payload, tag]")

	assert.Equal(t, []byte{0xf6}, []byte(elements[2]),
		"the payload must be CBOR null; the detached content is DeviceAuthenticationBytes")
}

// Normalising on the VERIFICATION path is a bypass: the verifier must
// reconstruct from exactly what the presentation carries, never from a
// tidied-up version of it.
//
// Both encoding helpers replaced a non-nil empty namespace content (h”)
// with the encoded empty map (h'a0'). extractDeviceNameSpacesBytes passes
// the tag content through unchanged, so an attacker could rewrite a
// presentation's namespaces from h'a0' to h” and the verifier would
// rebuild the ORIGINAL authenticated bytes and report success on a message
// that had been modified.
func TestMutatedEmptyNamespacesAreRefused(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	sessionKey := make([]byte, 32)
	_, err = rand.Read(sessionKey)
	require.NoError(t, err)

	transcript := testSessionTranscript()
	encoder, err := NewCBOREncoder()
	require.NoError(t, err)
	namespaces, err := encoder.Marshal(map[string]any{})
	require.NoError(t, err)
	verifier := NewDeviceAuthVerifier(transcript, DocType)

	for _, tc := range []struct {
		name  string
		build func() ([]byte, error)
	}{
		{"conformant", func() ([]byte, error) {
			return buildDeviceAuthenticationBytes(transcript, DocType, namespaces)
		}},
		{"legacy", func() ([]byte, error) {
			return buildLegacyDeviceAuthenticationBytes(transcript, DocType, namespaces)
		}},
	} {
		t.Run(tc.name+" signature", func(t *testing.T) {
			authBytes, err := tc.build()
			require.NoError(t, err)
			sign1, err := Sign1Detached(authBytes, key, AlgorithmES256, nil, nil)
			require.NoError(t, err)

			// The mutation: h'a0' becomes h''.
			mutated := &DeviceSignedMdoc{NameSpaces: cbor.Tag{Number: 24, Content: []byte{}}}
			mutated.DeviceAuth.DeviceSignature = []any{sign1.Protected, sign1.Unprotected, nil, sign1.Signature}

			assert.Error(t, verifier.VerifySignature(mutated, &key.PublicKey),
				"a presentation whose authenticated namespaces were rewritten must not verify")
		})

		t.Run(tc.name+" MAC", func(t *testing.T) {
			authBytes, err := tc.build()
			require.NoError(t, err)
			mac0, err := Mac0(authBytes, sessionKey, AlgorithmHMAC256, nil)
			require.NoError(t, err)

			mutated := &DeviceSignedMdoc{NameSpaces: cbor.Tag{Number: 24, Content: []byte{}}}
			mutated.DeviceAuth.DeviceMac = []any{mac0.Protected, mac0.Unprotected, nil, mac0.Tag}

			assert.Error(t, verifier.VerifyMAC(mutated, sessionKey),
				"same mutation, same refusal, on the MAC path")
		})
	}
}
