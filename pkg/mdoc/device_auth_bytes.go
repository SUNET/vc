package mdoc

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// encodedCBORTag is CBOR tag 24, "encoded CBOR data item" (RFC 8949 3.4.5.1).
// ISO 18013-5 writes it #6.24 and uses it wherever a structure must be signed
// over exactly the bytes a peer reconstructs.
const encodedCBORTag = 24

// buildDeviceAuthenticationBytes returns DeviceAuthenticationBytes, the
// detached content a DeviceSignature or DeviceMac is computed over.
//
// ISO 18013-5:2021 9.1.3.4:
//
//	DeviceAuthenticationBytes = #6.24(bstr .cbor DeviceAuthentication)
//	DeviceAuthentication = [
//	    "DeviceAuthentication",
//	    SessionTranscript,        ; the ARRAY from 12.6.1, inline
//	    DocType,
//	    DeviceNameSpacesBytes     ; = #6.24(bstr .cbor DeviceNameSpaces)
//	]
//
// sessionTranscript and deviceNameSpaces arrive already CBOR-encoded, which
// is why both need care: placing a Go []byte in a []any encodes a byte
// STRING, so the transcript has to be spliced in as a raw item and the
// namespaces have to be tagged rather than passed through.
//
// This build previously got all three wrong - an untagged transcript byte
// string, untagged namespaces, and no #6.24 around the whole array - and
// nothing caught it because the verifier rebuilt the same wrong shape, so
// the two agreed with each other and disagreed with the specification. Both
// wallet SDKs already emit the conformant shape, which is why they passed
// proximity interop while this did not.
func buildDeviceAuthenticationBytes(sessionTranscript []byte, docType string, deviceNameSpaces []byte) ([]byte, error) {
	encoder, err := NewCBOREncoder()
	if err != nil {
		return nil, err
	}
	deviceNameSpaces, err = normaliseDeviceNameSpaces(encoder, deviceNameSpaces)
	if err != nil {
		return nil, err
	}
	if len(sessionTranscript) == 0 {
		return nil, fmt.Errorf("device authentication needs a session transcript")
	}
	// It has to BE a CBOR item, because it is spliced in as one. The
	// previous encoding wrapped whatever it was given in a byte string, so
	// arbitrary bytes were accepted and produced a structure no conformant
	// reader could verify.
	var probe cbor.RawMessage
	if err := cbor.Unmarshal(sessionTranscript, &probe); err != nil {
		return nil, fmt.Errorf("the session transcript is not a CBOR item, so it cannot be embedded in DeviceAuthentication (ISO 18013-5 9.1.3.4): %w", err)
	}

	deviceAuth := []any{
		"DeviceAuthentication",
		// RawMessage splices the already-encoded SessionTranscript array in
		// as a CBOR item. A []byte here would encode as a byte string
		// wrapping it, which is a different document and a different
		// signature.
		cbor.RawMessage(sessionTranscript),
		docType,
		cbor.Tag{Number: encodedCBORTag, Content: deviceNameSpaces},
	}

	inner, err := encoder.Marshal(deviceAuth)
	if err != nil {
		return nil, fmt.Errorf("encoding DeviceAuthentication: %w", err)
	}
	// And the whole thing is itself an encoded CBOR data item.
	outer, err := encoder.Marshal(cbor.Tag{Number: encodedCBORTag, Content: inner})
	if err != nil {
		return nil, fmt.Errorf("encoding DeviceAuthenticationBytes: %w", err)
	}
	return outer, nil
}

// buildLegacyDeviceAuthenticationBytes reproduces the shape this build
// emitted before the conformance fix: the transcript as a byte string, the
// namespaces untagged, and no #6.24 around the array.
//
// It exists only so the verifier can still accept a presentation produced by
// an older build of THIS code. Nothing should sign with it, and it should be
// deleted once no such presentation can still be in flight.
func buildLegacyDeviceAuthenticationBytes(sessionTranscript []byte, docType string, deviceNameSpaces []byte) ([]byte, error) {
	encoder, err := NewCBOREncoder()
	if err != nil {
		return nil, err
	}
	deviceNameSpaces, err = normaliseDeviceNameSpaces(encoder, deviceNameSpaces)
	if err != nil {
		return nil, err
	}
	return encoder.Marshal([]any{
		"DeviceAuthentication",
		sessionTranscript,
		docType,
		deviceNameSpaces,
	})
}

// normaliseDeviceNameSpaces supplies the encoded empty map when a caller
// has no namespaces, and refuses a present-but-empty one.
//
// nil and h” are different things here, and the difference is a bypass.
// nil is a BUILDER saying it has no namespaces to disclose. h” comes from
// a PRESENTATION, via extractDeviceNameSpacesBytes, which passes the tag
// content through unchanged - and substituting the encoded empty map for
// it would reconstruct bytes the presentation does not carry. An attacker
// rewriting a presentation's namespaces from h'a0' to h” would then have
// the verifier rebuild the ORIGINAL authenticated bytes and report
// success on a message that had been modified.
//
// So the empty map is supplied only for an absent value, and a present
// empty one is refused: h” is not a DeviceNameSpaces encoding under any
// reading.
func normaliseDeviceNameSpaces(encoder *CBOREncoder, deviceNameSpaces []byte) ([]byte, error) {
	if deviceNameSpaces == nil {
		encoded, err := encoder.Marshal(map[string]any{})
		if err != nil {
			return nil, fmt.Errorf("encoding empty device namespaces: %w", err)
		}
		return encoded, nil
	}
	if len(deviceNameSpaces) == 0 {
		return nil, fmt.Errorf("device namespaces are present but empty, which is not a DeviceNameSpaces encoding; " +
			"reconstructing from a substituted value would authenticate bytes the presentation does not carry")
	}
	return deviceNameSpaces, nil
}
