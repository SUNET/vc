// Package verifier builds the nym_auth circuit verifier's request and
// checks its policy inputs.
//
// It holds the parts that need no native library: the challenge message
// the circuits bind a presentation to, the age bounds a request asks
// for, and the rules about which of these a Verifier may take from the
// holder (none of them). The native proof check is behind the zknative
// build tag - see the zknative/stub pair in pkg/mdoc for the shape.
//
// Every value here is the VERIFIER'S. T comes from its own clock, the
// age bounds from its own policy, e2 from its own session, and
// verifier_input from its own identity. Taking any of them from the
// holder's response would let the holder choose what it is proving.
package verifier

import (
	"crypto/sha256"
	"fmt"

	"github.com/SUNET/vc/pkg/mdoc"

	"github.com/fxamacker/cbor/v2"
)

// coseProtectedES256 is the COSE protected header the circuits fix for
// the device signature: {1: -7}, ES256. Serialised, because that is what
// the Sig_structure carries.
var coseProtectedES256 = []byte{0xa1, 0x01, 0x26}

// MinNonceChars is the shortest request nonce the challenge accepts.
//
// The nonce is what makes a proof THIS session's rather than a replay of
// an earlier one, so its length is the entropy of that binding. The
// shared vectors fix the floor at 16 characters; both native bindings
// refuse a shorter one, and so does this, because a verifier that
// accepted one would build a challenge no prover will match and read the
// resulting failure as a bad proof.
const MinNonceChars = 16

// jwkThumbprintBytes is the length of a reader public key JWK
// thumbprint, when the request advertised an encryption key. SHA-256, so
// exactly 32 bytes; any other length is a different value and refused
// rather than hashed.
const jwkThumbprintBytes = 32

// MdocSessionTranscript builds the SessionTranscript the circuits bind
// to, for a presentation delivered through the Digital Credentials API.
//
//	SessionTranscript = cbor([null, null,
//	    ["OpenID4VPDCAPIHandover", bstr(SHA-256(cbor([origin, nonce, thumbprint])))]])
//
// From the verifier's OWN session - the origin it served the page from
// and the nonce it issued - never from anything the response carries. A
// transcript derived from the holder's values would be a proof that the
// holder chose what to prove.
func MdocSessionTranscript(origin, nonce string, jwkThumbprint []byte) ([]byte, error) {
	if origin == "" {
		return nil, fmt.Errorf("nymauth: the challenge needs the calling origin, which is what binds the proof to the page that asked for it")
	}
	if nonce == "" {
		return nil, fmt.Errorf("nymauth: the challenge needs the request nonce, which is what makes it this session's proof")
	}
	if len([]rune(nonce)) < MinNonceChars {
		return nil, fmt.Errorf("nymauth: the request nonce is %d characters; the shared vectors require at least %d, and a shorter one weakens the only thing binding this proof to this session",
			len([]rune(nonce)), MinNonceChars)
	}
	if jwkThumbprint != nil && len(jwkThumbprint) != jwkThumbprintBytes {
		return nil, fmt.Errorf("nymauth: the reader key thumbprint is %d bytes; a SHA-256 thumbprint is %d, and hashing another length would produce a transcript no wallet reproduces",
			len(jwkThumbprint), jwkThumbprintBytes)
	}
	transcript, err := mdoc.BuildOID4VPDCAPISessionTranscript(origin, nonce, jwkThumbprint)
	if err != nil {
		return nil, fmt.Errorf("nymauth: session transcript: %w", err)
	}
	return transcript, nil
}

// MdocSessionTranscriptRedirect builds the SessionTranscript the
// circuits bind to, for a presentation delivered by REDIRECT - a
// scanned QR or a link, where the wallet POSTs to response_uri.
//
//	SessionTranscript = cbor([null, null,
//	    ["OpenID4VPHandover", bstr(SHA-256(cbor([clientID, nonce, thumbprint, responseURI])))]])
//
// OpenID4VP 1.0 appendix B.2.6.1, and the shared derive_redirect
// vectors. A separate entry point from MdocSessionTranscript rather
// than a flag on it, because the two handovers are different
// structures and a verifier that picked the wrong one would get an
// opaque proof failure instead of a legible wiring error.
//
// From the verifier's OWN session - the client_id it published, the
// nonce it issued, the response_uri it is listening on - never from
// anything the response carries.
//
// THE THUMBPRINT IS REQUIRED HERE, and 32 bytes. Over a redirect the
// response must be encrypted (direct_post.jwt), so there is always a
// reader key and always a thumbprint of it; a nil one would mean an
// unencrypted response, which this flow does not allow. That is the
// one place this is stricter than mdoc.BuildOID4VPSessionTranscript,
// which takes nil for the general OpenID4VP case - and it is why the
// nil case is in the shared rejects_redirect vectors rather than
// being left to each implementation to decide.
//
// The rules for the response mode itself are not enforced here; this
// function sees only the values. See the caller in
// internal/verifier/apiv1, which refuses a redirect response that did
// not use direct_post.jwt before it ever gets here.
func MdocSessionTranscriptRedirect(clientID, nonce, responseURI string, jwkThumbprint []byte) ([]byte, error) {
	if clientID == "" {
		return nil, fmt.Errorf("nymauth: the challenge needs the request's client_id, which is what binds the proof to the verifier that asked for it")
	}
	if nonce == "" {
		return nil, fmt.Errorf("nymauth: the challenge needs the request nonce, which is what makes it this session's proof")
	}
	if len([]rune(nonce)) < MinNonceChars {
		return nil, fmt.Errorf("nymauth: the request nonce is %d characters; the shared vectors require at least %d, and a shorter one weakens the only thing binding this proof to this session",
			len([]rune(nonce)), MinNonceChars)
	}
	if responseURI == "" {
		return nil, fmt.Errorf("nymauth: the challenge needs the response_uri, which is what binds the proof to where this verifier is listening")
	}
	if len(jwkThumbprint) != jwkThumbprintBytes {
		// Nil included, and deliberately not "nil means unencrypted".
		// Over a redirect an unencrypted response is not allowed, so
		// a missing thumbprint is a request that should never have
		// been sent rather than a variant to accommodate.
		return nil, fmt.Errorf("nymauth: the reader key thumbprint is %d bytes; a redirect presentation is always encrypted, so it is a %d-byte SHA-256 thumbprint, and anything else would produce a transcript no wallet reproduces",
			len(jwkThumbprint), jwkThumbprintBytes)
	}
	transcript, err := mdoc.BuildOID4VPSessionTranscript(clientID, nonce, responseURI, jwkThumbprint)
	if err != nil {
		return nil, fmt.Errorf("nymauth: session transcript: %w", err)
	}
	return transcript, nil
}

// MdocChallenge returns the bytes an mdoc device signature is computed
// over, for a SessionTranscript the caller already holds.
//
// nym-auth-circuits SPEC section 3:
//
//	DeviceAuthenticationBytes = #6.24(bstr(cbor(["DeviceAuthentication",
//	    SessionTranscript, docType, #6.24(bstr(h'A0'))])))
//	message = cbor(["Signature1", bstr(h'A10126'), bstr(h''),
//	    bstr(DeviceAuthenticationBytes)])
//
// The transcript and DeviceAuthenticationBytes come from pkg/mdoc rather
// than being re-derived here, because this has to be byte-identical to
// what the wallet signed and a second implementation of a CBOR shape is
// how two of them drift apart.
func MdocChallenge(sessionTranscript []byte, docType string) ([]byte, error) {
	if err := checkSessionTranscript(sessionTranscript); err != nil {
		return nil, err
	}
	if docType == "" {
		return nil, fmt.Errorf("nymauth: the challenge needs the docType, which is what binds the proof to this credential type")
	}

	// nil deviceNameSpaces is the empty DeviceNameSpaces the circuits
	// specify - #6.24(bstr(h'A0')).
	deviceAuth, err := mdoc.BuildDeviceAuthenticationBytes(sessionTranscript, docType, nil)
	if err != nil {
		return nil, fmt.Errorf("nymauth: device authentication: %w", err)
	}

	encoder, err := mdoc.NewCBOREncoder()
	if err != nil {
		return nil, fmt.Errorf("nymauth: %w", err)
	}
	// Sig_structure for a COSE_Sign1 with detached payload: the external
	// AAD is empty and the payload is the DeviceAuthenticationBytes.
	message, err := encoder.Marshal([]any{
		"Signature1",
		coseProtectedES256,
		[]byte{},
		deviceAuth,
	})
	if err != nil {
		return nil, fmt.Errorf("nymauth: encoding the signature structure: %w", err)
	}
	return message, nil
}

// MdocChallengeDigest is SHA-256 of MdocChallenge: the circuits' e2.
func MdocChallengeDigest(sessionTranscript []byte, docType string) ([32]byte, error) {
	message, err := MdocChallenge(sessionTranscript, docType)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(message), nil
}

// MdocE2 derives the transcript from this session and returns its
// challenge digest - the two steps the native bindings call
// nymauth_derive_challenge and nymauth_challenge_digest.
func MdocE2(origin, nonce, docType string, jwkThumbprint []byte) ([32]byte, error) {
	transcript, err := MdocSessionTranscript(origin, nonce, jwkThumbprint)
	if err != nil {
		return [32]byte{}, err
	}
	return MdocChallengeDigest(transcript, docType)
}

// MdocE2Redirect derives the redirect handover's transcript from this
// session and returns its challenge digest.
//
// The digest step is the same for either handover - only the
// transcript differs - so this is MdocSessionTranscriptRedirect
// followed by the same MdocChallengeDigest the DC API path uses.
func MdocE2Redirect(clientID, nonce, responseURI, docType string, jwkThumbprint []byte) ([32]byte, error) {
	transcript, err := MdocSessionTranscriptRedirect(clientID, nonce, responseURI, jwkThumbprint)
	if err != nil {
		return [32]byte{}, err
	}
	return MdocChallengeDigest(transcript, docType)
}

// checkSessionTranscript refuses a transcript that is not exactly one
// three-item CBOR array.
//
// Each of these is in the shared reject vectors, and each would
// otherwise hash cleanly into a challenge no prover reproduces - which
// surfaces as a failed proof rather than as the malformed input it is:
//
//   - empty;
//   - a CBOR item that is not a 3-item array;
//   - a valid array with TRAILING bytes, which a lenient decode ignores;
//   - a truncated item.
func checkSessionTranscript(sessionTranscript []byte) error {
	if len(sessionTranscript) == 0 {
		return fmt.Errorf("nymauth: the challenge needs a session transcript")
	}
	var items []cbor.RawMessage
	if err := cbor.Unmarshal(sessionTranscript, &items); err != nil {
		// Covers truncation and trailing bytes: fxamacker reports both
		// rather than decoding a prefix.
		return fmt.Errorf("nymauth: the session transcript is not a single CBOR array: %w", err)
	}
	if len(items) != sessionTranscriptItems {
		return fmt.Errorf("nymauth: the session transcript has %d items; ISO 18013-5 fixes it at %d",
			len(items), sessionTranscriptItems)
	}

	// And the CONTENTS, which the decode above does not look at.
	//
	// A cbor.RawMessage is bytes: fxamacker checks the shape of each
	// item but not what is inside it, so a text string holding
	// invalid UTF-8 decodes into one without complaint. That is not a
	// curiosity - it is the same failure as every other case here. An
	// ill-formed transcript hashes perfectly cleanly into a challenge
	// no prover reproduces, and the resulting mismatch is reported as
	// a bad proof rather than as the malformed input it is.
	//
	// Decoding into `any` forces each item to be interpreted, which
	// is what applies the UTF-8 check.
	var contents []any
	if err := cbor.Unmarshal(sessionTranscript, &contents); err != nil {
		return fmt.Errorf("nymauth: the session transcript is not well-formed CBOR: %w", err)
	}
	return nil
}

// sessionTranscriptItems is the fixed length of a SessionTranscript
// array: DeviceEngagementBytes, EReaderKeyBytes, Handover.
const sessionTranscriptItems = 3
