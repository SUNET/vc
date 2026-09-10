package mdoc

import (
	"crypto/sha256"
	"fmt"
)

// BuildOID4VPSessionTranscript builds the ISO 18013-5 SessionTranscript CBOR
// structure for the OpenID4VP browser-redirect flow (a response_uri is
// present; this is OpenID4VP 1.0 §B.2.6.1 "Invocation via Redirects" -
// see multipaz's OpenID4VP.kt Version.DRAFT_29 branch, which this mirrors
// exactly; multipaz's DRAFT_29 tag corresponds to the frozen 1.0 text). It is needed by both plain "mso_mdoc" device-signature checks
// and "mso_mdoc_zk" ZK proof verification (see ZkPresentationContext.
// SessionTranscript) - vc-verifier does not otherwise build one anywhere
// today.
//
//	SessionTranscript = [
//	  null,                              // DeviceEngagementBytes (not used in this flow)
//	  null,                              // EReaderKeyBytes (not used in this flow)
//	  ["OpenID4VPHandover", SHA256(handoverInfo)],
//	]
//	handoverInfo = [clientID, nonce, readerPublicKeyJWKThumbprint, responseURI]
//
// readerPublicKeyJWKThumbprint is nil unless the request advertised an
// encryption key for the response (nil is the common case for a
// direct_post-only flow); pass it if/when vc-verifier's request object
// includes one.
//
// NOT independently verified against a real device's own transcript bytes -
// this is spec-derived, best-effort plumbing for the native ZK verify call.
// Confirm against a real wallet before relying on it for anything that
// actually checks a cryptographic binding.
func BuildOID4VPSessionTranscript(clientID, nonce, responseURI string, readerPublicKeyJWKThumbprint []byte) ([]byte, error) {
	// Use the package's canonical CBOR encoder (NewCBOREncoder), not the
	// cbor library's plain package-level Marshal, for the same reason every
	// other CBOR encode call site in this package does: the wallet/prover
	// side that this must byte-match also encodes canonically, so any
	// mismatch here (e.g. a future field becoming map-shaped) could
	// silently make otherwise-valid proofs fail verification.
	encoder, err := NewCBOREncoder()
	if err != nil {
		return nil, fmt.Errorf("failed to create CBOR encoder: %w", err)
	}

	var jwkThumbprint any
	if readerPublicKeyJWKThumbprint != nil {
		jwkThumbprint = readerPublicKeyJWKThumbprint
	}

	handoverInfo, err := encoder.Marshal([]any{clientID, nonce, jwkThumbprint, responseURI})
	if err != nil {
		return nil, fmt.Errorf("failed to encode handoverInfo: %w", err)
	}
	handoverInfoDigest := sha256.Sum256(handoverInfo)

	transcript, err := encoder.Marshal([]any{nil, nil, []any{"OpenID4VPHandover", handoverInfoDigest[:]}})
	if err != nil {
		return nil, fmt.Errorf("failed to encode SessionTranscript: %w", err)
	}
	return transcript, nil
}

// BuildOID4VPDCAPISessionTranscript builds the SessionTranscript for a
// presentation delivered through the browser's Digital Credentials API
// (OpenID4VP 1.0 §B.2.6.2 "Invocation via the Digital Credentials API").
//
//	SessionTranscript = [
//	  null,                                  // DeviceEngagementBytes
//	  null,                                  // EReaderKeyBytes
//	  ["OpenID4VPDCAPIHandover", SHA256(handoverInfo)],
//	]
//	handoverInfo = [origin, nonce, readerPublicKeyJWKThumbprint]
//
// Three differences from the redirect flow's handover, each of which makes
// the two transcripts incompatible - so the caller has to pick by how the
// response actually arrived, not by which is convenient:
//
//   - the calling web origin replaces the response URI, and comes first;
//   - there is no clientID member at all;
//   - the label is OpenID4VPDCAPIHandover.
//
// nonce is the request's nonce exactly as it appeared on the wire. multipaz
// models it as raw bytes and base64url-encodes it here, and an OpenID4VP
// request's nonce parameter is that same base64url text, so passing the
// string through is the same value - see VerificationUtil.kt's own doc
// ("For OpenID4VP, this will be base64url-encoded without padding").
//
// readerPublicKeyJWKThumbprint is nil when the request advertised no
// encryption key, and encodes as CBOR null in that case rather than being
// omitted: the array is three elements either way.
//
// Layout taken from multipaz's VerificationUtil.kt, which is the upstream
// reference implementation, rather than from reading the specification -
// see BuildOID4VPSessionTranscript above for what happens otherwise. It is
// still not confirmed against bytes captured from a live wallet session;
// SUNET/vc#655 tracks getting that capture.
func BuildOID4VPDCAPISessionTranscript(origin, nonce string, readerPublicKeyJWKThumbprint []byte) ([]byte, error) {
	if origin == "" {
		// The origin is the whole point of this handover: it is what binds
		// the presentation to the page that asked for it. An empty one would
		// produce a transcript that hashes cleanly and means nothing.
		return nil, fmt.Errorf("mdoc: DC API session transcript requires the calling origin")
	}

	encoder, err := NewCBOREncoder()
	if err != nil {
		return nil, fmt.Errorf("failed to create CBOR encoder: %w", err)
	}

	var jwkThumbprint any
	if readerPublicKeyJWKThumbprint != nil {
		jwkThumbprint = readerPublicKeyJWKThumbprint
	}

	handoverInfo, err := encoder.Marshal([]any{origin, nonce, jwkThumbprint})
	if err != nil {
		return nil, fmt.Errorf("failed to encode DC API handoverInfo: %w", err)
	}
	handoverInfoDigest := sha256.Sum256(handoverInfo)

	transcript, err := encoder.Marshal([]any{nil, nil, []any{"OpenID4VPDCAPIHandover", handoverInfoDigest[:]}})
	if err != nil {
		return nil, fmt.Errorf("failed to encode DC API SessionTranscript: %w", err)
	}
	return transcript, nil
}
