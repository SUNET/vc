package mdoc

import (
	"crypto/sha256"
	"fmt"
)

// BuildOID4VPSessionTranscript builds the ISO 18013-5 SessionTranscript CBOR
// structure for the OpenID4VP browser-redirect flow (a response_uri is
// present; this is OpenID4VP Draft 29's "Invocation via Redirects" case -
// see multipaz's OpenID4VP.kt Version.DRAFT_29 branch, which this mirrors
// exactly). It is needed by both plain "mso_mdoc" device-signature checks
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
