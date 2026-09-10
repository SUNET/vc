package apiv1

import "github.com/SUNET/vc/pkg/mdoc"

// zkSessionTranscript builds the SessionTranscript a ZK proof must be
// verified against, choosing the handover by how the response arrived.
//
// The two handovers hash different things and a wallet only ever produced
// one of them, so picking the wrong one fails every proof from that channel
// with an opaque proof error rather than a wiring error (SUNET/vc#652,
// SUNET/vc#655). origin is used only on the DC API branch, and is resolved
// by the caller so that a link-delivered response never depends on the DC
// API origin being configurable at all.
//
// Extracted from VerificationDirectPost so the choice can be tested without
// a valid Vega proof: verifying one end to end needs the native prover, and
// the selection happens before verification, so a test that stopped at the
// transcript would still be the only thing covering this flag.
func zkSessionTranscript(dcAPI bool, origin, clientID, nonce, responseURI string, readerPubKeyThumbprint []byte) ([]byte, error) {
	if dcAPI {
		return mdoc.BuildOID4VPDCAPISessionTranscript(origin, nonce, readerPubKeyThumbprint)
	}
	return mdoc.BuildOID4VPSessionTranscript(clientID, nonce, responseURI, readerPubKeyThumbprint)
}
