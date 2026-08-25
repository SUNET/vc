//go:build !zknative

package mdoc

// This file provides the default (no "zknative" build tag) implementations
// of nativeVerifyZkProof/nativeVerifyZkProofWithPPID: stubs that always
// return ErrNativeZkVerifyNotImplemented. This is what every existing
// vc-verifier build gets today (CGO_ENABLED=0, fully static) - see
// zk_native_cgo.go for the real, cgo-backed implementation, opt-in via
// `-tags zknative` (mirrors pkg/pki's PKCS#11 support: pkcs11_stub.go vs
// pkcs11.go).
//
// Every check upstream of this call (trust chain, zk_system_type matching,
// argument assembly, verifier_context derivation - see zk_verifier.go) is
// real and already runs before either of these functions is reached.

import (
	"context"

	"github.com/SUNET/vc/pkg/mdoc/zkvegaworker"
)

// nativeVerifyZkProof is the (stubbed) call site for a non-PPID native ZK
// verify. See docs/ZK_PPID_VERIFICATION_PLAN.md for what a real binding
// needs; see zk_native_cgo.go's own doc comment for why this direction
// (no pairwise pseudonym) remains stubbed even with "zknative" set:
// zk-cred-longfellow's Go-facing C ABI (src/go_ffi.rs) only exports
// rust_verify_with_ppid today, not a plain non-PPID verify.
func nativeVerifyZkProof(
	ctx context.Context,
	zkSystemID string,
	issuerPublicKeySEC1 []byte,
	attributes []ZkAttribute,
	docType string,
	deviceNameSpacesBytes []byte,
	sessionTranscript []byte,
	timeStr string,
	proof []byte,
	zkCircuitSources []string,
) error {
	return ErrNativeZkVerifyNotImplemented
}

// nativeVerifyZkProofWithPPID is the (stubbed) call site for
// verify_with_ppid, for a document that disclosed a pairwise_pseudonym
// attribute (V8 circuits only). Real with the "zknative" build tag - see
// zk_native_cgo.go.
func nativeVerifyZkProofWithPPID(
	ctx context.Context,
	zkSystemID string,
	issuerPublicKeySEC1 []byte,
	attributes []ZkAttribute,
	docType string,
	deviceNameSpacesBytes []byte,
	sessionTranscript []byte,
	timeStr string,
	verifierContext []byte,
	proof []byte,
	zkCircuitSources []string,
) error {
	return ErrNativeZkVerifyNotImplemented
}

// nativeVerifyZkProofVega is the (stubbed) call site for Vega verification.
// Real with the "zknative" build tag - see zk_native_cgo_vega.go.
func nativeVerifyZkProofVega(
	ctx context.Context,
	zkSystemID string,
	proof []byte,
	zkCircuitSources []string,
	workerPath string,
) (zkvegaworker.VerifyResult, error) {
	return zkvegaworker.VerifyResult{}, ErrNativeZkVerifyNotImplemented
}
