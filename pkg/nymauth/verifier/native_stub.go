//go:build !zknative

package verifier

// This file is what every default build of this repo gets: no cgo, no
// zk-cred-longfellow, and so no way to check a nym_auth proof. See
// native_cgo.go for the real implementation, opt-in via `-tags
// zknative` (the same shape as pkg/mdoc's zk_native_stub.go /
// zk_native_cgo.go pair, and pkg/pki's PKCS#11 support).
//
// These stubs REFUSE rather than return a verified-looking zero value.
// Everything upstream of the call - the trust chain, the request's own
// checks, the circuit selection - is real and has already run, so a
// stub that returned a nil error would be handing that work back as a
// successful verification of a proof nothing looked at.

// NativeVerifier is the no-native-library build's stand-in. It holds
// nothing, because a build without the tag can never construct one.
type NativeVerifier struct{}

// NewNativeVerifier always fails in this build.
func NewNativeVerifier(circuit []byte, params CircuitParams) (*NativeVerifier, error) {
	return nil, ErrNativeNotBuilt
}

// Close is a no-op in this build.
func (n *NativeVerifier) Close() error { return nil }

// Verify always fails in this build, and returns no pseudonym.
func (n *NativeVerifier) Verify(req Request, claimed [32]byte, proof []byte) ([32]byte, error) {
	return [32]byte{}, ErrNativeNotBuilt
}
