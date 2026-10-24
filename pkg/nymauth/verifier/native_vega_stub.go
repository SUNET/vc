//go:build !zknative

package verifier

// The Vega half of native_stub.go - see that file for why these refuse
// rather than return a verified-looking zero value.

// VegaVerifier is the no-native-library build's stand-in.
type VegaVerifier struct{}

// NewVegaVerifier always fails in this build.
func NewVegaVerifier(shapes []byte) (*VegaVerifier, error) {
	return nil, ErrNativeNotBuilt
}

// Close is a no-op in this build.
func (n *VegaVerifier) Close() error { return nil }

// Verify always fails in this build, and returns no pseudonym.
func (n *VegaVerifier) Verify(req Request, claimed [32]byte, proof []byte) ([32]byte, error) {
	return [32]byte{}, ErrNativeNotBuilt
}
