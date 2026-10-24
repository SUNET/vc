//go:build !zknative

package verifier

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Without the native library there is no way to check a proof, and the
// stubs must say so rather than return a zero value that reads as a
// verified one. Everything upstream - the trust chain, the request's
// own checks - is real and has already run by the time either is
// called, so a nil error here would hand that work back as a successful
// verification of a proof nothing looked at.
func TestNativeStubsRefuse(t *testing.T) {
	v, err := NewNativeVerifier([]byte("circuit"), CircuitParams{})
	assert.ErrorIs(t, err, ErrNativeNotBuilt)
	assert.Nil(t, v)

	pseudonym, err := (&NativeVerifier{}).Verify(testRequest(t), [32]byte{1}, []byte("proof"))
	assert.ErrorIs(t, err, ErrNativeNotBuilt)
	assert.Equal(t, [32]byte{}, pseudonym, "a refused verification returns no pseudonym")
}
