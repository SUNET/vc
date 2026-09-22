package mdoc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCOSEKeyCoordinatesAreFixedWidth pins RFC 9052 7.1.1: EC2 coordinates are
// fixed-width per curve. big.Int.Bytes() drops leading zero bytes, so a
// coordinate with a zero high byte - about 0.8% of generated P-256 keys -
// would otherwise be emitted one byte short.
func TestCOSEKeyCoordinatesAreFixedWidth(t *testing.T) {
	// A deliberately tiny coordinate is the same shape as an unlucky real one,
	// without needing to generate keys until the draw comes up.
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: big.NewInt(2)}

	key, err := NewCOSEKeyFromECDSAPublic(pub)
	require.NoError(t, err)
	assert.Len(t, key.X, 32, "P-256 X must be 32 bytes")
	assert.Len(t, key.Y, 32, "P-256 Y must be 32 bytes")

	// And a full-width coordinate is unchanged.
	big32 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(1))
	full, err := NewCOSEKeyFromECDSAPublic(&ecdsa.PublicKey{Curve: elliptic.P256(), X: big32, Y: big32})
	require.NoError(t, err)
	assert.Len(t, full.X, 32)
}
