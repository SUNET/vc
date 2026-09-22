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

// TestECDHSharedSecretIsFixedWidth pins the ECDH Z conversion. Per SEC1 2.3.5
// and RFC 5903 the shared secret is the fixed-length x-coordinate, and ISO
// 18013-5 9.1.1.5 derives SKReader/SKDevice from it with HKDF.
//
// big.Int.Bytes() drops leading zeros, so for roughly 1 session in 125 this
// side fed HKDF 31 bytes where a conformant peer fed it 32 - different session
// keys, and a session that fails to decrypt with nothing obviously wrong.
func TestECDHSharedSecretIsFixedWidth(t *testing.T) {
	// A tiny x is the same shape as an unlucky real one.
	assert.Len(t, ecdhSharedSecret(elliptic.P256(), big.NewInt(1)), 32)
	assert.Len(t, ecdhSharedSecret(elliptic.P384(), big.NewInt(1)), 48)

	// A full-width coordinate is unchanged.
	full := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(1))
	assert.Len(t, ecdhSharedSecret(elliptic.P256(), full), 32)

	// The padding is on the left: the value must survive a round trip.
	assert.Equal(t, big.NewInt(1), new(big.Int).SetBytes(ecdhSharedSecret(elliptic.P256(), big.NewInt(1))))
}
