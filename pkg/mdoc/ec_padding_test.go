package mdoc

import (
	"bytes"
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
	// Padded on the LEFT, value intact - length alone would also be satisfied
	// by a serializer that moved or mangled the bytes.
	assert.Equal(t, append(make([]byte, 31), 1), key.X)
	assert.Equal(t, append(make([]byte, 31), 2), key.Y)

	// A full-width coordinate is passed through byte for byte, and X and Y
	// are not transposed.
	x := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(1))
	y := new(big.Int).Sub(x, big.NewInt(7))
	full, err := NewCOSEKeyFromECDSAPublic(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y})
	require.NoError(t, err)
	assert.Equal(t, x.Bytes(), full.X)
	assert.Equal(t, y.Bytes(), full.Y)
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

	// A full-width secret is passed through byte for byte.
	full := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(1))
	assert.Equal(t, full.Bytes(), ecdhSharedSecret(elliptic.P256(), full))

	// And padding is on the left, so the value is preserved: HKDF must see
	// the same number the peer derived, not a shifted one.
	assert.Equal(t, append(make([]byte, 31), 1), ecdhSharedSecret(elliptic.P256(), big.NewInt(1)))
}

// TestCOSEKeyRejectsOversizedCoordinate covers the other half of FillBytes:
// it pads a short integer, but PANICS on one too wide for the destination.
//
// The key is not always one we generated. ParseDeviceKey decodes a COSE_Key
// from the wire and builds an ecdsa.PublicKey straight from the CBOR byte
// strings, with no width or on-curve check, so a peer can hand us a 64-byte
// X on a P-256 curve. That has to be an error, not a process panic.
func TestCOSEKeyRejectsOversizedCoordinate(t *testing.T) {
	wide := new(big.Int).Lsh(big.NewInt(1), 400) // far past P-256's 32 bytes

	_, err := NewCOSEKeyFromECDSAPublic(&ecdsa.PublicKey{Curve: elliptic.P256(), X: wide, Y: big.NewInt(2)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "X coordinate")

	_, err = NewCOSEKeyFromECDSAPublic(&ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: wide})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Y coordinate")

	// A missing coordinate is refused rather than dereferenced.
	_, err = NewCOSEKeyFromECDSAPublic(&ecdsa.PublicKey{Curve: elliptic.P256()})
	require.Error(t, err)

	// The same key straight off the wire, which is how it actually arrives.
	encoder, err := NewCBOREncoder()
	require.NoError(t, err)
	oversized := bytes.Repeat([]byte{0xff}, 64) // zeros would parse to 0 and legitimately fit
	raw, err := encoder.Marshal(&COSEKey{Kty: KeyTypeEC2, Crv: CurveP256, X: oversized, Y: oversized})
	require.NoError(t, err)
	parsed, err := ParseDeviceKey(raw, "cose")
	require.NoError(t, err, "parsing is lenient today - the width check has to hold on the way back out")
	_, err = publicKeyToCOSEKey(parsed)
	require.Error(t, err)
}
