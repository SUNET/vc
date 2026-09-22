package jwktest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCoord(t *testing.T) {
	// A coordinate with a zero high byte is the case Bytes() gets wrong.
	small, err := base64.RawURLEncoding.DecodeString(Coord(big.NewInt(1), elliptic.P256()))
	require.NoError(t, err)
	assert.Equal(t, append(make([]byte, 31), 1), small, "padded on the left, to the curve width")

	// Full-width coordinates are passed through unchanged.
	full := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(1))
	got, err := base64.RawURLEncoding.DecodeString(Coord(full, elliptic.P256()))
	require.NoError(t, err)
	assert.Equal(t, full.Bytes(), got)

	// The width follows the curve, not a hardcoded 32.
	wide, err := base64.RawURLEncoding.DecodeString(Coord(big.NewInt(1), elliptic.P384()))
	require.NoError(t, err)
	assert.Len(t, wide, 48)
}

func TestPublicKeyJWK(t *testing.T) {
	// X has a zero high byte, Y does not: both must still come out 32 bytes.
	key := &ecdsa.PublicKey{Curve: elliptic.P256(), X: big.NewInt(1), Y: new(big.Int).Lsh(big.NewInt(1), 255)}

	jwk := PublicKeyJWK(key)
	assert.Equal(t, "EC", jwk["kty"])
	assert.Equal(t, "P-256", jwk["crv"])
	for _, c := range []string{"x", "y"} {
		raw, err := base64.RawURLEncoding.DecodeString(jwk[c].(string))
		require.NoError(t, err)
		assert.Len(t, raw, 32, "%s must be the full curve width", c)
	}
}
