package jwktest

import (
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
