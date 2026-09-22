// Package jwktest builds JWK field values for tests.
package jwktest

import (
	"crypto/elliptic"
	"encoding/base64"
	"math/big"
)

// Coord renders an EC coordinate as a JWK value: base64url of the fixed-width
// big-endian bytes (RFC 7518 6.2.1.2).
//
// FillBytes, not Bytes(): the latter drops a leading zero byte, which happens
// for roughly 1 P-256 coordinate in 125 and yields a short, invalid key that
// parsers reject with `invalid "x" length (31)`.
func Coord(v *big.Int, curve elliptic.Curve) string {
	size := (curve.Params().BitSize + 7) / 8
	return base64.RawURLEncoding.EncodeToString(v.FillBytes(make([]byte, size)))
}
