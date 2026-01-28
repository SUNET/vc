//go:build pkcs11

package pki

import (
	"bytes"
	"crypto/elliptic"
	"fmt"
)

// bytesToUint converts a byte slice to uint (helper for PKCS11)
// PKCS#11 attributes are typically in platform-native byte order (little-endian on x86)
func bytesToUint(b []byte) uint {
	var result uint
	// Read in little-endian order
	for i := len(b) - 1; i >= 0; i-- {
		result = result<<8 | uint(b[i])
	}
	return result
}

// parseCurveOID parses the curve from DER-encoded OID
func parseCurveOID(oid []byte) (elliptic.Curve, error) {
	// Common curve OIDs
	p256OID := []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}
	p384OID := []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22}
	p521OID := []byte{0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23}

	switch {
	case bytes.Equal(oid, p256OID):
		return elliptic.P256(), nil
	case bytes.Equal(oid, p384OID):
		return elliptic.P384(), nil
	case bytes.Equal(oid, p521OID):
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported curve OID: %x", oid)
	}
}
