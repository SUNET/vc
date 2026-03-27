package cryptoutil

import (
	"encoding/asn1"
	"fmt"
	"math/big"
)

// ECDSARawToASN1 converts an IEEE P1363 raw (r||s) ECDSA signature to ASN.1
// DER encoding. This format conversion is required by XML-DSIG (RFC 4050),
// JWS (RFC 7518), COSE (RFC 9053), and WebAuthn, all of which use the raw
// concatenation format, while Go's crypto/ecdsa expects ASN.1 DER.
//
// The input must be an even number of bytes with r and s each occupying
// exactly half the total length.
func ECDSARawToASN1(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw)%2 != 0 {
		return nil, fmt.Errorf("cryptoutil: invalid ECDSA raw signature length %d (must be even and non-zero)", len(raw))
	}
	half := len(raw) / 2
	r := new(big.Int).SetBytes(raw[:half])
	s := new(big.Int).SetBytes(raw[half:])
	return asn1.Marshal(struct {
		R, S *big.Int
	}{r, s})
}

// ECDSAASN1ToRaw converts an ASN.1 DER-encoded ECDSA signature to IEEE P1363
// raw (r||s) format with the given byte size per component (typically
// key size in bytes: 32 for P-256, 48 for P-384, 66 for P-521).
//
// Each component is zero-padded on the left to exactly componentSize bytes.
func ECDSAASN1ToRaw(der []byte, componentSize int) ([]byte, error) {
	var sig struct {
		R, S *big.Int
	}
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil {
		return nil, fmt.Errorf("cryptoutil: failed to unmarshal ASN.1 ECDSA signature: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("cryptoutil: trailing data after ASN.1 ECDSA signature")
	}

	rBytes := sig.R.Bytes()
	sBytes := sig.S.Bytes()
	if len(rBytes) > componentSize || len(sBytes) > componentSize {
		return nil, fmt.Errorf("cryptoutil: ECDSA component too large for size %d", componentSize)
	}

	raw := make([]byte, 2*componentSize)
	copy(raw[componentSize-len(rBytes):], rBytes)
	copy(raw[2*componentSize-len(sBytes):], sBytes)
	return raw, nil
}
