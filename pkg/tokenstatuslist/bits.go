package tokenstatuslist

import "fmt"

// DefaultBits is the number of bits per status entry this package uses when
// GENERATING a Status List Token and the caller expressed no preference.
//
// It is a default, never an assumption about a token somebody else produced:
// draft-ietf-oauth-status-list Section 4.1 allows 1, 2, 4 and 8, the value in
// use is carried in the token's own "bits" member, and every decoding path
// here takes it as a parameter rather than reading this constant. Reading a
// bits=1 list as if it were bits=8 does not fail - it silently returns the
// status of a different credential - so the token's value is the only
// admissible source.
const DefaultBits = 8

// ValidBits reports whether bits is one of the values Section 4.1 allows.
func ValidBits(bits int) bool {
	switch bits {
	case 1, 2, 4, 8:
		return true
	default:
		return false
	}
}

// checkBits validates a bits value coming from a token or a caller.
func checkBits(bits int) error {
	if !ValidBits(bits) {
		return fmt.Errorf("invalid status list bits %d: allowed values are 1, 2, 4 and 8", bits)
	}
	return nil
}

// Pack lays out one-status-per-entry values as the compressed byte array of
// draft-ietf-oauth-status-list Section 4.1: entries are packed into bytes
// least-significant-bits first, so with bits=2 the byte 0b11100100 holds the
// statuses 0, 1, 2, 3 at indices 0..3 in that order.
//
// A status value that does not fit in bits is an error rather than a silent
// truncation: truncating would publish a DIFFERENT status than the caller
// asked for (a SUSPENDED entry becoming VALID under bits=1), which is exactly
// the failure a revocation list must not have.
func Pack(statuses []uint8, bits int) ([]byte, error) {
	if err := checkBits(bits); err != nil {
		return nil, err
	}
	if bits == 8 {
		out := make([]byte, len(statuses))
		copy(out, statuses)
		return out, nil
	}

	perByte := 8 / bits
	maxValue := uint8(1<<bits - 1)
	out := make([]byte, (len(statuses)+perByte-1)/perByte)
	for i, status := range statuses {
		if status > maxValue {
			return nil, fmt.Errorf("status value %d at index %d does not fit in %d bits (maximum %d)", status, i, bits, maxValue)
		}
		out[i/perByte] |= status << uint((i%perByte)*bits)
	}
	return out, nil
}

// Unpack expands the compressed byte array of Section 4.1 into one status
// value per index, inverting Pack.
//
// The returned slice always covers whole bytes, so with bits=2 a one-byte
// array yields four statuses. Indices past the last credential the issuer
// allocated read as VALID (0), which is what the padding in the byte array
// means.
func Unpack(raw []byte, bits int) ([]uint8, error) {
	if err := checkBits(bits); err != nil {
		return nil, err
	}
	if bits == 8 {
		out := make([]uint8, len(raw))
		copy(out, raw)
		return out, nil
	}

	perByte := 8 / bits
	mask := uint8(1<<bits - 1)
	out := make([]uint8, 0, len(raw)*perByte)
	for _, b := range raw {
		for slot := range perByte {
			out = append(out, (b>>uint(slot*bits))&mask)
		}
	}
	return out, nil
}

// DecompressAndUnpack decompresses a zlib-compressed status byte array and
// expands it into one status per index using the bits value the Status List
// Token declared.
func DecompressAndUnpack(compressed []byte, bits int) ([]uint8, error) {
	if err := checkBits(bits); err != nil {
		return nil, err
	}
	raw, err := DecompressStatuses(compressed)
	if err != nil {
		return nil, err
	}
	return Unpack(raw, bits)
}

// DecodeDecompressAndUnpack decodes a base64url "lst" member, decompresses it
// and expands it using the token's bits value.
func DecodeDecompressAndUnpack(encoded string, bits int) ([]uint8, error) {
	if err := checkBits(bits); err != nil {
		return nil, err
	}
	raw, err := DecodeAndDecompress(encoded)
	if err != nil {
		return nil, err
	}
	return Unpack(raw, bits)
}
