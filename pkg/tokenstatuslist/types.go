// Package tokenstatuslist provides types and functions for Token Status List operations
// per draft-ietf-oauth-status-list specification.
//
// The package supports both JWT (Section 5) and CWT (Section 6) formats for Status List Tokens.
package tokenstatuslist

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"fmt"
	"io"
	"math"
	"time"
)

// Status values per the specification
const (
	StatusValid     uint8 = 0 // VALID (0x00)
	StatusInvalid   uint8 = 1 // INVALID (0x01)
	StatusSuspended uint8 = 2 // SUSPENDED (0x02)
)

// Bits is the number of bits per status entry.
// We hardcode to 8 bits (1 byte per status) which supports status values 0-255.
const Bits = 8

// Media types for Status List Tokens
const (
	MediaTypeJWT = "application/statuslist+jwt"
	MediaTypeCWT = "application/statuslist+cwt"
)

// StatusListClaim represents the status_list claim in the Status List Token (Section 4.2)
// This structure is used in both JWT and CWT formats for serialization.
type StatusListClaim struct {
	// Bits: REQUIRED. Integer specifying the number of bits per Referenced Token
	// in the compressed byte array (lst). The allowed values for bits are 1, 2, 4 and 8.
	Bits int `json:"bits" cbor:"1,keyasint" validate:"required,oneof=1 2 4 8"`

	// Lst: REQUIRED. String that contains the status values for all the Referenced Tokens
	// it conveys statuses for. The value MUST be the base64url-encoded (for JWT) or
	// raw bytes (for CWT) compressed byte array as specified in Section 4.1.
	Lst string `json:"lst" cbor:"2,keyasint" validate:"required"`

	// AggregationURI: OPTIONAL. String that contains a URI to retrieve the
	// Status List Aggregation for this type of Referenced Token or Issuer.
	// See Section 9 for further details.
	AggregationURI string `json:"aggregation_uri,omitempty" cbor:"3,keyasint,omitempty"`
}

// StatusList represents a list of status values and provides methods for
// generating JWT and CWT tokens.
type StatusList struct {
	// statuses holds the raw status values (one byte per status with bits=8)
	statuses []uint8

	// Issuer is the issuer identifier (REQUIRED for token generation)
	Issuer string

	// Subject is the URI of the Status List Token (REQUIRED, must match uri in Referenced Token)
	Subject string

	// TTL is the time-to-live in seconds for caching, as specified in the draft-ietf-oauth-status-list specification (RECOMMENDED).
	TTL int64

	// ExpiresIn is the duration until the token expires (RECOMMENDED)
	ExpiresIn time.Duration

	// KeyID is the key identifier for the token header (OPTIONAL)
	KeyID string

	// AggregationURI is an optional URI for Status List Aggregation (OPTIONAL)
	AggregationURI string
}

// New creates a new StatusList with the given statuses.
func New(statuses []uint8) *StatusList {
	return &StatusList{
		statuses: statuses,
	}
}

// NewWithConfig creates a new StatusList with statuses and configuration.
func NewWithConfig(statuses []uint8, issuer, subject string) *StatusList {
	return &StatusList{
		statuses: statuses,
		Issuer:   issuer,
		Subject:  subject,
	}
}

// Statuses returns a copy of the status values.
func (sl *StatusList) Statuses() []uint8 {
	result := make([]uint8, len(sl.statuses))
	copy(result, sl.statuses)
	return result
}

// Len returns the number of statuses in the list.
func (sl *StatusList) Len() int {
	return len(sl.statuses)
}

// Get retrieves the status value at the given index.
// The index corresponds to the "idx" value in the Referenced Token's status claim.
func (sl *StatusList) Get(index int) (uint8, error) {
	if index < 0 || index >= len(sl.statuses) {
		return 0, ErrInvalidStatusIndex
	}
	return sl.statuses[index], nil
}

// Set updates the status value at the given index.
func (sl *StatusList) Set(index int, status uint8) error {
	if index < 0 || index >= len(sl.statuses) {
		return ErrInvalidStatusIndex
	}
	sl.statuses[index] = status
	return nil
}

// Compress compresses the status byte array using DEFLATE (zlib) compression
// as specified in Section 4.1 of the specification.
func (sl *StatusList) Compress() ([]byte, error) {
	return CompressStatuses(sl.statuses)
}

// CompressAndEncode compresses and encodes as base64url without padding.
// This is the format used in JWT Status List Tokens (Section 5.1).
func (sl *StatusList) CompressAndEncode() (string, error) {
	return CompressAndEncode(sl.statuses)
}

// TokenConfig holds configuration for generating a Status List Token (JWT or CWT).
// Deprecated: Use StatusList fields directly instead.
type TokenConfig struct {
	// Subject is the URI of the Status List Token (REQUIRED, must match uri in Referenced Token)
	Subject string

	// Issuer is the issuer identifier (REQUIRED)
	Issuer string

	// Statuses is the byte array of status values (REQUIRED)
	Statuses []uint8

	// TTL is the time to live in seconds (RECOMMENDED)
	TTL int64

	// ExpiresIn is the duration until the token expires (RECOMMENDED)
	ExpiresIn time.Duration

	// KeyID is the key identifier for the token header (OPTIONAL)
	KeyID string

	// AggregationURI is an optional URI for Status List Aggregation (OPTIONAL)
	AggregationURI string
}

// CompressStatuses compresses a status byte array using DEFLATE (zlib) compression
// as specified in Section 4.1 of the specification.
func CompressStatuses(statuses []uint8) ([]byte, error) {
	var b bytes.Buffer
	w, err := zlib.NewWriterLevel(&b, zlib.BestCompression)
	if err != nil {
		return nil, err
	}

	_, err = w.Write(statuses)
	if err != nil {
		return nil, err
	}

	if err := w.Close(); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// CompressAndEncode compresses statuses and encodes them as base64url without padding.
// This is the format used in JWT Status List Tokens (Section 5.1).
func CompressAndEncode(statuses []uint8) (string, error) {
	compressed, err := CompressStatuses(statuses)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(compressed), nil
}

// maxDecompressedSize is the maximum allowed decompressed status list size (50 MB).
// This prevents zip-bomb attacks where a small compressed payload expands to exhaust memory.
const maxDecompressedSize = 50 << 20

// DefaultMaxEntries is the default limit on the entries in one status list read by a verifier.
const DefaultMaxEntries = 1 << 24

// DecompressStatuses decompresses a zlib-compressed status byte array.
// The decompressed output is limited to maxDecompressedSize to prevent zip-bomb attacks.
func DecompressStatuses(compressed []byte) ([]uint8, error) {
	return DecompressStatusesLimit(compressed, maxDecompressedSize)
}

// DecompressStatusesLimit is DecompressStatuses with a caller-chosen limit on the decompressed size in bytes.
func DecompressStatusesLimit(compressed []byte, maxBytes int64) ([]uint8, error) {
	r, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	defer r.Close()

	readLimit := maxBytes
	if readLimit < math.MaxInt64 {
		readLimit++
	}
	b, err := io.ReadAll(io.LimitReader(r, readLimit))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("decompressed status list exceeds maximum size (%d bytes)", maxBytes)
	}

	return b, nil
}

func validateBits(bits int) error {
	switch bits {
	case 1, 2, 4, 8:
		return nil
	}
	return fmt.Errorf("unsupported status list bits value: %d", bits)
}

// ExpandStatuses decompresses lst and returns one status value per byte for any bits value.
// A list may hold up to maxEntries entries plus padding to the next byte;
// zero or less means DefaultMaxEntries.
func ExpandStatuses(lst []byte, bits int, maxEntries int64) ([]uint8, error) {
	if err := validateBits(bits); err != nil {
		return nil, err
	}
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEntries
	}

	perByte := int64(8 / bits)
	maxBytes := maxEntries / perByte
	if maxEntries%perByte != 0 {
		maxBytes++
	}

	raw, err := DecompressStatusesLimit(lst, maxBytes)
	if err != nil {
		return nil, err
	}
	if bits == 8 {
		return raw, nil
	}

	mask := uint8(1<<bits - 1)
	out := make([]uint8, len(raw)*int(perByte))
	for i, b := range raw {
		for j := range int(perByte) {
			out[i*int(perByte)+j] = (b >> (j * bits)) & mask
		}
	}
	return out, nil
}

// StatusAt returns the entry at index from a decompressed list packed with the given bits,
// least significant bits first (draft-ietf-oauth-status-list Section 4.1).
func StatusAt(raw []uint8, bits int, index int64) (uint8, error) {
	if err := validateBits(bits); err != nil {
		return 0, err
	}
	if index < 0 {
		return 0, ErrInvalidStatusIndex
	}
	perByte := int64(8 / bits)
	byteIdx := index / perByte
	if byteIdx >= int64(len(raw)) {
		return 0, ErrInvalidStatusIndex
	}
	shift := uint((index % perByte) * int64(bits))
	mask := uint8(1<<bits - 1)
	return (raw[byteIdx] >> shift) & mask, nil
}

// DecodeAndDecompress decodes a base64url string and decompresses it.
// This is used to parse JWT Status List Tokens.
func DecodeAndDecompress(encoded string) ([]uint8, error) {
	compressed, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	return DecompressStatuses(compressed)
}

// GetStatus retrieves the status value at the given index from a status list.
// The index corresponds to the "idx" value in the Referenced Token's status claim.
func GetStatus(statuses []uint8, index int) (uint8, error) {
	if index < 0 || index >= len(statuses) {
		return 0, ErrInvalidStatusIndex
	}
	return statuses[index], nil
}
