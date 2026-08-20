// Package mdoc implements ISO/IEC 18013-5:2021 Mobile Driving Licence (mDL) data model and operations.
package mdoc

import (
	"bytes"
	"crypto/rand"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// CBOR tags used in ISO 18013-5
const (
	// TagEncodedCBOR is the CBOR tag for encoded CBOR data items (tag 24)
	TagEncodedCBOR = 24

	// TagDate is the CBOR tag for date (tag 1004 - full-date per RFC 8943)
	TagDate = 1004

	// TagDateTime is the CBOR tag for date-time (tag 0 - tdate per RFC 8949)
	TagDateTime = 0
)

// CBOREncoder provides CBOR encoding with ISO 18013-5 specific options.
type CBOREncoder struct {
	encMode cbor.EncMode
	decMode cbor.DecMode
}

// NewCBOREncoder creates a new CBOR encoder configured for ISO 18013-5.
func NewCBOREncoder() (*CBOREncoder, error) {
	// Configure encoding options per ISO 18013-5
	encOpts := cbor.EncOptions{
		Sort:        cbor.SortCanonical, // Canonical CBOR sorting
		IndefLength: cbor.IndefLengthForbidden,
		TimeTag:     cbor.EncTagRequired,
	}

	encMode, err := encOpts.EncMode()
	if err != nil {
		return nil, fmt.Errorf("failed to create CBOR encoder: %w", err)
	}

	decOpts := cbor.DecOptions{
		DupMapKey:   cbor.DupMapKeyEnforcedAPF,
		IndefLength: cbor.IndefLengthAllowed,
	}

	decMode, err := decOpts.DecMode()
	if err != nil {
		return nil, fmt.Errorf("failed to create CBOR decoder: %w", err)
	}

	encoder := &CBOREncoder{
		encMode: encMode,
		decMode: decMode,
	}
	return encoder, nil
}

// Marshal encodes a value to CBOR.
func (e *CBOREncoder) Marshal(v any) ([]byte, error) {
	return e.encMode.Marshal(v)
}

// Unmarshal decodes CBOR data into a value.
func (e *CBOREncoder) Unmarshal(data []byte, v any) error {
	return e.decMode.Unmarshal(data, v)
}

// TaggedValue wraps a value with a CBOR tag.
type TaggedValue struct {
	Tag   uint64
	Value any
}

// MarshalCBOR implements cbor.Marshaler for TaggedValue.
func (t TaggedValue) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal(cbor.Tag{Number: t.Tag, Content: t.Value})
}

// EncodedCBORBytes represents CBOR-encoded bytes wrapped with tag 24.
// This is used for IssuerSignedItem and other structures that need to be
// independently verifiable.
type EncodedCBORBytes []byte

// MarshalCBOR implements cbor.Marshaler for EncodedCBORBytes.
func (e EncodedCBORBytes) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal(cbor.Tag{Number: TagEncodedCBOR, Content: []byte(e)})
}

// UnmarshalCBOR implements cbor.Unmarshaler for EncodedCBORBytes.
func (e *EncodedCBORBytes) UnmarshalCBOR(data []byte) error {
	var tag cbor.Tag
	if err := cbor.Unmarshal(data, &tag); err != nil {
		return err
	}
	if tag.Number != TagEncodedCBOR {
		return fmt.Errorf("expected tag %d, got %d", TagEncodedCBOR, tag.Number)
	}
	content, ok := tag.Content.([]byte)
	if !ok {
		return fmt.Errorf("expected byte string content")
	}
	*e = content
	return nil
}

// FullDate represents a full-date (YYYY-MM-DD) with CBOR tag 1004.
type FullDate string

// MarshalCBOR implements cbor.Marshaler for FullDate.
func (f FullDate) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal(cbor.Tag{Number: TagDate, Content: string(f)})
}

// UnmarshalCBOR implements cbor.Unmarshaler for FullDate.
func (f *FullDate) UnmarshalCBOR(data []byte) error {
	var tag cbor.Tag
	if err := cbor.Unmarshal(data, &tag); err != nil {
		// Try plain string
		var s string
		if err := cbor.Unmarshal(data, &s); err != nil {
			return err
		}
		*f = FullDate(s)
		return nil
	}
	if tag.Number != TagDate {
		return fmt.Errorf("expected tag %d, got %d", TagDate, tag.Number)
	}
	s, ok := tag.Content.(string)
	if !ok {
		return fmt.Errorf("expected string content for full-date")
	}
	*f = FullDate(s)
	return nil
}

// TDate represents a date-time with CBOR tag 0.
type TDate string

// MarshalCBOR implements cbor.Marshaler for TDate.
func (t TDate) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal(cbor.Tag{Number: TagDateTime, Content: string(t)})
}

// UnmarshalCBOR implements cbor.Unmarshaler for TDate.
func (t *TDate) UnmarshalCBOR(data []byte) error {
	var tag cbor.Tag
	if err := cbor.Unmarshal(data, &tag); err != nil {
		// Try plain string
		var s string
		if err := cbor.Unmarshal(data, &s); err != nil {
			return err
		}
		*t = TDate(s)
		return nil
	}
	if tag.Number != TagDateTime {
		return fmt.Errorf("expected tag %d, got %d", TagDateTime, tag.Number)
	}
	s, ok := tag.Content.(string)
	if !ok {
		return fmt.Errorf("expected string content for tdate")
	}
	*t = TDate(s)
	return nil
}

// GenerateRandom generates cryptographically secure random bytes.
// Per ISO 18013-5, random values should be at least 16 bytes.
func GenerateRandom(length int) ([]byte, error) {
	if length < 16 {
		length = 16 // Minimum per spec
	}
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return b, nil
}

// WrapInEncodedCBOR wraps a value in CBOR tag 24 (encoded CBOR).
func WrapInEncodedCBOR(v any) (EncodedCBORBytes, error) {
	encoded, err := cbor.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("failed to encode value: %w", err)
	}
	return EncodedCBORBytes(encoded), nil
}

// UnwrapEncodedCBOR extracts the value from CBOR tag 24.
func UnwrapEncodedCBOR(data EncodedCBORBytes, v any) error {
	return cbor.Unmarshal(data, v)
}

// DataElementValue represents any valid data element value in an mDL.
type DataElementValue any

// DataElementBytes encodes a data element value to CBOR bytes.
func DataElementBytes(v DataElementValue) ([]byte, error) {
	return cbor.Marshal(v)
}

// CompareCBOR compares two CBOR-encoded byte slices for equality.
func CompareCBOR(a, b []byte) bool {
	return bytes.Equal(a, b)
}
