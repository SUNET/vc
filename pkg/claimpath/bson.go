package claimpath

import (
	"fmt"
	"math"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// MarshalBSONValue stores the pointer as a BSON array of strings, nulls
// and 64-bit integers.
func (p Pointer) MarshalBSONValue() (byte, []byte, error) {
	if err := p.requireComponents(); err != nil && !p.empty {
		return 0, nil, err
	}
	values := p.values()
	for i, value := range values {
		index, ok := value.(uint)
		if !ok {
			continue
		}
		if index > math.MaxInt64 {
			return 0, nil, fmt.Errorf("claimpath: index %d exceeds a BSON integer", index)
		}
		values[i] = int64(index)
	}
	typ, data, err := bson.MarshalValue(values)
	return byte(typ), data, err
}

// UnmarshalBSONValue reads a BSON array. BSON null leaves the pointer
// unset.
func (p *Pointer) UnmarshalBSONValue(typ byte, data []byte) error {
	switch bson.Type(typ) {
	case bson.TypeNull:
		return nil
	case bson.TypeArray:
	case bson.TypeString:
		var text string
		if err := bson.UnmarshalValue(bson.TypeString, data, &text); err != nil {
			return fmt.Errorf("claimpath: %w", err)
		}
		return &StringError{Text: text}
	default:
		return fmt.Errorf("%w: a claims path pointer is a BSON array; the value is a BSON %s", ErrMalformed, bson.Type(typ))
	}
	var values []any
	if err := bson.UnmarshalValue(bson.Type(typ), data, &values); err != nil {
		return fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	pointer, err := fromValues(values)
	if err != nil {
		return err
	}
	*p = pointer
	return nil
}
