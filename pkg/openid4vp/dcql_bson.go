package openid4vp

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
)

// BSON type bytes, from the BSON specification. Spelled out rather than
// imported so this package keeps no dependency on a database driver: it
// is the wire model, and the fact that a verifier happens to cache its
// requests in Mongo is not its concern beyond this one file.
const (
	bsonTypeDouble   byte = 0x01
	bsonTypeString   byte = 0x02
	bsonTypeDocument byte = 0x03
	bsonTypeUndefi   byte = 0x06
	bsonTypeNull     byte = 0x0A
)

// MarshalBSONValue stores a DCQL as its JSON text.
//
// The HA cache persists the whole authorization context, this query
// inside it, and another replica reads it back - so whatever BSON does to
// these values is what the OTHER replica sends. And the driver's
// json.Number encoder tries Int64 and then Float64, which rounds a
// decimal beyond float64 precision and an integer beyond int64: the very
// values the JSON and YAML paths were fixed to preserve exactly, lost
// again at the last step, with the two replicas now sending different
// requests.
//
// A req param is an input to a proof. Storing the JSON text makes the
// persisted form the one already proven to preserve it, rather than
// adding a second exact representation to keep in step with the first.
//
// NOTE FOR DEPLOYMENT: this changes the stored shape of dcql_query from
// an embedded document to a string. Authorization contexts are
// short-lived session records, but a context written by an older replica
// cannot be read by a newer one, so in-flight sessions do not survive a
// rolling upgrade and those wallets must restart their flow. That is the
// lesser cost: the alternative is two replicas sending different requests
// and neither of them saying so.
func (d DCQL) MarshalBSONValue() (byte, []byte, error) {
	encoded, err := json.Marshal(d)
	if err != nil {
		return 0, nil, fmt.Errorf("dcql: %w", err)
	}
	return bsonTypeString, appendBSONString(nil, encoded), nil
}

// UnmarshalBSONValue reads back what MarshalBSONValue wrote.
func (d *DCQL) UnmarshalBSONValue(typ byte, data []byte) error {
	switch typ {
	case bsonTypeString:
		text, err := readBSONString(data)
		if err != nil {
			return fmt.Errorf("dcql: %w", err)
		}
		return json.Unmarshal(text, d)
	case bsonTypeNull, bsonTypeUndefi:
		*d = DCQL{}
		return nil
	case bsonTypeDocument:
		// Written by a replica from before this change. Named rather than
		// lumped in with "unexpected", because during a rolling upgrade
		// it is the one wrong type an operator will actually see, and
		// "restart the flow" is a useful thing to be told.
		return fmt.Errorf("dcql: this authorization context was written by an older build and cannot be read exactly; the session has to be restarted")
	default:
		return fmt.Errorf("dcql: cannot be read from BSON type 0x%02x", typ)
	}
}

// appendBSONString appends value as a BSON string: its length including
// the terminator, the bytes, and a NUL.
func appendBSONString(dst []byte, value []byte) []byte {
	dst = binary.LittleEndian.AppendUint32(dst, uint32(len(value)+1))
	dst = append(dst, value...)
	return append(dst, 0x00)
}

// readBSONString is appendBSONString's inverse, checking the framing
// rather than trusting it.
func readBSONString(data []byte) ([]byte, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("a BSON string is at least 5 bytes, got %d", len(data))
	}
	declared := binary.LittleEndian.Uint32(data[:4])
	if declared == 0 || int(declared) != len(data)-4 {
		return nil, fmt.Errorf("a BSON string declares %d bytes but carries %d", declared, len(data)-4)
	}
	if data[len(data)-1] != 0x00 {
		return nil, fmt.Errorf("a BSON string must end with NUL")
	}
	return data[4 : len(data)-1], nil
}
