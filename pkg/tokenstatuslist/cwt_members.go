package tokenstatuslist

import "fmt"

// normalizeCBORIntMap flattens the several shapes fxamacker/cbor can hand
// back for a CBOR map with integer labels into one map[int64]any.
//
// Which shape arrives depends on the Go type the payload was decoded into:
// `map[int]any` when the target said so, `map[any]any` with int, int64 or
// uint64 keys when it did not. Three packages used to open-code that switch
// per member they wanted, which is how status_list.bits came to be ignored
// everywhere - adding a member meant writing the whole dance again, so nobody
// did. Normalising once makes reading a new member a map lookup.
func normalizeCBORIntMap(raw any) (map[int64]any, bool) {
	switch m := raw.(type) {
	case map[int64]any:
		return m, true
	case map[int]any:
		out := make(map[int64]any, len(m))
		for k, v := range m {
			out[int64(k)] = v
		}
		return out, true
	case map[any]any:
		out := make(map[int64]any, len(m))
		for k, v := range m {
			switch key := k.(type) {
			case int:
				out[int64(key)] = v
			case int64:
				out[key] = v
			case uint64:
				out[int64(key)] = v
			}
		}
		return out, true
	default:
		return nil, false
	}
}

// CWTStatusListMembers reads the bits and lst members out of a decoded CWT
// status_list claim (Section 7.2), whatever CBOR map shape it decoded into.
//
// bits is REQUIRED by the specification; an absent or invalid one is an error
// rather than a fallback to DefaultBits, because guessing the width returns
// another credential's status instead of failing.
func CWTStatusListMembers(raw any) (bits int, lst []byte, err error) {
	if sl, ok := raw.(CWTStatusList); ok {
		if err := checkBits(sl.Bits); err != nil {
			return 0, nil, err
		}
		if len(sl.Lst) == 0 {
			return 0, nil, fmt.Errorf("lst not found in status_list claim")
		}
		return sl.Bits, sl.Lst, nil
	}

	m, ok := normalizeCBORIntMap(raw)
	if !ok {
		return 0, nil, fmt.Errorf("invalid status_list claim format: %T", raw)
	}

	rawBits, ok := m[statusListKeyBits]
	if !ok {
		return 0, nil, fmt.Errorf("bits not found in status_list claim")
	}
	bits, ok = cborInt(rawBits)
	if !ok {
		return 0, nil, fmt.Errorf("invalid bits member in status_list claim: %T", rawBits)
	}
	if err := checkBits(bits); err != nil {
		return 0, nil, err
	}

	lst, ok = m[statusListKeyLst].([]byte)
	if !ok || len(lst) == 0 {
		return 0, nil, fmt.Errorf("lst not found in status_list claim")
	}
	return bits, lst, nil
}

// cborInt narrows the integer types a CBOR decoder can produce.
func cborInt(raw any) (int, bool) {
	switch v := raw.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case uint64:
		return int(v), true
	case uint:
		return int(v), true
	default:
		return 0, false
	}
}
