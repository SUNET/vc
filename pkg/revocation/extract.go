package revocation

import "encoding/json"

// ExtractStatusListReference extracts a Token Status List reference from SD-JWT credential claims.
// Returns nil if no status claim is present (credential is not revocable).
func ExtractStatusListReference(claims map[string]any) *Reference {
	statusRaw, ok := claims["status"]
	if !ok {
		return nil
	}

	statusMap, ok := statusRaw.(map[string]any)
	if !ok {
		return nil
	}

	statusListRaw, ok := statusMap["status_list"]
	if !ok {
		return nil
	}

	statusList, ok := statusListRaw.(map[string]any)
	if !ok {
		return nil
	}

	uri, _ := statusList["uri"].(string)
	if uri == "" {
		return nil
	}

	var index int64
	switch idx := statusList["idx"].(type) {
	case float64:
		if idx != float64(int64(idx)) {
			return nil // Non-integer index
		}
		index = int64(idx)
	case int64:
		index = idx
	case int:
		index = int64(idx)
	case json.Number:
		i, err := idx.Int64()
		if err != nil {
			return nil
		}
		index = i
	default:
		return nil
	}

	return &Reference{
		Scheme: SchemeStatusList,
		URI:    uri,
		Index:  index,
	}
}
