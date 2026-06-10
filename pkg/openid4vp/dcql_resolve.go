package openid4vp

import "strconv"

// ResolveDCQLPath resolves a DCQL claim path against a credential value.
// Per DCQL Section 7.1:
//   - string segments navigate object keys
//   - nil means "all array elements" (returns []any of resolved values)
//   - numeric strings are array indices
func ResolveDCQLPath(data any, path []*string) any {
	if len(path) == 0 {
		return data
	}

	seg := path[0]
	rest := path[1:]

	if seg == nil {
		// null = iterate all array elements
		arr, ok := data.([]any)
		if !ok {
			return nil
		}
		results := make([]any, 0, len(arr))
		for _, elem := range arr {
			results = append(results, ResolveDCQLPath(elem, rest))
		}
		return results
	}

	// Try as array index
	if idx, err := strconv.Atoi(*seg); err == nil {
		arr, ok := data.([]any)
		if !ok || idx < 0 || idx >= len(arr) {
			return nil
		}
		return ResolveDCQLPath(arr[idx], rest)
	}

	// Object key
	obj, ok := data.(map[string]any)
	if !ok {
		return nil
	}
	val, exists := obj[*seg]
	if !exists {
		return nil
	}
	return ResolveDCQLPath(val, rest)
}
