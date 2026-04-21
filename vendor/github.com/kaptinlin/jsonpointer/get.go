package jsonpointer

import (
	"reflect"
)

// fastGet implements ultra-fast path that avoids token allocation entirely.
// Optimized for string-only Path - direct access without intermediate token creation.
// Returns the value and a boolean indicating success.
func fastGet(val any, step string) (any, bool) {
	switch v := val.(type) {
	case map[string]any:
		result, exists := v[step]
		return result, exists

	case *map[string]any:
		if v == nil {
			return nil, false
		}
		result, exists := (*v)[step]
		return result, exists

	case []any:
		if step == "-" {
			return nil, false
		}
		index := fastAtoi(step)
		if index < 0 || index >= len(v) {
			return nil, false
		}
		return v[index], true

	case *[]any:
		if v == nil {
			return nil, false
		}
		if step == "-" {
			return nil, false
		}
		index := fastAtoi(step)
		if index < 0 || index >= len(*v) {
			return nil, false
		}
		return (*v)[index], true

	case *any:
		if v == nil {
			return nil, false
		}
		return fastGet(*v, step)

	default:
		return nil, false
	}
}

// tryArrayAccess attempts array access using type assertions for performance.
// Enhanced to handle all slice types efficiently.
// Returns (value, handled, error) where handled indicates if this was an array access attempt.
func tryArrayAccess(current any, key string) (any, bool, error) {
	switch arr := current.(type) {
	case []any:
		index, err := validateAndAccessArray(key, len(arr))
		if err != nil {
			return nil, true, err
		}
		return arr[index], true, nil

	case *[]any:
		if arr == nil {
			return nil, true, ErrNilPointer
		}
		index, err := validateAndAccessArray(key, len(*arr))
		if err != nil {
			return nil, true, err
		}
		return (*arr)[index], true, nil

	default:
		arrayVal, err := derefValue(reflect.ValueOf(current))
		if err != nil {
			return nil, true, err
		}

		if arrayVal.Kind() != reflect.Slice && arrayVal.Kind() != reflect.Array {
			return nil, false, nil
		}

		index, err := validateAndAccessArray(key, arrayVal.Len())
		if err != nil {
			return nil, true, err
		}
		return arrayVal.Index(index).Interface(), true, nil
	}
}

// tryObjectAccess attempts object access using type assertions for performance.
// Enhanced with proper struct field handling.
// Returns (value, handled, error) where handled indicates if this was an object access attempt.
func tryObjectAccess(current any, key string) (any, bool, error) {
	switch obj := current.(type) {
	case map[string]any:
		result, exists := obj[key]
		if !exists {
			return nil, true, ErrKeyNotFound
		}
		return result, true, nil

	case *map[string]any:
		if obj == nil {
			return nil, true, ErrNilPointer
		}
		result, exists := (*obj)[key]
		if !exists {
			return nil, true, ErrKeyNotFound
		}
		return result, true, nil

	default:
		objVal, err := derefValue(reflect.ValueOf(current))
		if err != nil {
			return nil, false, err
		}

		switch objVal.Kind() {
		case reflect.Map:
			mapEntry, err := mapValueByPathKey(objVal, key)
			if err != nil {
				return nil, true, err
			}
			return mapEntry.Interface(), true, nil

		case reflect.Struct:
			if !structField(key, &objVal) {
				return nil, true, ErrFieldNotFound
			}
			return objVal.Interface(), true, nil

		default:
			return nil, false, nil
		}
	}
}

// get retrieves value at JSON pointer path, returns error if path cannot be traversed.
// Optimized for zero-allocation paths with layered fallback strategy.
func get(val any, path Path) (any, error) {
	pathLength := len(path)
	if pathLength == 0 {
		return val, nil
	}

	current := val
	fastPathDepth := 0

	// Ultra-fast path - direct access without token creation
	for i := range pathLength {
		step := path[i]

		if result, ok := fastGet(current, step); ok {
			current = result
			fastPathDepth = i + 1
		} else {
			break
		}
	}

	// Type assertion fallback for remaining path
	for i := fastPathDepth; i < pathLength; i++ {
		step := path[i]

		if current == nil {
			return nil, ErrNotFound
		}

		if result, handled, err := tryArrayAccess(current, step); err != nil {
			return nil, err
		} else if handled {
			current = result
			continue
		}

		if result, handled, err := tryObjectAccess(current, step); err != nil {
			return nil, err
		} else if handled {
			current = result
			continue
		}

		return nil, ErrNotFound
	}

	return current, nil
}
