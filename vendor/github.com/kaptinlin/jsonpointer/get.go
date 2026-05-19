package jsonpointer

import (
	"reflect"
)

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
		return fastSliceGet(v, step)

	case *[]any:
		if v == nil {
			return nil, false
		}
		return fastSliceGet(*v, step)

	case *any:
		if v == nil {
			return nil, false
		}
		return fastGet(*v, step)

	default:
		return nil, false
	}
}

func fastSliceGet(values []any, step string) (any, bool) {
	if step == "-" {
		return nil, false
	}
	index := fastAtoi(step)
	if index < 0 || index >= len(values) {
		return nil, false
	}
	return values[index], true
}

func sliceValue(values []any, step string) (any, error) {
	index, err := validateAndAccessArray(step, len(values))
	if err != nil {
		return nil, err
	}
	return values[index], nil
}

func stringMapValue(values map[string]any, step string) (any, error) {
	result, ok := values[step]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return result, nil
}

func get(val any, path Path) (any, error) {
	pathLength := len(path)
	if pathLength == 0 {
		return val, nil
	}

	current := val
	fastPathDepth := 0

	for i := range pathLength {
		step := path[i]

		if result, ok := fastGet(current, step); ok {
			current = result
			fastPathDepth = i + 1
		} else {
			break
		}
	}

	for i := fastPathDepth; i < pathLength; i++ {
		var err error
		current, err = traverseStep(current, path[i])
		if err != nil {
			return nil, err
		}
	}

	return current, nil
}

func traverseStep(current any, step string) (any, error) {
	if current == nil {
		return nil, ErrNotFound
	}

	switch value := current.(type) {
	case []any:
		return sliceValue(value, step)

	case *[]any:
		if value == nil {
			return nil, ErrNilPointer
		}
		return sliceValue(*value, step)

	case map[string]any:
		return stringMapValue(value, step)

	case *map[string]any:
		if value == nil {
			return nil, ErrNilPointer
		}
		return stringMapValue(*value, step)
	}

	value, err := derefValue(reflect.ValueOf(current))
	if err != nil {
		return nil, err
	}

	switch value.Kind() {
	case reflect.Slice, reflect.Array:
		index, err := validateAndAccessArray(step, value.Len())
		if err != nil {
			return nil, err
		}
		return value.Index(index).Interface(), nil

	case reflect.Map:
		result, err := mapValueByPathKey(value, step)
		if err != nil {
			return nil, err
		}
		return result.Interface(), nil

	case reflect.Struct:
		if !structField(step, &value) {
			return nil, ErrFieldNotFound
		}
		return value.Interface(), nil

	default:
		return nil, ErrNotFound
	}
}
