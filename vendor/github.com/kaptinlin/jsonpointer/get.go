package jsonpointer

import "reflect"

func resolveValue(doc any, pointer Pointer) (any, error) {
	value, _, err := walk(doc, pointer, nil)
	return value, err
}

func resolveReference(doc any, pointer Pointer) (Reference, error) {
	var parent any
	value, token, err := walk(doc, pointer, &parent)
	if err != nil {
		return Reference{}, err
	}

	return Reference{
		value:   value,
		parent:  parent,
		token:   token,
		pointer: pointer,
	}, nil
}

func walk(doc any, pointer Pointer, parent *any) (any, string, error) {
	current := doc
	var token string
	for depth, stepToken := range pointer.tokens {
		var parentOutput *any
		if parent != nil && depth == len(pointer.tokens)-1 {
			parentOutput = parent
		}
		next, err := step(current, stepToken, parentOutput)
		if err != nil {
			return nil, "", newError(err, pointer, depth)
		}
		token = stepToken
		current = next
	}
	return current, token, nil
}

func step(current any, token string, parent *any) (any, error) {
	if current == nil {
		return nil, ErrNotTraversable
	}

	switch value := current.(type) {
	case map[string]any:
		next, err := stringMapValue(value, token)
		if err == nil && parent != nil {
			*parent = value
		}
		return next, err
	case *map[string]any:
		if value == nil {
			return nil, ErrNilPointer
		}
		next, err := stringMapValue(*value, token)
		if err == nil && parent != nil {
			*parent = *value
		}
		return next, err
	case []any:
		next, err := sliceValue(value, token)
		if err == nil && parent != nil {
			*parent = value
		}
		return next, err
	case *[]any:
		if value == nil {
			return nil, ErrNilPointer
		}
		next, err := sliceValue(*value, token)
		if err == nil && parent != nil {
			*parent = *value
		}
		return next, err
	}

	value, err := derefValue(reflect.ValueOf(current))
	if err != nil {
		return nil, err
	}

	switch value.Kind() {
	case reflect.Slice, reflect.Array:
		index, err := validateAndAccessArray(token, value.Len())
		if err != nil {
			return nil, err
		}
		if parent != nil {
			*parent = value.Interface()
		}
		return value.Index(index).Interface(), nil
	case reflect.Map:
		result, err := mapValueByToken(value, token)
		if err != nil {
			return nil, err
		}
		if parent != nil {
			*parent = value.Interface()
		}
		return result.Interface(), nil
	default:
		return nil, ErrNotTraversable
	}
}

func sliceValue(values []any, token string) (any, error) {
	index, err := validateAndAccessArray(token, len(values))
	if err != nil {
		return nil, err
	}
	return values[index], nil
}

func stringMapValue(values map[string]any, token string) (any, error) {
	result, ok := values[token]
	if !ok {
		return nil, ErrKeyNotFound
	}
	return result, nil
}
