package jsonpointer

import (
	"reflect"
	"strings"
)

func parsePointer(pointer string) ([]string, error) {
	if pointer == "" {
		return nil, nil
	}
	if pointer[0] != '/' {
		return nil, ErrInvalidPointer
	}

	tokens := make([]string, 0, strings.Count(pointer, "/"))
	for segment := range strings.SplitSeq(pointer[1:], "/") {
		token, err := unescapeToken(segment)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, token)
	}
	return tokens, nil
}

func formatPointer(tokens []string) string {
	if len(tokens) == 0 {
		return ""
	}

	var b strings.Builder
	b.Grow(pointerLength(tokens))
	for _, token := range tokens {
		b.WriteByte('/')
		b.WriteString(escapeToken(token))
	}
	return b.String()
}

func pointerLength(tokens []string) int {
	if len(tokens) == 0 {
		return 0
	}

	length := len(tokens)
	for _, token := range tokens {
		for i := range len(token) {
			switch token[i] {
			case '~', '/':
				length += 2
			default:
				length++
			}
		}
	}
	return length
}

func escapeToken(token string) string {
	if !strings.Contains(token, "/") && !strings.Contains(token, "~") {
		return token
	}

	var b strings.Builder
	b.Grow(len(token) * 2)
	for i := range len(token) {
		switch token[i] {
		case '~':
			b.WriteString("~0")
		case '/':
			b.WriteString("~1")
		default:
			b.WriteByte(token[i])
		}
	}
	return b.String()
}

func unescapeToken(encoded string) (string, error) {
	if !strings.Contains(encoded, "~") {
		return encoded, nil
	}

	var b strings.Builder
	b.Grow(len(encoded))
	for i := 0; i < len(encoded); i++ {
		if encoded[i] != '~' {
			b.WriteByte(encoded[i])
			continue
		}
		if i+1 >= len(encoded) {
			return "", ErrInvalidPointer
		}
		switch encoded[i+1] {
		case '0':
			b.WriteByte('~')
		case '1':
			b.WriteByte('/')
		default:
			return "", ErrInvalidPointer
		}
		i++
	}
	return b.String(), nil
}

func derefValue(v reflect.Value) (reflect.Value, error) {
	type pointerIdentity struct {
		typeOf reflect.Type
		value  uintptr
	}

	var seen map[pointerIdentity]struct{}
	for {
		if !v.IsValid() {
			return reflect.Value{}, ErrNotTraversable
		}
		switch v.Kind() {
		case reflect.Pointer:
			if v.IsNil() {
				return reflect.Value{}, ErrNilPointer
			}
			identity := pointerIdentity{typeOf: v.Type(), value: v.Pointer()}
			if _, ok := seen[identity]; ok {
				return reflect.Value{}, ErrNotTraversable
			}
			if seen == nil {
				seen = make(map[pointerIdentity]struct{})
			}
			seen[identity] = struct{}{}
			v = v.Elem()
		case reflect.Interface:
			if v.IsNil() {
				return reflect.Value{}, ErrNotTraversable
			}
			v = v.Elem()
		default:
			return v, nil
		}
	}
}

func mapValueByToken(mapVal reflect.Value, token string) (reflect.Value, error) {
	mapKey := reflect.ValueOf(token)
	mapKeyType := mapVal.Type().Key()
	stringType := reflect.TypeFor[string]()

	switch {
	case stringType.AssignableTo(mapKeyType):
	case stringType.ConvertibleTo(mapKeyType):
		mapKey = mapKey.Convert(mapKeyType)
	default:
		return reflect.Value{}, ErrNotTraversable
	}

	mapEntry := mapVal.MapIndex(mapKey)
	if !mapEntry.IsValid() {
		return reflect.Value{}, ErrKeyNotFound
	}
	return mapEntry, nil
}

func isArrayIndex(token string) bool {
	if token == "0" {
		return true
	}
	if len(token) == 0 || token[0] < '1' || token[0] > '9' {
		return false
	}
	for i := 1; i < len(token); i++ {
		if token[i] < '0' || token[i] > '9' {
			return false
		}
	}
	return true
}

// IsArrayIndex reports whether token has canonical RFC 6901 array-index syntax.
func IsArrayIndex(token string) bool {
	return isArrayIndex(token)
}

func validateAndAccessArray(token string, length int) (int, error) {
	if token == "-" {
		return -1, ErrIndexOutOfBounds
	}
	if !isArrayIndex(token) {
		return -1, ErrInvalidIndex
	}
	if length == 0 {
		return -1, ErrIndexOutOfBounds
	}

	maxIndex := length - 1
	var index int
	for i := range len(token) {
		digit := int(token[i] - '0')
		if index > maxIndex/10 || index == maxIndex/10 && digit > maxIndex%10 {
			return -1, ErrIndexOutOfBounds
		}
		index = index*10 + digit
	}
	return index, nil
}
