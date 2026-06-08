package jsonpointer

import (
	"reflect"
	"slices"
	"strconv"
	"strings"
)

func fastAtoi(s string) int {
	if len(s) == 0 {
		return -1
	}

	if s == "0" {
		return 0
	}

	if s[0] == '0' {
		return -1
	}

	var n int
	for i := range len(s) {
		c := s[i]
		if c < '0' || c > '9' {
			return -1
		}
		next := n*10 + int(c-'0')
		if next < n {
			return -1
		}
		n = next
	}
	return n
}

func derefValue(v reflect.Value) (reflect.Value, error) {
	for {
		if !v.IsValid() {
			return reflect.Value{}, ErrNotFound
		}

		switch v.Kind() {
		case reflect.Pointer:
			if v.IsNil() {
				return reflect.Value{}, ErrNilPointer
			}
			v = v.Elem()
		case reflect.Interface:
			if v.IsNil() {
				return reflect.Value{}, ErrNotFound
			}
			v = v.Elem()
		default:
			return v, nil
		}
	}
}

func mapValueByPathKey(mapVal reflect.Value, key string) (reflect.Value, error) {
	mapKey := reflect.ValueOf(key)
	mapKeyType := mapVal.Type().Key()
	stringType := reflect.TypeFor[string]()

	switch {
	case stringType.AssignableTo(mapKeyType):
	case stringType.ConvertibleTo(mapKeyType):
		mapKey = mapKey.Convert(mapKeyType)
	default:
		return reflect.Value{}, ErrNotFound
	}

	mapEntry := mapVal.MapIndex(mapKey)
	if !mapEntry.IsValid() {
		return reflect.Value{}, ErrKeyNotFound
	}

	return mapEntry, nil
}

// unescapeComponent un-escapes a JSON pointer path component.
//
// TypeScript Original:
//
//	export function unescapeComponent(component: string): string {
//	  if (component.indexOf('~') === -1) return component;
//	  return component.replace(r1, '/').replace(r2, '~');
//	}
func unescapeComponent(component string) string {
	if !strings.Contains(component, "~") {
		return component
	}

	result := make([]byte, 0, len(component))
	for i := 0; i < len(component); i++ {
		if component[i] == '~' && i+1 < len(component) {
			switch component[i+1] {
			case '0':
				result = append(result, '~')
				i++
			case '1':
				result = append(result, '/')
				i++
			default:
				result = append(result, component[i])
			}
		} else {
			result = append(result, component[i])
		}
	}
	return string(result)
}

// escapeComponent escapes a JSON pointer path component.
//
// TypeScript Original:
//
//	export function escapeComponent(component: string): string {
//	  if (component.indexOf('/') === -1 && component.indexOf('~') === -1) return component;
//	  return component.replace(r3, '~0').replace(r4, '~1');
//	}
func escapeComponent(component string) string {
	if !strings.Contains(component, "/") && !strings.Contains(component, "~") {
		return component
	}

	result := make([]byte, 0, len(component)*2)
	for i := range len(component) {
		switch component[i] {
		case '~':
			result = append(result, '~', '0')
		case '/':
			result = append(result, '~', '1')
		default:
			result = append(result, component[i])
		}
	}
	return string(result)
}

// parseJSONPointer converts JSON pointer like "/foo/bar" to path slice
// like []string{"foo", "bar"}, while also un-escaping reserved characters.
//
// TypeScript Original:
//
//	export function parseJsonPointer(pointer: string): Path {
//	  if (!pointer) return [];
//	  return pointer.slice(1).split('/').map(unescapeComponent);
//	}
func parseJSONPointer(pointer string) Path {
	if pointer == "" {
		return Path{}
	}

	segmentCount := strings.Count(pointer, "/")
	result := make(Path, 0, segmentCount)
	for segment := range strings.SplitSeq(pointer[1:], "/") {
		result = append(result, unescapeComponent(segment))
	}
	return result
}

// formatJSONPointer escapes and formats a path slice like []string{"foo", "bar"}
// to JSON pointer like "/foo/bar".
//
// TypeScript Original:
//
//	export function formatJsonPointer(path: Path): string {
//	  if (isRoot(path)) return '';
//	  return '/' + path.map((component) => escapeComponent(String(component))).join('/');
//	}
func formatJSONPointer(path Path) string {
	if IsRoot(path) {
		return ""
	}

	capacity := len(path)
	for _, component := range path {
		capacity += len(component)
	}

	var b strings.Builder
	b.Grow(capacity)

	for _, component := range path {
		b.WriteByte('/')
		b.WriteString(escapeComponent(component))
	}
	return b.String()
}

// IsChild returns true if parent contains child path, false otherwise.
//
// TypeScript Original:
//
//	export function isChild(parent: Path, child: Path): boolean {
//	  if (parent.length >= child.length) return false;
//	  for (let i = 0; i < parent.length; i++) if (parent[i] !== child[i]) return false;
//	  return true;
//	}
func IsChild(parent, child Path) bool {
	if len(parent) >= len(child) {
		return false
	}
	return slices.Equal(parent, child[:len(parent)])
}

// IsPathEqual returns true if two paths are equal, false otherwise.
//
// TypeScript Original:
//
//	export function isPathEqual(p1: Path, p2: Path): boolean {
//	  if (p1.length !== p2.length) return false;
//	  for (let i = 0; i < p1.length; i++) if (p1[i] !== p2[i]) return false;
//	  return true;
//	}
func IsPathEqual(p1, p2 Path) bool {
	return slices.Equal(p1, p2)
}

// IsRoot returns true if JSON Pointer points to root value, false otherwise.
//
// TypeScript Original:
// export const isRoot = (path: Path): boolean => !path.length;
func IsRoot(path Path) bool {
	return len(path) == 0
}

// Parent returns parent path, e.g. for []string{"foo", "bar", "baz"}
// returns []string{"foo", "bar"}.
// Returns ErrNoParent if the path has no parent (empty or root path).
//
// TypeScript Original:
//
//	export function parent(path: Path): Path {
//	  if (path.length < 1) throw new Error('NO_PARENT');
//	  return path.slice(0, path.length - 1);
//	}
func Parent(path Path) (Path, error) {
	if len(path) < 1 {
		return nil, ErrNoParent
	}

	parent := make(Path, len(path)-1)
	copy(parent, path[:len(path)-1])
	return parent, nil
}

// IsValidIndex checks if path component can be a valid array index.
//
// TypeScript Original:
//
//	export function isValidIndex(index: string | number): boolean {
//	  if (typeof index === 'number') return true;
//	  const n = Number.parseInt(index, 10);
//	  return String(n) === index && n >= 0;
//	}
func IsValidIndex(index string) bool {
	if index == "-" {
		return true
	}
	n, err := strconv.ParseInt(index, 10, 64)
	if err != nil {
		return false
	}
	return strconv.FormatInt(n, 10) == index && n >= 0
}

// IsInteger checks if a string contains only digit characters (0-9).
//
// TypeScript Original:
//
//	export const isInteger = (str: string): boolean => {
//	  const len = str.length;
//	  let i = 0;
//	  let charCode: any;
//	  while (i < len) {
//	    charCode = str.charCodeAt(i);
//	    if (charCode >= 48 && charCode <= 57) {
//	      i++;
//	      continue;
//	    }
//	    return false;
//	  }
//	  return true;
//	};
func IsInteger(str string) bool {
	if len(str) == 0 {
		return false
	}
	for i := range len(str) {
		if str[i] < '0' || str[i] > '9' {
			return false
		}
	}
	return true
}

func validateAndAccessArray(key string, length int) (int, error) {
	if key == "-" {
		return -1, ErrIndexOutOfBounds
	}
	index := fastAtoi(key)
	if index < 0 {
		return -1, ErrInvalidIndex
	}
	if index >= length {
		return -1, ErrIndexOutOfBounds
	}
	return index, nil
}
