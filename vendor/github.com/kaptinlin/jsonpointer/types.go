package jsonpointer

import "reflect"

// Path represents a JSON Pointer path as array of string tokens.
type Path []string

// Reference represents a found reference with context.
type Reference struct {
	Val any    `json:"val"`
	Obj any    `json:"obj,omitempty"`
	Key string `json:"key,omitempty"`
}

// ArrayReference represents a reference to an array element.
// TypeScript original code:
//
//	export interface ArrayReference<T = unknown> {
//	  readonly val: undefined | T;
//	  readonly obj: T[];
//	  readonly key: number;
//	}
type ArrayReference[T any] struct {
	Val *T  `json:"val"`
	Obj []T `json:"obj"`
	Key int `json:"key"`
}

// ObjectReference represents a reference to an object property.
// TypeScript original code:
//
//	export interface ObjectReference<T = unknown> {
//	  readonly val: T;
//	  readonly obj: Record<string, T>;
//	  readonly key: string;
//	}
type ObjectReference[T any] struct {
	Val T            `json:"val"`
	Obj map[string]T `json:"obj"`
	Key string       `json:"key"`
}

// IsArrayReference checks if a Reference points to an array element.
// TypeScript original code:
// export const isArrayReference = <T = unknown>(ref: Reference): ref is ArrayReference<T> =>
//
//	isArray(ref.obj) && typeof ref.key === 'number';
func IsArrayReference(ref Reference) bool {
	objType, ok := referenceObjectType(ref)
	if !ok || (objType.Kind() != reflect.Slice && objType.Kind() != reflect.Array) {
		return false
	}

	return fastAtoi(ref.Key) >= 0
}

// IsObjectReference checks if a Reference points to an object property.
// TypeScript original code:
// export const isObjectReference = <T = unknown>(ref: Reference): ref is ObjectReference<T> =>
//
//	typeof ref.obj === 'object' && typeof ref.key === 'string';
func IsObjectReference(ref Reference) bool {
	objType, ok := referenceObjectType(ref)
	return ok && objType.Kind() == reflect.Map && objType.Key().Kind() == reflect.String
}

func referenceObjectType(ref Reference) (reflect.Type, bool) {
	if ref.Obj == nil {
		return nil, false
	}

	obj := reflect.ValueOf(ref.Obj)
	for {
		switch obj.Kind() {
		case reflect.Pointer, reflect.Interface:
			if obj.IsNil() {
				return nil, false
			}
			obj = obj.Elem()
		default:
			return obj.Type(), true
		}
	}
}
