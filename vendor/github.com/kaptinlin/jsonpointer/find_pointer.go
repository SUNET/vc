package jsonpointer

import (
	"reflect"
	"strings"
)

// TypeScript original code from findByPointer/v5.ts:
//
//	export const findByPointer = (pointer: string, val: unknown): Reference => {
//	  if (!pointer) return {val};
//	  let obj: Reference['obj'];
//	  let key: Reference['key'];
//	  let indexOfSlash = 0;
//	  let indexAfterSlash = 1;
//	  while (indexOfSlash > -1) {
//	    indexOfSlash = pointer.indexOf('/', indexAfterSlash);
//	    key = indexOfSlash > -1 ? pointer.substring(indexAfterSlash, indexOfSlash) : pointer.substring(indexAfterSlash);
//	    indexAfterSlash = indexOfSlash + 1;
//	    obj = val;
//	    if (isArray(obj)) {
//	      const length = obj.length;
//	      if (key === '-') key = length;
//	      else {
//	        const key2 = ~~key;
//	        if ('' + key2 !== key) throw new Error('INVALID_INDEX');
//	        key = key2;
//	        if (key < 0) throw 'INVALID_INDEX';
//	      }
//	      val = obj[key];
//	    } else if (typeof obj === 'object' && !!obj) {
//	      key = unescapeComponent(key);
//	      val = has(obj, key) ? (obj as any)[key] : undefined;
//	    } else throw 'NOT_FOUND';
//	  }
//	  return {val, obj, key};
//	};
func findByPointer(pointer string, val any) (*Reference, error) {
	if pointer == "" {
		return &Reference{Val: val}, nil
	}

	var obj any
	var key string

	for keyStr := range strings.SplitSeq(pointer[1:], "/") {
		obj = val

		switch current := obj.(type) {
		case map[string]any:
			key = unescapeComponent(keyStr)
			var err error
			val, err = stringMapValue(current, key)
			if err != nil {
				return nil, err
			}
			continue

		case *map[string]any:
			if current == nil {
				return nil, ErrNilPointer
			}
			key = unescapeComponent(keyStr)
			var err error
			val, err = stringMapValue(*current, key)
			if err != nil {
				return nil, err
			}
			continue

		case []any:
			next, err := sliceValue(current, keyStr)
			if err != nil {
				return nil, err
			}
			key = keyStr
			val = next
			continue

		case *[]any:
			if current == nil {
				return nil, ErrNilPointer
			}
			next, err := sliceValue(*current, keyStr)
			if err != nil {
				return nil, err
			}
			key = keyStr
			val = next
			continue
		}

		if obj == nil {
			return nil, ErrNotFound
		}

		objVal, err := derefValue(reflect.ValueOf(obj))
		if err != nil {
			return nil, err
		}

		switch objVal.Kind() {
		case reflect.Slice, reflect.Array:
			index, err := validateAndAccessArray(keyStr, objVal.Len())
			if err != nil {
				return nil, err
			}
			val = objVal.Index(index).Interface()
			key = keyStr

		case reflect.Map:
			keyStr = unescapeComponent(keyStr)
			key = keyStr
			mapEntry, err := mapValueByPathKey(objVal, keyStr)
			if err != nil {
				return nil, err
			}
			val = mapEntry.Interface()

		case reflect.Struct:
			keyStr = unescapeComponent(keyStr)
			key = keyStr
			if !structField(keyStr, &objVal) {
				return nil, ErrFieldNotFound
			}
			val = objVal.Interface()

		default:
			return nil, ErrNotFound
		}
	}

	return &Reference{
		Val: val,
		Obj: obj,
		Key: key,
	}, nil
}
