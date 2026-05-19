package jsonpointer

import (
	"cmp"
	"reflect"
	"strings"
	"sync"
)

type structFields map[string]int

var structFieldsCache sync.Map

func structField(field string, value *reflect.Value) bool {
	for value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return false
		}
		*value = value.Elem()
	}

	if value.Kind() != reflect.Struct {
		return false
	}

	fields := getStructFields(value.Type())
	fieldIndex, ok := fields[field]
	if !ok {
		return false
	}

	*value = value.Field(fieldIndex)
	return true
}

func getStructFields(t reflect.Type) structFields {
	if cached, ok := structFieldsCache.Load(t); ok {
		return cached.(structFields)
	}

	fields := make(structFields)
	for field := range t.Fields() {
		if !field.IsExported() {
			continue
		}

		name := getFieldName(&field)
		if name == "-" {
			continue
		}

		fields[name] = field.Index[0]
	}

	cached, _ := structFieldsCache.LoadOrStore(t, fields)
	return cached.(structFields)
}

func getFieldName(field *reflect.StructField) string {
	tag := field.Tag.Get("json")
	if tag == "" {
		return field.Name
	}

	name, _, _ := strings.Cut(tag, ",")
	return cmp.Or(name, field.Name)
}
