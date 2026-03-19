package trace

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"time"

	"go.opentelemetry.io/otel/attribute"
)

func SafeAttr(key string, val any) attribute.KeyValue {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("SafeAttr panic recovered for key %q: %v", key, r)
		}
	}()

	if val == nil || (isPointer(val) && reflect.ValueOf(val).IsNil()) {
		return fallbackAttr(key, val)
	}

	switch v := val.(type) {
	case *string:
		return attribute.String(key, *v)

	case *int:
		return attribute.Int(key, *v)

	case *int64:
		return attribute.Int64(key, *v)

	case *float64:
		return attribute.Float64(key, *v)

	case *bool:
		return attribute.Bool(key, *v)

	case *[]string:
		return attribute.StringSlice(key, *v)

	case *[]int:
		return attribute.IntSlice(key, *v)

	case *[]float64:
		return attribute.Float64Slice(key, *v)

	case *[]byte:
		if json.Valid(*v) {
			return attribute.String(key, string(*v))
		}
		return attribute.String(key, base64.StdEncoding.EncodeToString(*v))

	case *time.Time:
		return attribute.String(key, v.Format(time.RFC3339))

	case *map[string]string:
		if jsonBytes, err := json.Marshal(*v); err == nil {
			return attribute.String(key, string(jsonBytes))
		}
		return attribute.String(fmt.Sprintf("%s.unsupported", key), "map[string]string marshal error")

	default:
		return fallbackAttr(key, val)
	}
}

func fallbackAttr(key string, val any) attribute.KeyValue {
	var typeName string
	if val == nil {
		typeName = "nil"
	} else {
		typeName = reflect.TypeOf(val).String()
	}
	return attribute.String(fmt.Sprintf("%s.unsupported", key), fmt.Sprintf("unsupported type: %s", typeName))
}

func isPointer(val any) bool {
	return reflect.TypeOf(val).Kind() == reflect.Pointer
}
