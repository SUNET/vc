package trace_test

import (
	"fmt"

	"github.com/SUNET/vc/pkg/trace"
)

func ExampleSafeAttr_string() {
	s := "hello"
	attr := trace.SafeAttr("greeting", &s)
	fmt.Println(attr.Key)
	fmt.Println(attr.Value.AsString())
	// Output:
	// greeting
	// hello
}

func ExampleSafeAttr_int() {
	n := 42
	attr := trace.SafeAttr("count", &n)
	fmt.Println(attr.Key)
	fmt.Println(attr.Value.AsInt64())
	// Output:
	// count
	// 42
}

func ExampleSafeAttr_bool() {
	b := true
	attr := trace.SafeAttr("enabled", &b)
	fmt.Println(attr.Key)
	fmt.Println(attr.Value.AsBool())
	// Output:
	// enabled
	// true
}

func ExampleSafeAttr_float64() {
	f := 3.14
	attr := trace.SafeAttr("pi", &f)
	fmt.Println(attr.Key)
	fmt.Println(attr.Value.AsFloat64())
	// Output:
	// pi
	// 3.14
}

func ExampleSafeAttr_nil() {
	attr := trace.SafeAttr("missing", nil)
	fmt.Println(attr.Key)
	// Output:
	// missing.unsupported
}

func ExampleSafeAttr_stringSlice() {
	vals := []string{"a", "b", "c"}
	attr := trace.SafeAttr("tags", &vals)
	fmt.Println(attr.Key)
	fmt.Println(attr.Value.AsStringSlice())
	// Output:
	// tags
	// [a b c]
}
