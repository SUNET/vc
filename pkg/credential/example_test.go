package credential_test

import (
	"fmt"

	"github.com/SUNET/vc/pkg/credential"
)

func ExampleApplyTransform_lowercase() {
	result := credential.ApplyTransform("HELLO WORLD", "lowercase")
	fmt.Println(result)
	// Output:
	// hello world
}

func ExampleApplyTransform_uppercase() {
	result := credential.ApplyTransform("hello world", "uppercase")
	fmt.Println(result)
	// Output:
	// HELLO WORLD
}

func ExampleApplyTransform_trim() {
	result := credential.ApplyTransform("  padded string  ", "trim")
	fmt.Println(result)
	// Output:
	// padded string
}

func ExampleApplyTransform_noTransform() {
	result := credential.ApplyTransform("unchanged", "")
	fmt.Println(result)
	// Output:
	// unchanged
}

func ExampleApplyTransform_nonString() {
	result := credential.ApplyTransform(42, "lowercase")
	fmt.Println(result)
	// Output:
	// 42
}

func ExampleSetNestedValue() {
	doc := make(map[string]any)

	_ = credential.SetNestedValue(doc, "identity.given_name", "Alice")
	_ = credential.SetNestedValue(doc, "identity.family_name", "Smith")
	_ = credential.SetNestedValue(doc, "vct", "pid")

	fmt.Println("given_name:", doc["identity"].(map[string]any)["given_name"])
	fmt.Println("family_name:", doc["identity"].(map[string]any)["family_name"])
	fmt.Println("vct:", doc["vct"])
	// Output:
	// given_name: Alice
	// family_name: Smith
	// vct: pid
}

func ExampleSetNestedValue_emptyPath() {
	doc := make(map[string]any)
	err := credential.SetNestedValue(doc, "", "value")
	fmt.Println("error:", err)
	// Output:
	// error: empty path
}

func ExampleGetNestedValue() {
	doc := map[string]any{
		"identity": map[string]any{
			"given_name":  "Alice",
			"family_name": "Smith",
		},
		"vct": "pid",
	}

	name, ok := credential.GetNestedValue(doc, "identity.given_name")
	fmt.Println("value:", name, "found:", ok)

	vct, ok := credential.GetNestedValue(doc, "vct")
	fmt.Println("value:", vct, "found:", ok)

	_, ok = credential.GetNestedValue(doc, "missing.path")
	fmt.Println("missing found:", ok)
	// Output:
	// value: Alice found: true
	// value: pid found: true
	// missing found: false
}

func ExampleGetNestedValue_emptyPath() {
	doc := map[string]any{"key": "value"}
	_, ok := credential.GetNestedValue(doc, "")
	fmt.Println("found:", ok)
	// Output:
	// found: false
}

func ExampleNewClaimTransformer() {
	transformer := credential.NewClaimTransformer(nil)
	fmt.Printf("%T\n", transformer)
	// Output:
	// *credential.ClaimTransformer
}
