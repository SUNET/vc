package mdoc_test

import (
	"fmt"

	"github.com/SUNET/vc/pkg/mdoc"
)

func ExampleDocType() {
	fmt.Println(mdoc.DocType)
	// Output:
	// org.iso.18013.5.1.mDL
}

func ExampleNamespace() {
	fmt.Println(mdoc.Namespace)
	// Output:
	// org.iso.18013.5.1
}

func ExampleNewCBOREncoder() {
	enc, err := mdoc.NewCBOREncoder()
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Printf("%T\n", enc)
	// Output:
	// *mdoc.CBOREncoder
}

func ExampleCBOREncoder_Marshal() {
	enc, err := mdoc.NewCBOREncoder()
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	// Encode a simple map to CBOR
	original := map[string]string{"hello": "world"}
	data, err := enc.Marshal(original)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("encoded length:", len(data))

	// Decode back
	var decoded map[string]string
	if err := enc.Unmarshal(data, &decoded); err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("decoded:", decoded["hello"])
	// Output:
	// encoded length: 13
	// decoded: world
}

func ExampleCompareCBOR() {
	enc, err := mdoc.NewCBOREncoder()
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	a, _ := enc.Marshal("test")
	b, _ := enc.Marshal("test")
	c, _ := enc.Marshal("other")

	fmt.Println("same:", mdoc.CompareCBOR(a, b))
	fmt.Println("different:", mdoc.CompareCBOR(a, c))
	// Output:
	// same: true
	// different: false
}

func ExampleNewMSOBuilder() {
	builder := mdoc.NewMSOBuilder(mdoc.DocType)
	fmt.Printf("%T\n", builder)
	// Output:
	// *mdoc.MSOBuilder
}

func ExampleDigestAlgorithmSHA256() {
	fmt.Println(mdoc.DigestAlgorithmSHA256)
	// Output:
	// SHA-256
}

func ExampleFullDate() {
	enc, err := mdoc.NewCBOREncoder()
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	date := mdoc.FullDate("2024-01-15")
	data, err := enc.Marshal(date)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	var decoded mdoc.FullDate
	if err := enc.Unmarshal(data, &decoded); err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(string(decoded))
	// Output:
	// 2024-01-15
}
