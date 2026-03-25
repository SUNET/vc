package crypto_test

import (
	"fmt"

	"github.com/SUNET/vc/pkg/crypto"
)

func ExampleGenerateSecureToken_defaultSize() {
	token, err := crypto.GenerateSecureToken(0, 0)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	// Default: 32 bytes -> 43 base64url characters
	fmt.Println("length:", len(token))
	// Output:
	// length: 43
}

func ExampleGenerateSecureToken_exactStringLength() {
	token, err := crypto.GenerateSecureToken(0, 16)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("length:", len(token))
	// Output:
	// length: 16
}

func ExampleGenerateSecureToken_byteSize() {
	token, err := crypto.GenerateSecureToken(10, 0)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	// 10 bytes -> 14 base64url characters (ceil(10*4/3) without padding)
	fmt.Println("length:", len(token))
	// Output:
	// length: 14
}

func ExampleGenerateSecureToken_exceedsMaxLength() {
	_, err := crypto.GenerateSecureToken(0, 200)
	fmt.Println("error:", err)
	// Output:
	// error: requested stringLength 200 exceeds maximum supported length of 128
}

func ExampleGenerateSecureToken_exceedsMaxByteSize() {
	_, err := crypto.GenerateSecureToken(100, 0)
	fmt.Println("error:", err)
	// Output:
	// error: requested byteSize 100 exceeds maximum supported size of 96 bytes
}
