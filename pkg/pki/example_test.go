package pki_test

import (
	"fmt"

	"github.com/SUNET/vc/pkg/pki"
)

func ExampleNewKeyLoader() {
	kl := pki.NewKeyLoader()
	fmt.Printf("%T\n", kl)
	// Output:
	// *pki.KeyLoader
}

func ExampleNewSignerConfig() {
	config := pki.NewSignerConfig(&pki.KeyConfig{
		PrivateKeyPath: "/path/to/key.pem",
		ChainPath:      "/path/to/chain.pem",
	})
	fmt.Printf("%T\n", config)
	// Output:
	// *pki.SignerConfig
}

func ExampleKeySourceFile() {
	fmt.Println(pki.KeySourceFile)
	fmt.Println(pki.KeySourceHSM)
	// Output:
	// 0
	// 1
}
