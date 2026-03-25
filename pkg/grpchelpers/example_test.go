package grpchelpers_test

import (
	"fmt"

	"github.com/SUNET/vc/pkg/grpchelpers"
)

func ExampleFormatFingerprint() {
	// A short hex string for demonstration
	fp := "aabbccdd"
	formatted := grpchelpers.FormatFingerprint(fp)
	fmt.Println(formatted)
	// Output:
	// SHA256:aa:bb:cc:dd
}

func ExampleFormatFingerprint_full() {
	// A full SHA-256 fingerprint (64 hex characters)
	fp := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	formatted := grpchelpers.FormatFingerprint(fp)
	fmt.Println(formatted)
	// Output:
	// SHA256:e3:b0:c4:42:98:fc:1c:14:9a:fb:f4:c8:99:6f:b9:24:27:ae:41:e4:64:9b:93:4c:a4:95:99:1b:78:52:b8:55
}
