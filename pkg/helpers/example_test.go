package helpers_test

import (
	"fmt"

	"github.com/SUNET/vc/pkg/helpers"
)

func ExampleNewError() {
	err := helpers.NewError("NOT_FOUND")
	fmt.Println(err)
	// Output:
	// Error: [NOT_FOUND]
}

func ExampleNewErrorDetails() {
	err := helpers.NewErrorDetails("VALIDATION_FAILED", "field 'name' is required")
	fmt.Println(err)
	// Output:
	// Error: [VALIDATION_FAILED] field 'name' is required
}

func ExampleNewErrorWithStatus() {
	err := helpers.NewErrorWithStatus("UNAUTHORIZED", 401)
	fmt.Println(err)
	fmt.Println("status:", err.HTTPStatus)
	// Output:
	// Error: [UNAUTHORIZED]
	// status: 401
}

func ExampleHostFromURL() {
	host, err := helpers.HostFromURL("https://example.com:8080/path")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(host)
	// Output:
	// example.com:8080
}

func ExampleHostFromURL_withoutPort() {
	host, err := helpers.HostFromURL("https://example.com/path/to/resource")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(host)
	// Output:
	// example.com
}

func ExampleHostFromURL_noHost() {
	_, err := helpers.HostFromURL("not-a-url")
	fmt.Println("error:", err)
	// Output:
	// error: URL "not-a-url" has no host
}
