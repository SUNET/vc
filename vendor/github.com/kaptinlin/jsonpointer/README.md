# JSON Pointer

[![Go Module](https://img.shields.io/badge/go-module-blue.svg)](https://golang.org/)
[![Go Reference](https://pkg.go.dev/badge/github.com/kaptinlin/jsonpointer.svg)](https://pkg.go.dev/github.com/kaptinlin/jsonpointer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A read-only JSON Pointer (RFC 6901) library for Go that traverses maps, slices, arrays, structs, and pointers with explicit errors

## Features

- **RFC 6901 semantics**: Parse, format, escape, unescape, and validate JSON Pointer strings with the expected token rules
- **Go-native traversal**: Read `map[string]any`, slices, arrays, structs, and pointers without converting everything to generic JSON first
- **Explicit errors**: Distinguish missing keys, missing struct fields, invalid indexes, nil pointers, and generic traversal failures
- **Small API**: Learn `Get`, `Find`, `GetByPointer`, `FindByPointer`, and a handful of path helpers
- **Fast common paths**: Optimize `map[string]any` and `[]any` reads while keeping reflective fallbacks for typed Go values
- **Benchmarked and tested**: Includes package tests, executable examples, fuzz tests, and benchmark comparisons

## Installation

```bash
go get github.com/kaptinlin/jsonpointer
```

Requires the Go version declared in `go.mod`.

## Quick Start

```go
package main

import (
	"fmt"
	"log"

	"github.com/kaptinlin/jsonpointer"
)

func main() {
	doc := map[string]any{
		"users": []any{
			map[string]any{"name": "Alice"},
		},
	}

	name, err := jsonpointer.GetByPointer(doc, "/users/0/name")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(name)
}
```

## Core APIs

| API | Description |
| --- | --- |
| `Get(doc any, path ...string) (any, error)` | Read a value by path tokens |
| `Find(doc any, path ...string) (*Reference, error)` | Read a value and return its parent container plus last key |
| `GetByPointer(doc any, pointer string) (any, error)` | Read a value directly from a pointer string |
| `FindByPointer(doc any, pointer string) (*Reference, error)` | Read a reference directly from a pointer string |
| `Parse(pointer string) Path` | Convert a pointer string to path tokens |
| `Format(path ...string) string` | Convert path tokens to a pointer string |
| `Escape(component string) string` | Escape `~` and `/` in one token |
| `Unescape(component string) string` | Reverse `Escape` for one token |
| `Validate(pointer string) error` | Validate pointer syntax and length |
| `ValidatePath(path Path) error` | Validate path length |

`GetByPointer` and `FindByPointer` do not call `Validate` automatically. If you need strict pointer syntax checks before traversal, call `Validate` explicitly.

## Reference Results

`Find` and `FindByPointer` return a `Reference`:

| Field | Meaning |
| --- | --- |
| `Val` | The resolved value |
| `Obj` | The parent container when one exists |
| `Key` | The final path token used to reach `Val` |

Use `IsArrayReference` and `IsObjectReference` when you need to inspect the returned parent context.

## Examples

### Read by path tokens

```go
doc := map[string]any{
	"users": []any{
		map[string]any{"name": "Alice"},
	},
}

name, err := jsonpointer.Get(doc, "users", "0", "name")
if err != nil {
	log.Fatal(err)
}
fmt.Println(name)
```

### Read by pointer string

```go
doc := map[string]any{
	"foo/bar": map[string]any{
		"tilde~key": "ready",
	},
}

ref, err := jsonpointer.FindByPointer(doc, "/foo~1bar/tilde~0key")
if err != nil {
	log.Fatal(err)
}
fmt.Println(ref.Val)
fmt.Println(ref.Key)
```

### Traverse structs and pointers

```go
type User struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

user := &User{Name: "Alice", Email: "alice@example.com"}
email, err := jsonpointer.Get(user, "email")
if err != nil {
	log.Fatal(err)
}
fmt.Println(email)
```

### Work with path utilities

```go
path := jsonpointer.Parse("/foo~1bar/tilde~0key")
fmt.Println(path)
fmt.Println(jsonpointer.Format(path...))
fmt.Println(jsonpointer.Validate("/foo~1bar/tilde~0key") == nil)
```

The examples in this README are mirrored in `example_test.go` so `go test` checks they stay correct.

## Error Handling

Common sentinel errors include:

- `ErrKeyNotFound`
- `ErrFieldNotFound`
- `ErrInvalidIndex`
- `ErrIndexOutOfBounds`
- `ErrNilPointer`
- `ErrNotFound`
- `ErrPointerInvalid`
- `ErrPointerTooLong`
- `ErrPathTooLong`

Use `errors.Is` when checking traversal and validation failures.

## Performance

The package optimizes common `map[string]any` and `[]any` reads and falls back to reflection for typed Go values.
See [benchmarks/README.md](benchmarks/README.md) for comparison data and benchmark coverage.

Run benchmarks with:

```bash
task bench
```

## Development

```bash
task test          # Run package tests with the race detector
task lint          # Run golangci-lint and tidy checks
task yamllint      # Lint YAML files
task bench         # Run benchmarks
```

Run the demo program with:

```bash
go run ./examples
```

For development workflow and package contracts, see [AGENTS.md](AGENTS.md) and [`SPECS/`](SPECS/).

## Contributing

Contributions are welcome. Keep `README.md`, `example_test.go`, and the relevant `SPECS/` documents aligned when public behavior changes.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
