# JSON Pointer

[![Go Module](https://img.shields.io/badge/go-module-blue.svg)](https://golang.org/)
[![Go Reference](https://pkg.go.dev/badge/github.com/kaptinlin/jsonpointer.svg)](https://pkg.go.dev/github.com/kaptinlin/jsonpointer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A read-only JSON Pointer (RFC 6901) library for Go built around one strict,
immutable `Pointer` value.

## Features

- **Strict RFC 6901 parsing**: malformed pointer strings return errors instead
  of becoming lookup keys.
- **Raw token construction**: build pointers from literal Go strings without
  confusing token text with pointer-string syntax.
- **Go-native traversal**: read JSON-shaped maps, slices, arrays, typed
  string-keyed maps, pointers, and interface-wrapped values.
- **Explicit errors**: keep `errors.Is` sentinel checks and use `errors.As` for
  pointer, token, and depth context.
- **Small API**: parse or build a `Pointer`, then ask it for a value or
  reference.
- **Fast common paths**: optimize decoded JSON shapes such as `map[string]any`
  and `[]any` before typed-container fallbacks.

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

	p, err := jsonpointer.Parse("/users/0/name")
	if err != nil {
		log.Fatal(err)
	}

	name, err := p.Value(doc)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(name)
}
```

## Core APIs

| API | Description |
| --- | --- |
| `Parse(pointer string) (Pointer, error)` | Parse a strict JSON Pointer string |
| `FromTokens(tokens ...string) Pointer` | Build a pointer from raw token strings |
| `Root() Pointer` | Return the root pointer |
| `(Pointer).String() string` | Format the canonical JSON Pointer string |
| `(Pointer).Tokens() []string` | Return a copy of the raw tokens |
| `(Pointer).Parent() (Pointer, error)` | Return the parent pointer |
| `(Pointer).Child(tokens ...string) Pointer` | Return a child pointer |
| `(Pointer).Value(doc any) (any, error)` | Resolve a value |
| `(Pointer).Reference(doc any) (Reference, error)` | Resolve a value with parent context |
| `Value(doc any, pointer string) (any, error)` | Strict one-shot value lookup |
| `ReferenceOf(doc any, pointer string) (Reference, error)` | Strict one-shot reference lookup |
| `EscapeToken(token string) string` | Escape one raw token |
| `UnescapeToken(encoded string) (string, error)` | Decode one escaped token strictly |
| `IsArrayIndex(token string) bool` | Report whether a token has canonical array-index syntax |

`Parse("/~2")` returns `ErrInvalidPointer`. `FromTokens("~2")` succeeds because
`"~2"` is literal token data, not pointer-string syntax.

## Reference Results

`Pointer.Reference` and `ReferenceOf` return a `Reference` with named accessors:

| Method | Meaning |
| --- | --- |
| `Value() any` | The resolved value |
| `Parent() (any, bool)` | The parent container when one exists |
| `Token() string` | The final token used to reach the value |
| `Pointer() Pointer` | The pointer used for traversal |

Root references have no parent and return `(nil, false)` from `Parent`. For
non-root references, `Parent` is the dereferenced container that consumed the
final token, so pointer and interface wrappers do not leak into reference
context.

## Examples

### Build from raw tokens

```go
p := jsonpointer.FromTokens("foo/bar", "tilde~key")
fmt.Println(p.String())
```

Output:

```text
/foo~1bar/tilde~0key
```

### Read with parent context

```go
doc := map[string]any{
	"foo/bar": map[string]any{
		"tilde~key": "ready",
	},
}

p, err := jsonpointer.Parse("/foo~1bar/tilde~0key")
if err != nil {
	log.Fatal(err)
}

ref, err := p.Reference(doc)
if err != nil {
	log.Fatal(err)
}
fmt.Println(ref.Value())
fmt.Println(ref.Token())
```

### Traverse typed containers

```go
type Key string

doc := map[string]any{
	"labels": map[Key]string{
		"status": "ready",
	},
}

p := jsonpointer.FromTokens("labels", "status")
status, err := p.Value(doc)
if err != nil {
	log.Fatal(err)
}
fmt.Println(status)
```

Traversal follows JSON-shaped containers. Structs are not field-selected; convert
struct values to a JSON document shape before using JSON Pointer over fields.

## Error Handling

Pointer construction and navigation sentinel errors include:

- `ErrInvalidPointer`
- `ErrNoParent`

Traversal sentinel errors include:

- `ErrKeyNotFound`
- `ErrInvalidIndex`
- `ErrIndexOutOfBounds`
- `ErrNilPointer`
- `ErrNotTraversable`

For arrays, malformed index tokens such as `01`, `+1`, non-ASCII digits, or
decimal text return `ErrInvalidIndex`. `-`, indexes outside the collection, and
arbitrarily long canonical indexes outside the collection return
`ErrIndexOutOfBounds`.
Values that cannot consume another token return `ErrNotTraversable`; a nil Go
pointer returns the more specific `ErrNilPointer`.

Use `errors.Is` for error classes and `errors.As` when traversal context matters:

```go
value, err := jsonpointer.Value(doc, "/users/1/name")
if errors.Is(err, jsonpointer.ErrIndexOutOfBounds) {
	var pointerErr *jsonpointer.Error
	if errors.As(err, &pointerErr) {
		fmt.Println(pointerErr.Pointer(), pointerErr.Token(), pointerErr.Depth())
	}
}
_ = value
```

## Performance

The package optimizes common `map[string]any` and `[]any` reads and falls back to
reflection only for typed container mechanics such as slices, arrays, maps,
pointers, and interfaces. Reuse parsed pointers when resolving the same location
repeatedly.

See [benchmarks/README.md](benchmarks/README.md) for benchmark coverage.

Run benchmarks with:

```bash
task bench
```

## Development

```bash
task test          # Run package tests with the race detector
task lint          # Run golangci-lint and tidy checks
task specs-check   # Validate spec and design doc placement
task yamllint      # Lint YAML files
task bench         # Run benchmark suites
```

Run the demo program with:

```bash
go run ./examples
```

For development workflow and package contracts, see [AGENTS.md](AGENTS.md) and
[`SPECS/`](SPECS/).

## Contributing

Contributions are welcome. Keep `README.md`, `example_test.go`, and the relevant
`SPECS/` documents aligned when public behavior changes.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file
for details.
