# MessageFormat Go `v1`

Supported ICU MessageFormat v1 compatibility package for this repository.

`v1` is a package inside the root module, not a standalone Go module. Import it as:

```go
import mf "github.com/kaptinlin/messageformat-go/v1"
```

Do not run `go get github.com/kaptinlin/messageformat-go/v1` as if it were a separate module. Use the root module version instead:

```bash
go get github.com/kaptinlin/messageformat-go@latest
```

## Status

- Supported compatibility surface for ICU MessageFormat v1
- Kept as product code and covered by repository lint and test workflows
- Intended for consumers that still need the legacy MessageFormat v1 API shape

## Quick Start

```go
package main

import (
	"fmt"
	"log"

	mf "github.com/kaptinlin/messageformat-go/v1"
)

func main() {
	messageFormat, err := mf.New("en", nil)
	if err != nil {
		log.Fatal(err)
	}

	msg, err := messageFormat.Compile("Hello, {name}!")
	if err != nil {
		log.Fatal(err)
	}

	result, err := msg(map[string]any{"name": "World"})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(result)
}
```

## Examples

- [Basic](./examples/basic/main.go)
- [E-commerce](./examples/ecommerce/main.go)
- [Multilingual](./examples/multilingual/main.go)
- [Performance](./examples/performance/main.go)

Run examples from the repository root:

```bash
go run ./v1/examples/basic
go run ./v1/examples/ecommerce
go run ./v1/examples/multilingual
go run ./v1/examples/performance
```

## Documentation

- [API reference](./docs/api-reference.md)
- [Performance guide](./docs/performance.md)
- [Examples guide](./examples/README.md)

## Notes

- `v1` is not deprecated inside this repository.
- `v1` must not be pruned during cleanup or refactoring.
- Release tags apply to the root module; `v1` ships as part of that module.
