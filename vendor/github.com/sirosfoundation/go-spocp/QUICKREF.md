# SPOCP Quick Reference

## Installation
```bash
go get github.com/sirosfoundation/go-spocp
```

## Basic Usage

### Create Engine
```go
engine := spocp.NewEngine()
```

### Add Rules
```go
// Using elements
rule := sexp.NewList("resource", sexp.NewAtom("public"))
engine.AddRuleElement(rule)

// Using canonical form
engine.AddRule("(8:resource6:public)")
```

### Query Authorization
```go
query := sexp.NewList("resource", sexp.NewAtom("public"))
if engine.QueryElement(query) {
    // Authorized
}
```

## Star Forms Quick Reference

| Star Form | Syntax | Example | Matches |
|-----------|--------|---------|---------|
| Wildcard | `(*)` | `&starform.Wildcard{}` | Anything |
| Set | `(* set ...)` | `&starform.Set{Elements: []sexp.Element{...}}` | Any element in set |
| Range | `(* range type ...)` | `&starform.Range{RangeType: RangeNumeric, ...}` | Values in range |
| Prefix | `(* prefix str)` | `&starform.Prefix{Value: "/etc/"}` | Strings starting with prefix |
| Suffix | `(* suffix str)` | `&starform.Suffix{Value: ".pdf"}` | Strings ending with suffix |

## Common Patterns

### File Access
```go
// Allow /etc/* files
sexp.NewList("file", &starform.Prefix{Value: "/etc/"})

// Allow *.pdf files
sexp.NewList("file", &starform.Suffix{Value: ".pdf"})
```

### Time-Based
```go
// Work hours 08:00-17:00
sexp.NewList("access", &starform.Range{
    RangeType: starform.RangeTime,
    LowerBound: &starform.RangeBound{Op: starform.OpGE, Value: "08:00:00"},
    UpperBound: &starform.RangeBound{Op: starform.OpLE, Value: "17:00:00"},
})
```

### Action Control
```go
// Allow read or write
sexp.NewList("action", &starform.Set{
    Elements: []sexp.Element{
        sexp.NewAtom("read"),
        sexp.NewAtom("write"),
    },
})
```

### Wildcard
```go
// Admin can do anything
sexp.NewList("permission",
    sexp.NewList("role", sexp.NewAtom("admin")),
    sexp.NewList("action", &starform.Wildcard{}),
)
```

## The <= Relation

`query <= rule` means query is **more specific** (less permissive) than rule.

### Examples

✅ `(http GET)` <= `(http)` - More elements <= fewer elements  
✅ `(user alice)` <= `(user)` - Specific user <= any user  
✅ `"config.txt"` <= `(* prefix conf)` - Matches prefix  
✅ `"12:00:00"` <= `(* range time ge 08:00:00 le 17:00:00)` - In range  
✅ `"read"` <= `(* set read write)` - In set  

❌ `(http)` <= `(http GET)` - Fewer not <= more  
❌ `(http GET)` <= `(http POST)` - Order matters  
❌ `"data.txt"` <= `(* prefix conf)` - Doesn't match prefix  

## Canonical Form

**Format:** `<length>:<data>`

```
Atom:  5:hello
List:  (4:http3:GET)
Nested: (5:spocp(8:Resource6:mailer))
```

**Advanced Form (human-readable):**
```
hello
(http GET)
(spocp (Resource mailer))
```

## Build Commands

```bash
make test          # Run tests
make coverage      # Coverage report
make build         # Build library
make fmt           # Format code
make check         # Full check (fmt + vet + test)
make help          # Show all targets
```

## Range Types

| Type | Description | Example |
|------|-------------|---------|
| `RangeAlpha` | String comparison | `"apple"` to `"zebra"` |
| `RangeNumeric` | Number comparison | `10` to `100` |
| `RangeTime` | Time of day | `08:00:00` to `17:00:00` |
| `RangeDate` | Date/timestamp | RFC3339 format |
| `RangeIPv4` | IPv4 addresses | `192.168.0.0` to `192.168.255.255` |
| `RangeIPv6` | IPv6 addresses | IPv6 format |

## Range Operators

| Operator | Meaning |
|----------|---------|
| `OpGE` | Greater than or equal (>=) |
| `OpGT` | Greater than (>) |
| `OpLE` | Less than or equal (<=) |
| `OpLT` | Less than (<) |

## Error Handling

```go
// Always check parsing errors
parser := sexp.NewParser(input)
elem, err := parser.Parse()
if err != nil {
    log.Fatal(err)
}

// Query errors
authorized, err := engine.Query(queryStr)
if err != nil {
    log.Fatal(err)
}
```

## Thread Safety

⚠️ **Not thread-safe by default**

For concurrent use:
```go
type SafeEngine struct {
    mu     sync.RWMutex
    engine *spocp.Engine
}

func (s *SafeEngine) Query(q string) (bool, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    return s.engine.Query(q)
}
```

## Complete Example

```go
package main

import (
    "fmt"
    "github.com/sirosfoundation/go-spocp"
    "github.com/sirosfoundation/go-spocp/pkg/sexp"
    "github.com/sirosfoundation/go-spocp/pkg/starform"
)

func main() {
    engine := spocp.NewEngine()
    
    // Rule: Any user can GET index.html
    rule := sexp.NewList("http",
        sexp.NewList("page", sexp.NewAtom("index.html")),
        sexp.NewList("action", sexp.NewAtom("GET")),
        sexp.NewList("user"),
    )
    engine.AddRuleElement(rule)
    
    // Query: Can alice GET index.html?
    query := sexp.NewList("http",
        sexp.NewList("page", sexp.NewAtom("index.html")),
        sexp.NewList("action", sexp.NewAtom("GET")),
        sexp.NewList("user", sexp.NewAtom("alice")),
    )
    
    if engine.QueryElement(query) {
        fmt.Println("Access granted!")
    }
}
```

## Further Reading

- `README.md` - Complete user guide
- `API.md` - Detailed API documentation
- `docs/draft-hedberg-spocp-sexp-00.txt` - Specification
- `examples/main.go` - Working examples
