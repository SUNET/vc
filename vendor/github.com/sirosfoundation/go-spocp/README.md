# go-spocp

[![Go Reference](https://pkg.go.dev/badge/github.com/sirosfoundation/go-spocp.svg)](https://pkg.go.dev/github.com/sirosfoundation/go-spocp)
[![CI](https://github.com/sirosfoundation/go-spocp/actions/workflows/ci.yml/badge.svg)](https://github.com/sirosfoundation/go-spocp/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/sirosfoundation/go-spocp)](https://goreportcard.com/report/github.com/sirosfoundation/go-spocp)
[![codecov](https://codecov.io/gh/sirosfoundation/go-spocp/branch/main/graph/badge.svg)](https://codecov.io/gh/sirosfoundation/go-spocp)
[![License](https://img.shields.io/badge/License-BSD_2--Clause-blue.svg)](https://opensource.org/licenses/BSD-2-Clause)

## Overview

A Go implementation of the SPOCP (Simple Policy Control Protocol) authorization engine based on restricted S-expressions. SPOCP is a lightning fast policy engine useful both as an embedded solution and as a server supporting AuthZen and a raw TCP protocol. SPOCP is orders of magnitude fast than similar policy engines.

## Acknowledgement

SPOCP was originally the brain-child of Roland Hedberg of Umeå University and this implementation is dedicated to his long service to the open source and standards community.

## Features

- **S-expression Parser**: Parses canonical form S-expressions (length-prefixed format)
- **Star Forms**: Support for wildcard, set, range, prefix, and suffix patterns
- **Partial Order Comparison**: Implements the `<=` (less permissive) relation from the specification
- **Authorization Engine**: Query-based policy evaluation with multiple strategies:
  - **Regular Engine**: Manual control over indexing
  - **Adaptive Engine**: Automatically optimizes based on ruleset characteristics
- **Tag-Based Indexing**: 2-5x performance improvement for large rulesets with diverse tags
- **Flexible Protocol Support**: TCP, HTTP, or both simultaneously
- **TCP Server**: Production-ready SPOCP protocol server (draft-hedberg-spocp-tcp-00)
  - TLS support with certificate validation
  - Multi-client connection handling
  - Dynamic rule reloading (zero downtime)
  - PID file management
  - Configurable logging (5 levels: silent/error/warn/info/debug)
  - Graceful shutdown with connection cleanup
- **HTTP Server**: Unified monitoring and optional AuthZen API
  - Always provides: `/health`, `/ready`, `/stats`, `/metrics` endpoints
  - Optionally enables: AuthZen Authorization API 1.0 (`POST /access/v1/evaluation`)
  - Automatic AuthZen-to-SPOCP query translation
  - Shared or standalone engine modes
  - Request metrics and X-Request-ID tracing support
  - See [docs/AUTHZEN.md](docs/AUTHZEN.md) for details
- **TCP Client**: Connection pooling client library with batch operations
- **Rule Persistence**: Load/save rules from files (text and binary formats)
- **Type-Safe**: Strongly typed implementation in Go
- **Well-Tested**: Comprehensive test suite (>96% coverage) based on specification examples

## Installation

```bash
go get github.com/sirosfoundation/go-spocp
```

### Building the Server Tools

```bash
# Build server and client to bin/
make build-tools

# Or build individually
make build-server  # Creates bin/spocpd
make build-client  # Creates bin/spocp-client
```

### Quick Server Start

```bash
# Start TCP server with HTTP monitoring
bin/spocpd -tcp -tcp-addr :6000 -http-addr :8000 -rules ./examples/rules -log info

# In another terminal, query via TCP
bin/spocp-client -addr localhost:6000
> query (http (page index.html)(action GET)(user alice))
✓ OK - Query matched

# Check server health and stats via HTTP (always available)
curl http://localhost:8000/health
{"status":"ok"}

curl http://localhost:8000/stats | jq .
{"queries": {"total": 1, "ok": 1, "denied": 0}, ...}
```

### HTTP/AuthZen API Server

```bash
# HTTP-only with AuthZen API enabled
bin/spocpd -authzen -http-addr :8000 -rules ./examples/rules -log info

# Query using AuthZen API
curl -X POST http://localhost:8000/access/v1/evaluation \
  -H "Content-Type: application/json" \
  -d '{
    "subject": {"type": "user", "id": "alice@acmecorp.com"},
    "resource": {"type": "account", "id": "123"},
    "action": {"name": "can_read"}
  }'

# Response: {"decision": true}

# Health and stats endpoints are always available on HTTP server
curl http://localhost:8000/health   # {"status":"ok"}
curl http://localhost:8000/ready    # {"status":"ready"}
curl http://localhost:8000/stats    # JSON statistics
curl http://localhost:8000/metrics  # Prometheus metrics

# Run both TCP and HTTP/AuthZen (shared engine)
bin/spocpd -tcp -tcp-addr :6000 -authzen -http-addr :8000 -rules ./examples/rules -log info
```

See [`docs/OPERATIONS.md`](docs/OPERATIONS.md) for complete deployment guide and [`docs/AUTHZEN.md`](docs/AUTHZEN.md) for HTTP/AuthZen API details.


## Quick Start

### Recommended Approach

```go
package main

import (
    "fmt"
    "github.com/sirosfoundation/go-spocp"
    "github.com/sirosfoundation/go-spocp/pkg/sexp"
)

func main() {
    // Create an engine - automatically optimizes based on your ruleset
    engine := spocp.New()  // Recommended!

    // Add rules - indexing automatically adapts
    rule := sexp.NewList("http",
        sexp.NewList("page", sexp.NewAtom("index.html")),
        sexp.NewList("action", sexp.NewAtom("GET")),
        sexp.NewList("user"),
    )
    engine.AddRuleElement(rule)

    // Query authorization
    query := sexp.NewList("http",
        sexp.NewList("page", sexp.NewAtom("index.html")),
        sexp.NewList("action", sexp.NewAtom("GET")),
        sexp.NewList("user", sexp.NewAtom("alice")),
    )

    if engine.QueryElement(query) {
        fmt.Println("Access granted!")
    }

    // Check adaptive statistics
    stats := engine.Stats()
    fmt.Printf("Rules: %d, Indexing: %v\n", stats.TotalRules, stats.IndexingEnabled)
}
```

**Note**: `spocp.New()` is an alias for `spocp.NewAdaptiveEngine()` - use whichever name you prefer.

### Advanced: Using the Regular Engine

For benchmarking, testing, or when you need explicit control:

```go
func main() {
    // Create a regular engine with always-on indexing
    engine := spocp.NewEngine()  // For advanced use

    // Add a rule: allow any user to GET index.html
    // (http (page index.html)(action GET)(user))
    rule := sexp.NewList("http",
        sexp.NewList("page", sexp.NewAtom("index.html")),
        sexp.NewList("action", sexp.NewAtom("GET")),
        sexp.NewList("user"),
    )
    engine.AddRuleElement(rule)

    // Query: can user 'alice' GET index.html?
    // (http (page index.html)(action GET)(user alice))
    query := sexp.NewList("http",
        sexp.NewList("page", sexp.NewAtom("index.html")),
        sexp.NewList("action", sexp.NewAtom("GET")),
        sexp.NewList("user", sexp.NewAtom("alice")),
    )

    // Check authorization
    if engine.QueryElement(query) {
        fmt.Println("Access granted!")
    } else {
        fmt.Println("Access denied!")
    }
}
```

## S-Expression Format

The library uses Rivest's canonical S-expression format where each atom is prefixed by its length:

**Canonical Form:**
```
(5:spocp(8:Resource6:mailer))
```

**Advanced Form (for humans):**
```
(spocp (Resource mailer))
```

## Star Forms

Star forms represent sets of possible values:

### Wildcard `(*)`
Matches any single element:
```go
&starform.Wildcard{}
```

### Set `(* set ...)`
Matches any element in the set:
```go
&starform.Set{
    Elements: []sexp.Element{
        sexp.NewAtom("read"),
        sexp.NewAtom("write"),
    },
}
```

### Range `(* range type op value ...)`
Matches values within a range:
```go
&starform.Range{
    RangeType: starform.RangeNumeric,
    LowerBound: &starform.RangeBound{
        Op:    starform.OpGE,
        Value: "10",
    },
    UpperBound: &starform.RangeBound{
        Op:    starform.OpLE,
        Value: "20",
    },
}
```

Supported range types:
- `RangeAlpha` - lexicographic string comparison
- `RangeNumeric` - numeric comparison
- `RangeDate` - date/time comparison (RFC3339 format)
- `RangeTime` - time of day comparison
- `RangeIPv4` - IPv4 address comparison
- `RangeIPv6` - IPv6 address comparison

### Prefix `(* prefix string)`
Matches strings with the given prefix:
```go
&starform.Prefix{Value: "/etc/"}
```

### Suffix `(* suffix string)`
Matches strings with the given suffix:
```go
&starform.Suffix{Value: ".pdf"}
```

## The Less-Permissive Relation (`<=`)

The core of SPOCP is the partial order relation `<=` where `A <= B` means "rule A is less permissive than rule B" (A grants fewer permissions than B).

### Examples

```go
// (fruit apple large red) <= (fruit apple)
// More specific <= more general (fewer elements)

// (http (page index.html)(action GET)(user alice)) <= (http (page index.html)(action GET)(user))
// Specific user <= any user

// "config.txt" <= (* prefix "conf")
// Specific string <= prefix pattern
```

### Rules (from specification section 6):

1. `T = (*)` → always true (wildcard matches anything)
2. Both atoms and equal → true
3. S is atom, T is star form matching S → true
4. Both ranges and T contains S → true
5. Both prefixes and T's prefix contains S → true
6. Both suffixes and T's suffix contains S → true
7. Both lists, `len(T) <= len(S)` and `S[i] <= T[i]` for all i → true
8. S is set and all elements `<= T` → true
9. T is set and S `<=` some element → true

**Important:** Order matters! `(a b c) <= (a b)` but `(a b c)` is NOT `<= (a c)`

## Usage Examples

### File Access Control

```go
engine := spocp.NewEngine()

// Allow access to files under /etc/
rule := sexp.NewList("file", &starform.Prefix{Value: "/etc/"})
engine.AddRuleElement(rule)

// Check if user can access /etc/passwd
query := sexp.NewList("file", sexp.NewAtom("/etc/passwd"))
authorized := engine.QueryElement(query) // true

// Check if user can access /var/log
query2 := sexp.NewList("file", sexp.NewAtom("/var/log"))
authorized2 := engine.QueryElement(query2) // false
```

### Time-Based Access

```go
// Work hours rule: 08:00:00 to 17:00:00
rule := sexp.NewList("worktime", &starform.Range{
    RangeType: starform.RangeTime,
    LowerBound: &starform.RangeBound{
        Op:    starform.OpGE,
        Value: "08:00:00",
    },
    UpperBound: &starform.RangeBound{
        Op:    starform.OpLE,
        Value: "17:00:00",
    },
})
engine.AddRuleElement(rule)

// Check access at 12:00:00
query := sexp.NewList("worktime", sexp.NewAtom("12:00:00"))
authorized := engine.QueryElement(query) // true
```

### Action-Based Access

```go
// Allow read or write actions only
rule := sexp.NewList("action", &starform.Set{
    Elements: []sexp.Element{
        sexp.NewAtom("read"),
        sexp.NewAtom("write"),
    },
})
engine.AddRuleElement(rule)

query := sexp.NewList("action", sexp.NewAtom("read"))
authorized := engine.QueryElement(query) // true

query2 := sexp.NewList("action", sexp.NewAtom("delete"))
authorized2 := engine.QueryElement(query2) // false
```

## Performance and Indexing

### Adaptive Engine (Recommended)

The `AdaptiveEngine` automatically decides whether to use tag-based indexing based on your ruleset:

```go
engine := spocp.NewAdaptiveEngine()

// Add rules - indexing automatically adapts
for i := 0; i < 100; i++ {
    engine.AddRule("(4:read4:file)")
}

// Check if indexing was enabled
stats := engine.Stats()
fmt.Printf("Indexing: %v (based on %d rules, %d tags)\n",
    stats.IndexingEnabled, stats.TotalRules, stats.UniqueTags)
```

**Indexing is enabled when:**
- Total rules ≥ 50
- Unique tags ≥ 5
- Average rules per tag ≤ 100

**Performance Benefits:**
- Small rulesets (< 50): No indexing overhead
- Large rulesets with diverse tags: 2-5x faster queries
- Large rulesets with few tags: No indexing (not beneficial)

See [ADAPTIVE_ENGINE.md](docs/ADAPTIVE_ENGINE.md) for details.

### Manual Indexing Control

For advanced use cases (benchmarking, testing, or specific performance requirements):

```go
// Regular engine - always indexed
engine := spocp.NewEngine()

// Regular engine - never indexed (for comparison/testing)
engine := spocp.NewEngineWithIndexing(false)

// Adaptive with manual override (for testing adaptive behavior)
engine := spocp.NewAdaptiveEngine()
engine.ForceIndexing(true)  // Force enable for testing
```

**When to use regular `Engine` instead of `AdaptiveEngine`:**
- **Benchmarking**: Need to measure indexed vs non-indexed performance
- **Testing**: Verifying specific indexing behaviors
- **Known workload**: You've profiled and know exactly which strategy is optimal
- **Minimal overhead**: The adaptive statistics tracking (< 0.1%) matters for your use case

**For production use**: Use `NewAdaptiveEngine()` - it adapts automatically and has negligible overhead.

## Building and Testing

```bash
# Run tests
make test

# Run tests with coverage
make coverage

# Format code
make fmt

# Run all checks (fmt, vet, test)
make check

# Build
make build

# Clean
make clean

# See all available targets
make help
```

## Project Structure

```
.
├── spocp.go                   # Main engine API
├── spocp_test.go              # Integration tests
├── pkg/
│   ├── sexp/                  # S-expression parser and types
│   │   ├── sexp.go
│   │   └── sexp_test.go
│   ├── starform/              # Star form implementations
│   │   ├── starform.go
│   │   └── starform_test.go
│   └── compare/               # Comparison algorithm
│       ├── compare.go
│       └── compare_test.go
├── docs/                      # Specification documents
├── Makefile                   # Build automation
└── README.md
```

## Specification

This implementation is based on:
- **draft-hedberg-spocp-sexp-00**: Restricted S-expressions for use in a generalized authorization service

The specification can be found in the `docs/` directory.

## Key Concepts from the Specification

### Generalized Authorization Service

SPOCP provides a **generalized** authorization service, meaning:
- Application-independent policy evaluation
- No knowledge of application semantics required
- Can serve multiple applications simultaneously

### Restricted S-expressions

Restrictions compared to general S-expressions:
- Empty lists not allowed
- First element of a list must be an atom (the "tag")
- Star forms have specific constraints (e.g., sets cannot have duplicate tags)
- Canonical form uses length-prefixed atoms

### Authorization Model

```
Principal P wants to perform Action A requiring Authorization X
→ Authorized if ∃ Rule Y such that X <= Y
```

The engine doesn't need to know:
- The identity of future clients
- The meaning of the policies
- All information for the decision (can delegate)

## Performance

### ⚡ Tag-Based Indexing (New!)

The engine now uses **tag-based indexing** by default for **2-5x faster queries**:

- **100 rules**: ~2 µs per query (480k queries/sec) - **2.9x faster**
- **1,000 rules**: ~19 µs per query (51k queries/sec) - **3.6x faster**
- **10,000 rules**: ~260 µs per query (3.8k queries/sec) - **3.2x faster**
- **50,000 rules**: ~2.3 ms per query (434 queries/sec) - **1.9x faster**
- **Zero allocations** during query evaluation ✅

Indexing adds only **24% memory overhead** while providing significant speedup.

**Highly selective queries** (few rules per tag) can be **100-2000x faster**!

For performance details and optimization strategies, see:

- **[`docs/OPERATIONS.md`](docs/OPERATIONS.md)** - Complete production deployment and operations guide ⭐
- **[`docs/TCP_SERVER.md`](docs/TCP_SERVER.md)** - SPOCP TCP protocol server and client documentation
- **[`docs/ADAPTIVE_ENGINE.md`](docs/ADAPTIVE_ENGINE.md)** - Adaptive indexing strategies and engine selection
- **[`docs/OPTIMIZATION_SUMMARY.md`](docs/OPTIMIZATION_SUMMARY.md)** - Performance guide and when to optimize
- **[`docs/FILE_LOADING.md`](docs/FILE_LOADING.md)** - Efficient bulk loading and serialization
- **[`INDEXING_RESULTS.md`](INDEXING_RESULTS.md)** - Tag-based indexing implementation and results
- **[`PERFORMANCE_REPORT.md`](PERFORMANCE_REPORT.md)** - Complete benchmark results and analysis

## Contributing

Contributions are welcome! Please ensure:
- All tests pass (`make test`)
- Code is formatted (`make fmt`)
- No vet warnings (`make vet`)
- New features have tests

## License

[Specify your license here]

## References

- SPOCP Project: Originally developed at the Swedish Institute of Computer Science (SICS)
- S-expressions: Based on Rivest's S-expression specification
- SPKI: Simple Public Key Infrastructure (related work using S-expressions)

## Authors

This Go implementation is based on the specification by:
- Roland Hedberg (Stockholm University)
- Olav Bandmann (Industrilogik L4i AB)

Original SPOCP project contributors:
- Babak Sadighi (original concepts)
- Mads Dam (mathematical evaluation)
- Torbjörn Wiberg (project leader)
- Leif Johansson
- Ola Gustafsson
