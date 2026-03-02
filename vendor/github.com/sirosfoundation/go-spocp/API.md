# SPOCP API Documentation

## Package Overview

The go-spocp library provides three main packages:

- `spocp` - Main engine and API
- `pkg/sexp` - S-expression parser and types
- `pkg/starform` - Star form implementations
- `pkg/compare` - Comparison algorithm

## Package: spocp

The main SPOCP authorization engine.

## Choosing an Engine

### Recommended: Use `New()`

For most use cases, simply use `spocp.New()`:
- Automatically optimizes based on ruleset characteristics
- No configuration needed
- Optimal performance for both small and large rulesets
- Returns an `*AdaptiveEngine`

### Advanced: Manual Control

Use `NewEngine()` or `NewEngineWithIndexing()` for:
- **Benchmarking**: Measuring specific indexing strategies
- **Testing**: Verifying indexing behavior
- **Known workloads**: When profiling shows a specific strategy is always optimal

### type AdaptiveEngine

```go
type AdaptiveEngine struct {
    // contains filtered or unexported fields
}
```

**Recommended for most users.** Automatically decides whether to use tag-based indexing based on ruleset characteristics. Provides optimal performance without manual configuration.

#### func New

```go
func New() *AdaptiveEngine
```

**Recommended constructor.** Creates a new adaptive SPOCP engine that automatically optimizes query strategy. This is an alias for `NewAdaptiveEngine()`.

**Example:**
```go
engine := spocp.New()  // Recommended!

// Add rules - indexing automatically adapts
engine.AddRule("(4:read4:file)")

// Check if indexing was enabled
stats := engine.Stats()
fmt.Printf("Indexing: %v\n", stats.IndexingEnabled)
```

#### func NewAdaptiveEngine

```go
func NewAdaptiveEngine() *AdaptiveEngine
```

Creates a new adaptive SPOCP engine. This is the same as `New()` - use whichever name you prefer.

**Example:**
```go
engine := spocp.NewAdaptiveEngine()  // Same as spocp.New()
```

#### func (*AdaptiveEngine) Stats

```go
func (ae *AdaptiveEngine) Stats() AdaptiveStats
```

Returns statistics about the adaptive behavior including rule counts, tag diversity, and whether indexing is enabled.

**Example:**
```go
stats := engine.Stats()
fmt.Printf("Rules: %d, Tags: %d, Indexing: %v\n",
    stats.TotalRules, stats.UniqueTags, stats.IndexingEnabled)
```

#### func (*AdaptiveEngine) ForceIndexing

```go
func (ae *AdaptiveEngine) ForceIndexing(enabled bool)
```

Manually override the adaptive indexing decision. Useful for testing or debugging.

**Example:**
```go
engine.ForceIndexing(true)  // Force enable indexing
engine.ForceIndexing(false) // Force disable indexing
```

See [ADAPTIVE_ENGINE.md](docs/ADAPTIVE_ENGINE.md) for detailed documentation.

---

### type Engine

```go
type Engine struct {
    // contains filtered or unexported fields
}
```

The base SPOCP policy engine. Use `AdaptiveEngine` instead unless you need explicit control over indexing for benchmarking or testing.

#### func NewEngine

```go
func NewEngine() *Engine
```

Creates a new empty SPOCP engine.

**Example:**
```go
engine := spocp.NewEngine()
```

#### func (*Engine) AddRule

```go
func (e *Engine) AddRule(rule string) error
```

Adds a policy rule to the engine using canonical S-expression format.

**Parameters:**
- `rule` - Canonical form S-expression (e.g., `"(5:admin)"`)

**Returns:**
- `error` - Parse error if the rule is invalid

**Example:**
```go
err := engine.AddRule("(4:http(4:page10:index.html))")
```

#### func (*Engine) AddRuleElement

```go
func (e *Engine) AddRuleElement(rule sexp.Element)
```

Adds a pre-parsed rule element to the engine.

**Parameters:**
- `rule` - A parsed S-expression element

**Example:**
```go
rule := sexp.NewList("http", sexp.NewAtom("GET"))
engine.AddRuleElement(rule)
```

#### func (*Engine) Query

```go
func (e *Engine) Query(query string) (bool, error)
```

Checks if a query (in canonical form) is authorized by any rule.

**Parameters:**
- `query` - Canonical form S-expression

**Returns:**
- `bool` - True if authorized
- `error` - Parse error if the query is invalid

**Example:**
```go
authorized, err := engine.Query("(4:http3:GET)")
```

#### func (*Engine) QueryElement

```go
func (e *Engine) QueryElement(query sexp.Element) bool
```

Checks if a pre-parsed query element is authorized.

**Parameters:**
- `query` - A parsed S-expression element

**Returns:**
- `bool` - True if query <= some rule in the engine

**Example:**
```go
query := sexp.NewList("http", sexp.NewAtom("GET"))
if engine.QueryElement(query) {
    fmt.Println("Authorized")
}
```

#### func (*Engine) FindMatchingRules

```go
func (e *Engine) FindMatchingRules(query string) ([]sexp.Element, error)
```

Returns all rules that authorize the given query.

**Parameters:**
- `query` - Canonical form S-expression

**Returns:**
- `[]sexp.Element` - All matching rules
- `error` - Parse error if the query is invalid

#### func (*Engine) RuleCount

```go
func (e *Engine) RuleCount() int
```

Returns the number of rules in the engine.

#### func (*Engine) Clear

```go
func (e *Engine) Clear()
```

Removes all rules from the engine.

## Package: sexp

S-expression parsing and representation.

### type Element

```go
type Element interface {
    String() string
    IsAtom() bool
    IsList() bool
    IsStarForm() bool
}
```

Base interface for all S-expression elements.

### type Atom

```go
type Atom struct {
    Value string
}
```

Represents an octet string (atom) in an S-expression.

#### func NewAtom

```go
func NewAtom(value string) *Atom
```

Creates a new atom with the given value.

**Example:**
```go
atom := sexp.NewAtom("hello")
fmt.Println(atom.String()) // "5:hello"
```

### type List

```go
type List struct {
    Tag      string
    Elements []Element
}
```

Represents an S-expression list with a tag and elements.

#### func NewList

```go
func NewList(tag string, elements ...Element) *List
```

Creates a new list with the given tag and elements.

**Example:**
```go
list := sexp.NewList("http",
    sexp.NewAtom("GET"),
    sexp.NewList("page", sexp.NewAtom("index.html")),
)
```

### type Parser

```go
type Parser struct {
    // contains filtered or unexported fields
}
```

Parser for canonical S-expressions.

#### func NewParser

```go
func NewParser(input string) *Parser
```

Creates a new parser for the given canonical form input.

#### func (*Parser) Parse

```go
func (p *Parser) Parse() (Element, error)
```

Parses the input and returns an Element.

**Example:**
```go
parser := sexp.NewParser("(5:hello5:world)")
elem, err := parser.Parse()
```

### func AdvancedForm

```go
func AdvancedForm(elem Element) string
```

Converts a canonical S-expression to human-readable advanced form.

**Example:**
```go
elem := sexp.NewList("http", sexp.NewAtom("GET"))
fmt.Println(sexp.AdvancedForm(elem)) // "(http GET)"
```

## Package: starform

Star form implementations for pattern matching.

### type StarForm

```go
type StarForm interface {
    sexp.Element
    Match(value sexp.Element) bool
    Type() string
}
```

Base interface for all star forms.

### type Wildcard

```go
type Wildcard struct{}
```

Matches any single element. Represents `(*)`.

**Example:**
```go
wildcard := &starform.Wildcard{}
// Matches anything
```

### type Set

```go
type Set struct {
    Elements []sexp.Element
}
```

Matches any element in the set. Represents `(* set ...)`.

**Example:**
```go
set := &starform.Set{
    Elements: []sexp.Element{
        sexp.NewAtom("read"),
        sexp.NewAtom("write"),
        sexp.NewAtom("execute"),
    },
}
```

### type Range

```go
type Range struct {
    RangeType  RangeType
    LowerBound *RangeBound
    UpperBound *RangeBound
}
```

Matches values within a range. Represents `(* range ...)`.

**Example:**
```go
// Match numbers 10-20
numRange := &starform.Range{
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

#### RangeType Constants

```go
const (
    RangeAlpha   RangeType = "alpha"
    RangeNumeric RangeType = "numeric"
    RangeDate    RangeType = "date"
    RangeTime    RangeType = "time"
    RangeIPv4    RangeType = "ipv4"
    RangeIPv6    RangeType = "ipv6"
)
```

#### RangeOp Constants

```go
const (
    OpLT RangeOp = "lt" // less than
    OpLE RangeOp = "le" // less than or equal
    OpGT RangeOp = "gt" // greater than
    OpGE RangeOp = "ge" // greater than or equal
)
```

### type Prefix

```go
type Prefix struct {
    Value string
}
```

Matches strings with the given prefix. Represents `(* prefix ...)`.

**Example:**
```go
prefix := &starform.Prefix{Value: "/etc/"}
// Matches "/etc/passwd", "/etc/hosts", etc.
```

### type Suffix

```go
type Suffix struct {
    Value string
}
```

Matches strings with the given suffix. Represents `(* suffix ...)`.

**Example:**
```go
suffix := &starform.Suffix{Value: ".pdf"}
// Matches "document.pdf", "report.pdf", etc.
```

## Package: compare

Comparison algorithm for S-expressions.

### func LessPermissive

```go
func LessPermissive(s, t sexp.Element) bool
```

Returns true if S is less permissive than T (S <= T).

This implements the partial order relation defined in the SPOCP specification where S <= T means "rule S grants fewer permissions than rule T".

**Parameters:**
- `s` - The subject S-expression
- `t` - The target S-expression

**Returns:**
- `bool` - True if s <= t

**Example:**
```go
s := sexp.NewList("fruit", sexp.NewAtom("apple"), sexp.NewAtom("red"))
t := sexp.NewList("fruit", sexp.NewAtom("apple"))

if compare.LessPermissive(s, t) {
    fmt.Println("s is less permissive than t")
}
```

**Comparison Rules:**

1. `T = (*)` → always true (wildcard matches anything)
2. Both atoms and equal → true
3. S is atom, T is star form matching S → true
4. Both ranges and T contains S → true
5. Both prefixes and T's prefix contains S → true
6. Both suffixes and T's suffix contains S → true
7. Both lists, `len(T) <= len(S)` and `S[i] <= T[i]` for all i → true
8. S is set and all elements `<= T` → true
9. T is set and S `<=` some element → true

### func Normalize

```go
func Normalize(elem sexp.Element) sexp.Element
```

Normalizes an S-expression by joining ranges and atoms in sets.

## Common Patterns

### HTTP Authorization

```go
// Allow any user to GET a specific page
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
authorized := engine.QueryElement(query) // true
```

### File System Paths

```go
// Allow access to files under /etc/
rule := sexp.NewList("file", &starform.Prefix{Value: "/etc/"})
engine.AddRuleElement(rule)

query := sexp.NewList("file", sexp.NewAtom("/etc/passwd"))
authorized := engine.QueryElement(query) // true
```

### Time-Based Access

```go
// Work hours: 08:00 - 17:00
rule := sexp.NewList("access", &starform.Range{
    RangeType: starform.RangeTime,
    LowerBound: &starform.RangeBound{Op: starform.OpGE, Value: "08:00:00"},
    UpperBound: &starform.RangeBound{Op: starform.OpLE, Value: "17:00:00"},
})
engine.AddRuleElement(rule)
```

### Role-Based Access

```go
// Admin can do anything
adminRule := sexp.NewList("permission",
    sexp.NewList("role", sexp.NewAtom("admin")),
    sexp.NewList("action", &starform.Wildcard{}),
)

// User can read or write
userRule := sexp.NewList("permission",
    sexp.NewList("role", sexp.NewAtom("user")),
    sexp.NewList("action", &starform.Set{
        Elements: []sexp.Element{
            sexp.NewAtom("read"),
            sexp.NewAtom("write"),
        },
    }),
)
```

## Error Handling

All parsing operations return errors that should be checked:

```go
parser := sexp.NewParser(input)
elem, err := parser.Parse()
if err != nil {
    log.Fatalf("Parse error: %v", err)
}

authorized, err := engine.Query(queryStr)
if err != nil {
    log.Fatalf("Query error: %v", err)
}
```

## Performance Considerations

- **Rule Order**: The engine checks rules in the order they were added
- **Early Exit**: Query evaluation stops at the first matching rule
- **Normalization**: Not yet fully implemented for set optimization
- **Caching**: No built-in caching (consider adding if needed)

## Thread Safety

The current implementation is **not thread-safe**. If you need concurrent access, wrap the engine with appropriate synchronization:

```go
type SafeEngine struct {
    mu     sync.RWMutex
    engine *spocp.Engine
}

func (s *SafeEngine) Query(query string) (bool, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    return s.engine.Query(query)
}
```
