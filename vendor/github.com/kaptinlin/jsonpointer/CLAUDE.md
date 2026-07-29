# JSON Pointer

A read-only JSON Pointer (RFC 6901) library for Go with strict parsing,
immutable `Pointer` values, explicit errors, and JSON-shaped Go traversal.

For installation, usage examples, and API-oriented guidance, see
[README.md](README.md).

## Commands

```bash
task test          # Run package tests with the race detector
task lint          # Run golangci-lint and go.mod/go.sum tidy checks
task specs-check   # Validate spec and design doc placement
task yamllint      # Lint YAML files
task bench         # Run benchmark suites
```

## Architecture

```text
jsonpointer/
├── jsonpointer.go      # Public Parse, one-shot traversal, and token helpers
├── types.go            # Pointer, Reference, and their methods
├── get.go              # Shared value/reference resolver
├── util.go             # Strict decode, format, traversal, and token helpers
├── errors.go           # Exported sentinels and structured Error
├── example_test.go     # Executable examples kept in sync by go test
├── examples/           # Runnable demo program
├── benchmarks/         # Pointer-centered benchmark module
└── SPECS/              # Canonical package contracts and coding standards
```

## Agent Workflow

### Design Phase - Read SPECS First

Before changing code or docs, read the relevant `SPECS/` documents first.
`README.md` is user-facing; `SPECS/` defines the package contract.

Workflow:

1. Identify the relevant spec files from the index below.
2. Verify the current code matches the spec before updating docs.
3. If code and spec intentionally changed, update the spec and code together
   instead of documenting stale behavior.
4. Keep `AGENTS.md` as a symlink to `CLAUDE.md`.

## SPECS Index

Specification documents in [`SPECS/`](SPECS/) define package contracts,
traversal semantics, and coding standards:

| Spec | Topic |
| --- | --- |
| [`SPECS/00-overview.md`](SPECS/00-overview.md) | Package scope, priorities, and compatibility boundaries |
| [`SPECS/10-domain-specs.md`](SPECS/10-domain-specs.md) | Pointer, token, traversal, and error semantics |
| [`SPECS/20-api-specs.md`](SPECS/20-api-specs.md) | Public functions, exported types, errors, and token helpers |
| [`SPECS/40-architecture-specs.md`](SPECS/40-architecture-specs.md) | Package layout, traversal pipeline, and performance strategy |
| [`SPECS/50-coding-standards.md`](SPECS/50-coding-standards.md) | Contribution, documentation, and validation rules |

## Design Philosophy

- **KISS**: keep one small package with one job: read JSON Pointer values and
  expose pointer helpers.
- **YAGNI**: stop at strict parsing, traversal, reference context, errors, and
  token utilities.
- **SRP**: keep public API entry points, shared traversal, strict token decoding,
  and token utilities separated by concern.
- **Simplicity as art**: the common path is `Parse`, then `Pointer.Value` or
  `Pointer.Reference`.
- **Errors as teachers**: preserve sentinel classes and add pointer, token, and
  depth context through `*Error` when traversal fails.
- **Never**: accidental complexity, feature gravity, abstraction theater,
  configurability cope.

## API Design Principles

- **Progressive Disclosure**: use `Parse` for pointer strings, `FromTokens` for
  raw token data, `Pointer.Value` for values, and `Pointer.Reference` when parent
  context matters.
- **Strict at the boundary**: malformed pointer strings fail before traversal.
- **Raw tokens stay raw**: token text such as `"~2"` is valid through
  `FromTokens` even though it is invalid pointer-string syntax.
- **Reference context is JSON-shaped**: `Reference.Parent()` returns the
  dereferenced container that consumed the final token, not pointer or interface
  wrappers.
- **Array errors stay small**: invalid array token syntax returns
  `ErrInvalidIndex`; `-` and canonical indexes outside the collection return
  `ErrIndexOutOfBounds`, regardless of token length or machine word size.

## Coding Rules

### Must Follow

- Use the Go version declared in `go.mod`; use modern standard library helpers
  where they simplify code.
- Follow [Google Go Best Practices](https://google.github.io/go-style/best-practices).
- Follow [Google Go Style Decisions](https://google.github.io/go-style/decisions).
- KISS/DRY/YAGNI: keep the package small, direct, and free of speculative APIs.
- Keep traversal behavior aligned with RFC 6901 unless `SPECS/` explicitly
  documents a Go-specific extension.
- Keep read APIs panic-free and explicit.
- Keep common `map[string]any` and `[]any` traversal on the fast path;
  reflection stays a fallback for typed container mechanics only.
- Keep pointer-string validation at `Parse` and one-shot helper boundaries.
- Keep one strict token decoder shared by `Parse` and `UnescapeToken`; do not
  reintroduce a parallel pointer-string escape validator.
- Keep pointer and interface normalization terminating; wrapper cycles return
  `ErrNotTraversable` when traversal must consume a token.
- Update `README.md`, `example_test.go`, and relevant `SPECS/` files together
  when public behavior changes.
- Keep `AGENTS.md` as a symlink to `CLAUDE.md`; do not duplicate the file.

### Forbidden

- No `panic` in production code: return errors instead.
- No premature abstraction: three similar lines are better than a helper used
  once.
- No feature creep: only implement what JSON Pointer reads and helper utilities
  require.
- No mutation APIs, patch helpers, JSONPath helpers, or compiled-pointer caches
  unless `SPECS/` expands the package scope.
- No permissive parse helpers that silently accept malformed pointer strings.
- No documentation masquerading as code: keep contract prose in `SPECS/`, not in
  dead flags or lookup tables.
- No working around dependency bugs: if a dependency blocks work, write
  `reports/<dependency-name>.md` instead of reimplementing it inline.

## Testing

- Use Go's `testing` package with `testify/assert` and `testify/require` in
  package tests.
- Keep coverage for strict parsing, raw-token construction, pointer immutability,
  map and slice traversal, typed maps, typed slices and arrays, pointer
  dereference, escaped tokens, read-honest array indexes, and structured errors.
- Keep executable examples in `example_test.go` aligned with `README.md` and the
  runnable demo in `examples/`.
- Run `task test` and `task lint` for code changes.
- Run `task specs-check` for markdown/spec changes.
- Run `task yamllint` for YAML changes.

## Dependencies

- `github.com/stretchr/testify`: test assertions and requirements only.

## Performance

- Optimize common `map[string]any` and `[]any` traversal paths before reflective
  fallbacks.
- Benchmark changes to `get.go`, pointer construction, or token utility hot
  paths.
- Run `task bench` after touching traversal performance-sensitive code.

## Dependency Issue Reporting

When you encounter a bug, limitation, or unexpected behavior in a dependency
library:

1. Do not work around it by reimplementing the dependency's functionality.
2. Do not skip the dependency and write a local replacement.
3. Create a report file in `reports/<dependency-name>.md`.
4. Include the dependency version, trigger scenario, expected behavior, actual
   behavior, relevant errors, and any non-code workaround suggestion.
5. Continue with tasks that do not depend on the broken behavior.

## Agent Skills

Shared workflow skills are available from `.agents/skills/` and
`.claude/skills/` in this checkout.
