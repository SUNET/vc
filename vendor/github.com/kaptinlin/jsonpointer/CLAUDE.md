# JSON Pointer

A read-only JSON Pointer (RFC 6901) library for Go with explicit errors, Go-native traversal, and behavior anchored to the TypeScript `jsonjoy-com/json-pointer` implementation.

For installation, usage examples, and API-oriented guidance, see [README.md](README.md).

## Commands

```bash
task test          # Run package tests with the race detector
task lint          # Run golangci-lint and go.mod/go.sum tidy checks
task yamllint      # Lint YAML files
task bench         # Run benchmark suites
```

## Architecture

```text
jsonpointer/
├── jsonpointer.go      # Public API entry points
├── get.go              # Value traversal optimized for common JSON-shaped data
├── find.go             # Reference traversal with parent tracking
├── find_pointer.go     # Direct pointer-string traversal
├── util.go             # Parse, format, escape, and path helpers
├── validate.go         # Pointer and path validation limits
├── struct.go           # Cached struct-field lookup
├── errors.go           # Exported sentinel errors
├── types.go            # Exported path/reference types and predicates
├── example_test.go     # Executable examples kept in sync by go test
├── examples/           # Runnable demo program
├── benchmarks/         # Performance comparisons and microbenchmarks
└── SPECS/              # Canonical package contracts and coding standards
```

## Agent Workflow

### Design Phase — Read SPECS First

Before changing code or docs, read the relevant `SPECS/` documents first. `README.md` is user-facing; `SPECS/` defines the package contract.

Workflow:

1. Identify the relevant spec files from the index below.
2. Verify the current code matches the spec before updating docs.
3. If code and spec intentionally changed, update the spec and code together instead of documenting stale behavior.
4. Keep `AGENTS.md` as a symlink to `CLAUDE.md`.

## SPECS Index

Specification documents in [`SPECS/`](SPECS/) — package contracts, traversal semantics, and coding standards:

| Spec | Topic |
| --- | --- |
| [`SPECS/00-overview.md`](SPECS/00-overview.md) | Package scope, priorities, and compatibility boundaries |
| [`SPECS/10-domain-specs.md`](SPECS/10-domain-specs.md) | Pointer, path, traversal, and error semantics |
| [`SPECS/20-api-specs.md`](SPECS/20-api-specs.md) | Public functions, exported types, errors, and validation limits |
| [`SPECS/40-architecture-specs.md`](SPECS/40-architecture-specs.md) | Package layout, traversal pipeline, and performance strategy |
| [`SPECS/50-coding-standards.md`](SPECS/50-coding-standards.md) | Contribution, documentation, and validation rules |

## Design Philosophy

- **KISS** — Keep one small package with one job: read JSON Pointer values and expose pointer helpers.
- **YAGNI** — Stop at traversal, validation, and path utilities. Do not grow this package into JSON Patch, mutation, or schema tooling.
- **SRP** — Keep public API entry points, traversal engines, validation helpers, and struct metadata lookup separated by file and concern.
- **Simplicity as art** — The common path is `Get`, `Find`, `GetByPointer`, and `FindByPointer`; everything else supports those reads without adding ceremony.
- **Errors as teachers** — Preserve distinct sentinel errors for missing keys, missing fields, invalid indexes, nil pointers, and generic traversal failure.
- **Never:** accidental complexity, feature gravity, abstraction theater, configurability cope.

## API Design Principles

- **Progressive Disclosure**: Use `Get` and `Find` for tokenized paths, use `GetByPointer` and `FindByPointer` for pointer strings, and reach for `Parse`, `Format`, `Escape`, and `Unescape` only when you need direct control.

## Coding Rules

### Must Follow

- Use the Go version declared in `go.mod`; use modern standard library helpers where they simplify code.
- Follow [Google Go Best Practices](https://google.github.io/go-style/best-practices)
- Follow [Google Go Style Decisions](https://google.github.io/go-style/decisions)
- KISS/DRY/YAGNI — keep the package small, direct, and free of speculative APIs.
- Keep traversal behavior aligned with the TypeScript reference implementation and RFC 6901 unless `SPECS/` explicitly documents a Go-specific extension.
- Keep read APIs panic-free and explicit: return sentinel errors instead of fallback values or `Must*` wrappers.
- Keep common `map[string]any` and `[]any` traversal on the zero-allocation fast path; reflection stays a fallback for typed Go values.
- Keep `Validate` and `ValidatePath` explicit; do not fold pointer validation into hot traversal paths.
- Update `README.md`, `example_test.go`, and relevant `SPECS/` files together when public behavior changes.
- Keep `AGENTS.md` as a symlink to `CLAUDE.md`; do not duplicate the file.

### Forbidden

- No `panic` in production code — return errors instead.
- No premature abstraction — three similar lines are better than a helper used once.
- No feature creep — only implement what JSON Pointer reads and helper utilities require.
- No mutation APIs, patch helpers, or compiled-pointer layers unless `SPECS/` expands the package scope.
- No documentation masquerading as code — keep contract prose in `SPECS/`, not in dead flags or lookup tables.
- No working around dependency bugs — if a dependency blocks work, write `reports/<dependency-name>.md` instead of reimplementing it inline.

## Testing

- Use Go's `testing` package with `testify/assert` and `testify/require` in package tests.
- Keep coverage for map and slice traversal, typed slices and arrays, struct tag lookup, pointer dereference, escaped pointer handling, and validation limits.
- Keep executable examples in `example_test.go` aligned with `README.md` and the runnable demo in `examples/`.
- Run `task test` and `task lint` for code changes.
- Run `task yamllint` for YAML changes.

## Dependencies

- `github.com/stretchr/testify` — test assertions and requirements only.

## Performance

- Optimize common `map[string]any` and `[]any` traversal paths before reflective fallbacks.
- Benchmark changes to `get.go`, `find.go`, `find_pointer.go`, `struct.go`, or pointer utility hot paths.
- Run `task bench` after touching traversal performance-sensitive code.

## Dependency Issue Reporting

When you encounter a bug, limitation, or unexpected behavior in a dependency library:

1. Do not work around it by reimplementing the dependency's functionality.
2. Do not skip the dependency and write a local replacement.
3. Create a report file in `reports/<dependency-name>.md`.
4. Include the dependency version, trigger scenario, expected behavior, actual behavior, relevant errors, and any non-code workaround suggestion.
5. Continue with tasks that do not depend on the broken behavior.

## Agent Skills

Shared workflow skills are available from `.agents/skills/` and `.claude/skills/` in this checkout.
