# Copilot instructions for the `vc` repository

These instructions are auto-loaded by GitHub Copilot for every request in this
workspace. Keep them short, concrete, and repo-specific.

## Communication style

- Be brief. Target 1–3 sentences for simple answers; expand only for complex
  work or when explicitly asked.
- Skip filler ("Here's the answer", "I will now…"). After completing file
  operations, confirm briefly rather than re-narrating.
- Do NOT create markdown files to document changes unless the user asks.
- Use file links, not inline code, when referring to files: `[path](path)` or
  `[file.go](file.go#L10)`.

## Implementation discipline

- Only make changes that are directly requested or clearly necessary.
- Do not add features, refactor code, or make cosmetic "improvements" beyond
  what was asked.
- Do not add docstrings, comments, or type annotations to code you did not
  change. Write comments only to state what the code cannot show on its own;
  keep them to one short line.
- Do not add error handling for scenarios that cannot happen. Validate at
  system boundaries only.
- Do not create helpers or abstractions for one-time operations.

## Workflow: build & test after changes

After any non-trivial change, run:

```bash
go build ./...
go test ./<package>/...
```

Focus tests on the packages you touched. Only run the full test suite when
asked or when the change is cross-cutting.

## Repo-specific patterns

### Readiness / health

- Every microservice (apigw, issuer, registry, verifier) exposes health via a
  shared aggregator: `pkg/status.Aggregator`.
- Components implement the Prober contract:
  `HealthProbe(ctx context.Context) error` — `nil` = healthy, non-nil error is
  surfaced verbatim.
- Each service's `apiv1.Client` holds a `statusAggregator *status.Aggregator`
  built in a helper called `buildStatusAggregator()` and consumed by the
  service's `Health` / `Status` handler.
- Probe names in the returned reply are automatically prefixed with the
  service name (e.g. `apigw.db`, `registry.tokenstatuslist`). Downstream
  probes forwarded through an aggregator keep their original prefix — do not
  double-prefix.
- The aggregator caches the merged `StatusReply` (default 10s TTL) and
  single-flights concurrent callers; do not add extra caching around it.
- Global signer material is checked once per service. Do not add duplicate
  signer probes.

### Protocol buffers

- Proto sources live in `proto/`. Regenerate with `make proto` after edits.
- The `go_package` option must use the full module path
  `github.com/SUNET/vc/internal/gen/...`, and the Makefile passes
  `module=github.com/SUNET/vc` to `protoc-gen-go`. Do not revert this to
  `module=vc` — it breaks cross-package imports in generated code.
- gRPC service protos import the shared status types via
  `import "v1-status-model.proto";` (path relative to `proto/`).

### gRPC servers

- Each service's `grpcserver.Service` registers business RPCs directly. Do
  NOT register `grpc.health.v1.Health` — health is served through the
  service's own `Status` RPC (apigw calls that, and aggregates).
- gRPC endpoint handlers in `internal/<svc>/grpcserver/endpoints.go` are thin
  shims that delegate to the corresponding `apiv1.Client` method.

### Build-time variables

- Populated via `-ldflags "-X github.com/SUNET/vc/pkg/status.<Name>=<value>"`.
  The canonical list is in `dockerfiles/worker`. Any new build variable
  belongs in `pkg/status` too.

## Go idioms

- Prefer standard-library and idiomatic Go patterns over custom abstractions.
- `Status(ctx) error` is a general Go readiness pattern, but in this repo it
  collides with unrelated `Status` names — use `HealthProbe(ctx) error` for
  the readiness contract.
- Use structural interface satisfaction: register probers directly (e.g.
  `Register("db", c.db)`) rather than wrapping in `RegisterFunc` closures
  when the component already implements `HealthProbe`.

## Operational safety

- Local, reversible actions (editing files, running tests, `go build`) are
  fine to run without asking.
- Ask before: deleting files/branches, `rm -rf`, `git push --force`,
  `git reset --hard`, amending published commits, deploying via
  `make fly-deploy-*`, editing shared infrastructure, or bypassing safety
  checks (`--no-verify`).
