# Makefile Documentation

## Quick Reference

### Most Common Commands

```bash
# Show all available targets
make help

# Build
make build                    # Build all services
make build-SERVICE            # Build specific service (e.g., build-apigw)
make build-verifier-zknative  # Build verifier with native ZK/PPID verification
make build-zkvegaverifyworker # Build the isolated Vega ZK-verify subprocess worker

# Test
make test                    # Run all tests
make test-SERVICE            # Test specific service
make test-bbsnative          # Test with bbsnative build tag (requires bbs-native-lib)
make test-pkcs11             # Test with pkcs11 build tag (requires test-env)
make test-zknative           # Test with zknative build tag (requires zk-native-lib zk-native-lib-vega)

# Docker
make docker-build                          # Build all images (VERSION=local)
make docker-build VERSION=myfeature       # Build with custom version
make docker-build-SERVICE VERSION=myfeature # Build specific service
make docker-push VERSION=myfeature         # Push all images
make docker-tag VERSION=myfeature NEWTAG=staging # Retag images

# Docker Compose
make start       # Start services
make stop        # Stop services
make restart     # Restart services

# Code Quality
make gosec        # Security scan
make staticcheck  # Linter
make vulncheck    # Vulnerability check

# Code Generation
make proto        # Generate protobuf code
make swagger      # Generate API documentation

# W3C VC 2.0 Testing
make create-w3c-test-suite   # Setup test suite
make run-w3c-test            # Run tests
make w3c-test                # Run tests (managed)

# Development
make pki          # Setup PKI infrastructure
make vscode       # Setup VS Code environment
make install-tools # Install required tools
```

## Environment Variables

```bash
VERSION=local        # Docker image version (default: local)
NEWTAG=staging       # Target tag for docker-tag operations (default: VERSION)
W3C_TEST_PORT=8888   # W3C test server port (default: 8888)
```

> **Note:** Reserved tags (`vX.Y.Z`, `latest`, `testing`, `demo`, `dev`) cannot be
> used with `VERSION` or `NEWTAG` directly. They are exclusively managed by
> `make release`, `make release-prod`, and `make release-demo`.
> See [Reserved Tag Guard](#reserved-tag-guard) for details.

## Architecture

### Services

The build system manages 4 microservices:
- **verifier** - Credential verification service (web worker)
- **registry** - Central registry service (worker)
- **apigw** - API gateway (worker)
- **issuer** - Credential issuing service (worker; links `zk-cred-bbs` for blind BBS issuance, PKCS#11 for HSM signing)

### Build Configuration

Every service is compiled with cgo enabled (`CGO_ENABLED=1`) and the
`netgo,osusergo` build tags, then statically linked via `--extldflags
'-static'`. The verifier additionally links `zk-cred-longfellow` (via the
`zknative` build tag) and is dynamically linked because Longfellow's C++
pulls in libm/libstdc++. The Docker builder stage in `dockerfiles/worker`
fetches and builds every native library it needs from source — no
host-side staging is required for `docker build`.

| Service    | Extra native libs linked into the main binary | Extra binaries shipped alongside | Docker stage       |
| ---------- | --------------------------------------------- | -------------------------------- | ------------------ |
| `verifier` | `zk-cred-bbs`, `zk-cred-longfellow`           | `zkvegaverifyworker`             | `runtime-verifier` |
| `issuer`   | `zk-cred-bbs`                                 | —                                | `runtime`          |
| `apigw`    | `zk-cred-bbs`                                 | —                                | `runtime`          |
| `registry` | `zk-cred-bbs`                                 | —                                | `runtime`          |

Every worker links `zk-cred-bbs` because `pkg/openid4vci` imports
`pkg/bbs` transitively. That import is what forces cgo on for every
worker; nothing else in the standard build actually calls into BBS.

### Template System

The Makefile uses templates to generate targets dynamically:

- **TEST_TEMPLATE** - Generates `test-SERVICE` targets (with `bbs-native-lib-staged` prereq)
- **BUILD_TEMPLATE** - Generates `build-SERVICE` targets (with `bbs-native-lib-staged` prereq)
- **DOCKER_BUILD_WORKER_TEMPLATE** - Generates `docker-build-SERVICE` targets
- **DOCKER_PUSH_TEMPLATE** - Generates `docker-push-SERVICE` targets
- **DOCKER_TAG_TEMPLATE** - Generates `docker-tag-SERVICE` targets

## How to Add a New Service

Adding a new service requires only 2 edits:

1. **Add to SERVICES list** (Configuration Variables block):
```makefile
SERVICES        := verifier registry apigw issuer newservice
WORKER_SERVICES := verifier registry apigw issuer newservice
```

The templates will automatically generate all targets:
- `test-newservice`
- `build-newservice`
- `docker-build-newservice`
- `docker-push-newservice`
- `docker-tag-newservice`

## Helper Functions

### docker-tag
Generates consistent Docker image tags:
```makefile
$(call docker-tag,verifier,1.2.3)  # Returns docker.sunet.se/iam_vc/verifier:1.2.3
```

## Native library staging

The build never picks up a native library from GOPATH or the system
package manager: each of `zk-cred-bbs`, `zk-cred-longfellow`, and
`zk-cred-vega` is fetched from source (`ZK_CRED_*_REPO` / `ZK_CRED_*_REF`
in the Makefile) and built into `third_party/`.

- **bbsnative** (`pkg/bbs` + `pkg/bbs/bbsnative`) — Blind BBS issuance.
  Staged by `make bbs-native-lib`, and is a prereq for every `make
  build-SERVICE` and every `make test-SERVICE` because `pkg/openid4vci`
  imports `pkg/bbs`. Runtime activation is configured in the
  `issuer.bbs` block; the code path only fires on the issuer.
- **pkcs11** (`pkg/pki`, `pkg/jose`) — HSM signing via `miekg/pkcs11`
  (vendored, cgo). No separate staging step: the C headers ship with
  the package. `make test-pkcs11` runs the SoftHSM2-backed tests
  (requires `softhsm2-util` and `pkcs11-tool` locally, installed by
  `make test-env`).
- **zknative** (`pkg/mdoc/zknative`, `pkg/mdoc/zknative_vega`, and
  `cmd/zkvegaverifyworker`) — Native ZK/PPID verification. Longfellow
  is linked into the main verifier binary via `make
  build-verifier-zknative` (prereq: `make zk-native-lib`); Vega is
  compiled into a separate subprocess binary via `make
  build-zkvegaverifyworker` (prereq: `make zk-native-lib-vega`). The
  Docker `runtime-verifier` stage in `dockerfiles/worker` builds both
  libraries inside the builder — no host staging is needed.

### Usage Examples

```bash
# Default build: every worker links pkg/bbs's cgo backend.
make build-issuer
make build-verifier

# Verifier with native ZK/PPID (Longfellow linked into the binary).
make zk-native-lib
make build-verifier-zknative

# Vega subprocess worker (execed by the zknative verifier at runtime).
make zk-native-lib-vega
make build-zkvegaverifyworker

# Run the tagged tests directly.
make test-bbsnative
make test-pkcs11
make test-zknative
```

## Docker Workflows

### Standard Build and Push
```bash
# Build all services (default VERSION=local)
make docker-build

# Build with a custom tag
make docker-build VERSION=myfeature

# Push to registry
make docker-push VERSION=myfeature
```

### Retagging Images
```bash
# Build with a custom tag
make docker-build VERSION=myfeature

# Retag to another custom tag
make docker-tag VERSION=myfeature NEWTAG=staging

# Push the new tag
make docker-push VERSION=staging
```

> **Note:** Retagging to reserved tags (`latest`, `demo`, etc.) is only allowed
> through the release targets. See [Reserved Tag Guard](#reserved-tag-guard).

### Building Specific Services
```bash
# Build only the API gateway.
make docker-build-apigw VERSION=myfeature

# Build only the verifier (gets the runtime-verifier stage automatically,
# including the two native ZK shared objects and zkvegaverifyworker).
make docker-build-verifier VERSION=myfeature
```

## Reserved Tag Guard

The following Docker image tags are **reserved** and cannot be set directly via
`VERSION` or `NEWTAG`:

| Tag | Purpose | Managed by |
|---|---|---|
| `vX.Y.Z` (semver) | Versioned releases | `make release` |
| `latest` | Current production | `make release-prod` |
| `testing` | Testing environment | (reserved) |
| `demo` | Demo environment | `make release-demo` |
| `dev` | Latest development build | `make release` |

Attempting to use a reserved tag directly will produce an error:

```bash
$ make VERSION=dev docker-build
Error: 'dev' is a reserved tag. Use 'make release', 'make release-prod', or 'make release-demo' instead.
```

For local development, use any non-reserved tag (the default `local` works well):

```bash
make docker-build                   # uses VERSION=local (default)
make docker-build VERSION=myfeature  # any non-reserved string
```

## Release Process

Three targets manage the release lifecycle. Only these targets are allowed to
produce reserved Docker tags.

### `make release` — Create a new versioned release

Bumps the latest `vX.Y.Z` git tag and builds/pushes Docker images.

```bash
make release                        # patch bump (default)
make release BUMP=minor             # minor bump
make release BUMP=major             # major bump
make release FORCE=true             # release from any branch
make release BUMP=minor FORCE=true  # combine options
```

This performs:
1. Verifies you're on the `main` branch (unless `FORCE=true`)
2. Verifies the working tree is clean (unless `FORCE=true`)
3. Bumps the latest `vX.Y.Z` tag according to `BUMP`
4. Builds all Docker images tagged `:vX.Y.Z` (fail-fast: no git tag is
   created if the build fails)
5. Creates and pushes the new git tag
6. Pushes images tagged `:vX.Y.Z`
7. Retags and pushes all images as `:dev`

### `make release-prod` — Promote to production

Pulls existing `:vX.Y.Z` images and retags them as `:latest`. No rebuild.

```bash
make release-prod                   # promotes latest vX.Y.Z tag
make release-prod TAG=v1.2.3        # promotes a specific version
```

### `make release-demo` — Promote to demo

Pulls existing `:vX.Y.Z` images and retags them as `:demo`. No rebuild.

```bash
make release-demo                   # promotes latest vX.Y.Z tag
make release-demo TAG=v1.2.3        # promotes a specific version
```

## Development Setup

### Initial Setup
```bash
# Setup VS Code environment (includes test-env)
make vscode

# Or just test environment
make test-env

# Setup PKI infrastructure
make pki
```

### Code Generation
```bash
# Generate all code
make proto swagger

# Generate specific components
make proto-registry
make proto-issuer
make swagger-apigw
```

## Troubleshooting

### Check Available Targets
```bash
make help
```

### Verify Make Version
GNU Make 4.0+ required for advanced features:
```bash
make --version
```

### Check Service Configuration
```bash
# View service lists
grep "^SERVICES" Makefile
grep "^WORKER_SERVICES" Makefile

# Check what targets exist for a service
make -n build-apigw
make -n docker-build-apigw
```

### Debug Template Generation
```bash
# Show what would be executed (dry run)
make -n build-verifier
make -n docker-push-registry VERSION=myfeature
```

## Maintenance Notes

### Make Primitives Used
The Makefile uses only Make built-in primitives (no bash dependencies):
- `$(info ...)` - Print messages
- `$(error ...)` - Error messages
- `$(shell ...)` - Command substitution
- `$(file >path,content)` - Write files
- `$(foreach ...)` - Loops
- `$(eval ...)` - Evaluate code
- `$(call ...)` - Call functions
- `$(filter ...)` - Filter lists

### No Shell Dependencies
All operations use Make's own features rather than bash-specific constructs:
- ✅ `$(info message)` instead of `@echo`
- ✅ `$$(command)` instead of backticks
- ✅ `$(file >path,content)` instead of `echo > file`
- ✅ `-@command` prefix instead of `|| true`

This ensures the Makefile works across different shells and platforms.
