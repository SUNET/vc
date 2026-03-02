# Makefile Documentation

## Quick Reference

### Most Common Commands

```bash
# Show all available targets
make help

# Build
make build                    # Build all services
make build-SERVICE            # Build specific service (e.g., build-apigw)
make build-apigw-saml        # Build apigw with SAML support
make build-apigw-oidcrp      # Build apigw with OIDC RP support
make build-apigw-all         # Build apigw with all features
make build-issuer-hsm        # Build issuer with HSM/PKCS#11 support

# Test
make test                    # Run all tests
make test-SERVICE            # Test specific service
make test-saml              # Test with SAML build tag
make test-oidcrp            # Test with OIDC RP build tag
make test-all-tags          # Test with all build tags

# Docker
make docker-build                          # Build all images
make docker-build VERSION=1.2.3           # Build with version
make docker-build-SERVICE VERSION=1.2.3   # Build specific service
make docker-push VERSION=1.2.3            # Push all images
make docker-tag VERSION=1.2.3 NEWTAG=prod # Retag images

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
VERSION=1.2.3        # Docker image version (default: latest)
NEWTAG=prod          # Target tag for docker-tag operations (default: VERSION)
W3C_TEST_PORT=8888   # W3C test server port (default: 8888)
```

## Architecture

### Services

The build system manages 6 microservices:
- **verifier** - Credential verification service (web worker)
- **registry** - Central registry service (worker)
- **mockas** - Mock assertion service (worker)
- **apigw** - API gateway (worker, supports SAML/OIDCRP tags)
- **issuer** - Credential issuing service (worker)
- **ui** - User interface (web worker)

### Build Configuration

Each service has a specific build configuration:

```makefile
verifier:static:           # Static linking, no CGO, no build tags
registry:dynamic:          # Dynamic linking, CGO enabled
mockas:static:             # Static linking
apigw:static:              # Static linking, supports saml/oidcrp tags
issuer:static:             # Static linking, supports pkcs11 tag
ui:static:                 # Static linking
```

### Template System

The Makefile uses templates to generate targets dynamically:

- **TEST_TEMPLATE** - Generates `test-SERVICE` targets
- **BUILD_TEMPLATE** - Generates `build-SERVICE` targets
- **DOCKER_BUILD_WEB_TEMPLATE** - Docker builds for web workers (verifier, ui)
- **DOCKER_BUILD_WORKER_TEMPLATE** - Docker builds for workers (registry, mockas, apigw, issuer)
- **DOCKER_PUSH_TEMPLATE** - Generates `docker-push-SERVICE` targets
- **DOCKER_TAG_TEMPLATE** - Generates `docker-tag-SERVICE` targets

## How to Add a New Service

Adding a new service requires only 3 edits:

1. **Add to SERVICES list** (line ~22):
```makefile
SERVICES := verifier registry mockas apigw issuer ui newservice
```

2. **Add to WEB_SERVICES or WORKER_SERVICES** (lines ~23-24):
```makefile
WEB_SERVICES    := verifier ui newservice        # if web worker
WORKER_SERVICES := registry mockas apigw issuer  # OR worker
```

3. **Add build configuration** (lines ~38-45):
```makefile
BUILD_CONFIGS := \
    newservice:static: \
    # ... existing configs
```

The templates will automatically generate all targets:
- `test-newservice`
- `build-newservice`
- `docker-build-newservice`
- `docker-push-newservice`
- `docker-tag-newservice`

## Helper Functions

### get-cgo
Returns CGO configuration for a service based on BUILD_CONFIGS:
```makefile
$(call get-cgo,apigw)  # Returns CGO_ENABLED=0 or CGO_ENABLED=1
```

### get-tags
Returns build tags for a service:
```makefile
$(call get-tags,apigw)  # Returns build tags like "saml" or empty
```

### get-ldflags
Returns appropriate LDFLAGS (static vs dynamic):
```makefile
$(call get-ldflags,issuer)  # Returns static or dynamic LDFLAGS
```

### docker-tag
Generates consistent Docker image tags:
```makefile
$(call docker-tag,verifier,1.2.3)  # Returns docker.sunet.se/iam_vc/verifier:1.2.3
```

## Build Tags

### Available Tags
- **saml** - SAML authentication support
- **oidcrp** - OpenID Connect Relying Party support
- **pkcs11** - Hardware Security Module (HSM) support
- **vc20** - W3C Verifiable Credentials 2.0 support

### Usage Examples
```bash
# Build with specific tag
make build-apigw-saml

# Test with specific tag
make test-saml
make test-oidcrp

# Test all tags
make test-all-tags

# Docker build with tags
make docker-build-apigw-saml VERSION=1.2.3
make docker-build-issuer-hsm VERSION=1.2.3
```

## Docker Workflows

### Standard Build and Push
```bash
# Build all services with version 1.2.3
make docker-build VERSION=1.2.3

# Push to registry
make docker-push VERSION=1.2.3
```

### Retagging Images
```bash
# Build as version 1.2.3
make docker-build VERSION=1.2.3

# Retag as production
make docker-tag VERSION=1.2.3 NEWTAG=prod

# Push production tag
make docker-push VERSION=prod

# Retag as latest
make docker-tag VERSION=prod NEWTAG=latest
make docker-push VERSION=latest
```

### Building Specific Services
```bash
# Build only the API gateway
make docker-build-apigw VERSION=1.2.3

# Build with SAML support
make docker-build-apigw-saml VERSION=1.2.3

# Build with all features
make docker-build-apigw-all VERSION=1.2.3
```

## Release Process

The `release` target automates the full release workflow:

```bash
make release VERSION=1.2.3 NEWTAG=prod
```

This performs:
1. Verifies you're on the `main` branch
2. Creates and pushes git tag `1.2.3`
3. Builds all Docker images with version `1.2.3`
4. Pushes images with version `1.2.3`
5. Retags all images to `prod`
6. Pushes images with `prod` tag
7. Retags all images to `latest`
8. Pushes images with `latest` tag

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
grep "^BUILD_CONFIGS" Makefile

# Check what targets exist for a service
make -n build-apigw
make -n docker-build-apigw
```

### Debug Template Generation
```bash
# Show what would be executed (dry run)
make -n build-verifier
make -n docker-push-registry VERSION=1.2.3
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
