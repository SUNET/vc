# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed - Architecture Redesign

- **HTTP Server Architecture**: Major restructuring for clearer separation of concerns
  - HTTP server now always runs and provides monitoring endpoints
  - TCP server is optional (enabled via `-tcp` flag)
  - AuthZen API is optional on HTTP server (enabled via `-authzen` flag)
  - Monitoring endpoints (`/health`, `/ready`, `/stats`, `/metrics`) always available
  - At least one protocol (`-tcp` or `-authzen`) must be enabled

- **Command-Line Flag Changes**:
  - **Removed**: `-http` flag (HTTP server now always runs for monitoring)
  - **Removed**: `-health` flag (monitoring always on HTTP server)
  - **Removed**: `-addr` flag (replaced with `-tcp-addr` for clarity)
  - **Added**: `-tcp` flag (enables TCP server, default: false)
  - **Added**: `-authzen` flag (enables AuthZen API on HTTP server, default: false)
  - **Added**: `-tcp-addr` flag (TCP server address, default: ":6000")
  - **Renamed**: `-http-addr` now serves monitoring + optional AuthZen (default: ":8000")

- **Deployment Modes**:
  1. TCP-only + monitoring: `-tcp` (HTTP provides monitoring for TCP)
  2. AuthZen-only: `-authzen` (HTTP provides monitoring + AuthZen API)
  3. Dual-protocol: `-tcp -authzen` (both protocols + monitoring, shared engine)

### Added

- **HTTP/AuthZen API Support**:
  - AuthZen Authorization API 1.0 endpoint (`POST /access/v1/evaluation`)
  - Automatic AuthZen JSON to SPOCP S-expression conversion
  - Dual-protocol server supporting TCP and HTTP simultaneously
  - Shared engine mode for dual-protocol deployments
  - Standalone HTTP mode with automatic rule loading
  - Request metrics and X-Request-ID header support
  - See `docs/AUTHZEN.md` for details

- **HTTP Monitoring Endpoints** (always available):
  - `GET /health` - Health check endpoint
  - `GET /ready` - Readiness check (verifies rules loaded)
  - `GET /stats` - JSON statistics (requests, rules, indexing)
  - `GET /metrics` - Prometheus-style metrics

- **Build System Improvements**:
  - Makefile targets: `build-server`, `build-client`, `build-tools`
  - Binary output to `bin/` directory (gitignored)
  - Clean target removes `bin/`

- **Documentation Enhancements**:
  - Comprehensive godoc comments for all public APIs
  - Package-level examples for `httpserver` package
  - Method documentation with usage examples
  - Three new ADRs documenting architectural decisions:
    - ADR-09: Dual-Protocol Server Architecture
    - ADR-10: AuthZen S-Expression Mapping Strategy
    - ADR-11: HTTP Server Operational Modes
  - Updated README.md with new flag structure and deployment modes
  - Updated `docs/AUTHZEN.md` with new architecture examples
  - Updated all ADRs to reflect new architecture

### Changed

- **Bug Fix**: Fixed mutex copying issue in `httpserver` package
  - Changed `HTTPServer.mu` from value to pointer (`*sync.RWMutex`)
  - Enables proper mutex sharing between TCP and HTTP servers
  - Prevents lock value copying warning

- **httpserver Package**:
  - Added `EnableAuthZen` field to `Config` struct
  - Conditional route registration for AuthZen endpoint
  - Package documentation updated to describe monitoring + optional AuthZen model

### Added (from previous work)

- Initial implementation of SPOCP authorization engine
- S-expression parser supporting canonical form (length-prefixed)
- Star form implementations:
  - Wildcard (`*`) - matches any element
  - Set (`* set`) - matches elements in a set
  - Range (`* range`) - matches values in a range (numeric, alpha, time, date, IPv4, IPv6)
  - Prefix (`* prefix`) - matches strings with given prefix
  - Suffix (`* suffix`) - matches strings with given suffix
- Partial order comparison algorithm (<=) from SPOCP specification
- Engine API with Query, AddRule, and FindMatchingRules methods
- Comprehensive test suite based on specification examples
- Example programs demonstrating common use cases
- Makefile for build automation
- Documentation:
  - README.md with quick start and examples
  - API.md with detailed API documentation
  - Inline code documentation

### Implementation Notes
- Based on draft-hedberg-spocp-sexp-00 specification
- Follows Go best practices and idioms
- Test coverage: ~31% overall, core functionality well covered
- All specification examples tested and passing

### Known Limitations
- Set normalization not yet fully implemented
- No caching mechanism
- Not thread-safe (requires external synchronization)
- Time ranges use simple string comparison for HH:MM:SS format
- Date ranges require RFC3339 format

## [0.1.0] - 2025-12-10

### Added
- Initial release
