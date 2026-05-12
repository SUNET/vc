# Release Process

## Overview

Releases are managed entirely through **git tags** and **Make targets**. The version is always derived from the latest `vX.Y.Z` git tag using [semantic versioning](https://semver.org/).

## Release Cycle

```text
feature branch ──▶ make release (v0.4.1) ──▶ :v0.4.1 + :dev
                                                   │
                                          test in staging...
                                                   │
                                    ┌──────────────┼──────────────┐
                                    │              │              │
                           make release-demo       │     make release-prod
                                    │              │              │
                                    ▼              │              ▼
                                 :demo             │          :latest
                                                   │
                                          next make release...
```

## Commands

| Command                | What it does                                                                      |
| ---------------------- | --------------------------------------------------------------------------------- |
| `make release`         | Bump version, create git tag, build & push Docker images as `:vX.Y.Z` and `:dev` |
| `make release-demo`    | Promote a release to demo by re-tagging as `:demo`                                |
| `make release-prod`    | Promote a release to production by re-tagging as `:latest`                        |
| `make get_release-tag` | Show the current latest version tag                                               |

## Docker Tag Lifecycle

```text
make release        →  :vX.Y.Z  +  :dev
make release-demo   →  :demo
make release-prod   →  :latest
```

- **`:vX.Y.Z`** — Immutable, versioned tag created on every release.
- **`:dev`** — Mutable, always points to the most recent release. Intended for development/staging environments.
- **`:demo`** — Mutable, only updated when explicitly promoted with `make release-demo`. Intended for demo environments.
- **`:latest`** — Mutable, only updated when explicitly promoted with `make release-prod`. Intended for production/end-user environments.

## Creating a Release

### Basic usage (patch bump)

```bash
make release
```

This will:

1. Verify you are on the `main` branch
2. Find the latest `vX.Y.Z` tag (e.g., `v0.4.0`)
3. Bump the patch version (e.g., `v0.4.0` → `v0.4.1`)
4. Create and push an annotated git tag
5. Build all Docker images tagged as `:v0.4.1`
6. Tag and push images as `:dev`

### Minor or major bump

```bash
make release BUMP=minor    # v0.4.0 → v0.5.0
make release BUMP=major    # v0.4.0 → v1.0.0
```

### Releasing from a non-main branch

By default, `make release` requires you to be on the `main` branch. If you need to release from another branch (e.g., during active development), use `FORCE=true`:

```bash
make release FORCE=true
make release BUMP=minor FORCE=true
```

`FORCE=true` also skips the dirty working tree check.

## Promoting to Demo

Promote a release to the demo environment by re-tagging as `:demo`:

### Promote the most recent release to demo

```bash
make release-demo
```

This will:

1. Find the latest `vX.Y.Z` tag
2. Pull the Docker images for that version
3. Re-tag them as `:demo`
4. Push `:demo`

### Promote a specific version to demo

```bash
make release-demo TAG=v0.4.0
```

This lets you point the demo environment at any previous release.

## Promoting to Production

Once a release has been tested and is ready for production, promote it to `:latest`:

### Promote the most recent release

```bash
make release-prod
```

This will:

1. Find the latest `vX.Y.Z` tag
2. Pull the Docker images for that version
3. Re-tag them as `:latest`
4. Push `:latest`

### Promote a specific version

```bash
make release-prod TAG=v0.4.0
```

This is useful for rolling back — you can promote any previous version to `:latest`.

## Checking the Current Version

```bash
make get_release-tag
```

Prints the latest `vX.Y.Z` git tag (e.g., `v0.4.1`).

## Examples

### Full release workflow

```bash
# Create a patch release
make release

# Test the :dev images in staging...

# Promote to demo
make release-demo

# Promote to production
make release-prod
```

### Hotfix from a feature branch

```bash
# Force release from current branch
make release FORCE=true

# Promote immediately
make release-prod
```

### Rollback production

```bash
# Promote an older version to :latest
make release-prod TAG=v0.3.0
```

## Safety Checks

| Check                      | Behaviour                                    | Override     |
| -------------------------- | -------------------------------------------- | ------------ |
| Must be on `main` branch   | Errors if not on `main`                      | `FORCE=true` |
| Working tree must be clean | Errors if uncommitted changes                | `FORCE=true` |
| `BUMP` must be valid       | Errors if not `major`, `minor`, or `patch`   | —            |
| `TAG` must match `vX.Y.Z`  | Errors on invalid format                     | —            |
| Reserved tag guard         | Blocks reserved tags on direct docker targets | —            |

### Reserved Tag Guard

The Docker tags `vX.Y.Z`, `latest`, `testing`, `demo`, and `dev` are **reserved** and cannot be used as `VERSION` or `NEWTAG` when running docker targets directly (e.g., `make docker-build`, `make docker-push`, `make docker-tag`).

Only `make release`, `make release-prod`, and `make release-demo` are allowed to produce these tags.

```bash
# These are BLOCKED:
make VERSION=dev docker-build           # ✗ 'dev' is reserved
make VERSION=v1.2.3 docker-build        # ✗ semver is reserved
make VERSION=latest docker-push         # ✗ 'latest' is reserved
make VERSION=foo NEWTAG=demo docker-tag # ✗ 'demo' is reserved

# These are ALLOWED:
make docker-build                       # ✓ uses default VERSION=local
make docker-build VERSION=myfeature     # ✓ non-reserved tag
make release                            # ✓ creates vX.Y.Z and :dev
make release-prod                       # ✓ creates :latest
make release-demo                       # ✓ creates :demo
```

## Docker Registry

All images are pushed to `docker.sunet.se/iam_vc/`. Services:

| Service  | Image                              |
| -------- | ---------------------------------- |
| apigw    | `docker.sunet.se/iam_vc/apigw`    |
| verifier | `docker.sunet.se/iam_vc/verifier` |
| registry | `docker.sunet.se/iam_vc/registry` |
| issuer   | `docker.sunet.se/iam_vc/issuer`   |
