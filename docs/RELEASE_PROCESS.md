# Release Process

## Overview

This project uses **semantic versioning** (`MAJOR.MINOR.PATCH`) with **release candidate (RC) builds on every PR**. The current target version is tracked in the `VERSION` file at the repository root.

## Release Cycle

```
feature branch ──PR──▶ RC build (0.4.0-rc.42.a1b2c3d4) ──merge──▶ Release (v0.4.0)
                                                                         │
                                                          version-bump workflow
                                                                         │
                                                                         ▼
                                                               VERSION = 0.5.0
                                                                         │
next feature branch ──PR──▶ RC build (0.5.0-rc.55.e5f6g7h8) ──merge──▶ Release (v0.5.0)
```

### 1. Development (feature branches)

- Create a branch from `main` and open a PR.
- Every push triggers **Jenkins** (`.jenkins.yaml`), which:
  - Reads `VERSION` (e.g., `0.4.0`)
  - Builds and pushes Docker images tagged `0.4.0-rc.{PR#}.{short-sha}` to `docker.sunet.se`
- **GitHub Actions** (`pr-rc-build.yaml`) runs the Go build and posts a comment on the PR with the expected RC image tags.
- These RC images can be deployed to staging/test environments for validation.

### 2. Release (merge to main)

- When a PR is merged:
  - **Jenkins** builds Docker images tagged with the version (e.g., `0.4.0`) **and** `latest`, and pushes them to `docker.sunet.se`.
  - **GitHub Actions** (`build.yaml`) creates a GitHub Release with tag `v0.4.0` and auto-generated release notes.
  - If the tag already exists (e.g., multiple merges at the same version), it skips release creation.

### 3. Version Bump (prepare next cycle)

After a release, bump the version for the next development cycle:

- Go to **Actions → version-bump → Run workflow**
- Select bump type: `patch`, `minor`, or `major`
- This creates a PR that updates `VERSION` and `CHANGELOG.md`
- Merge it to start the next RC cycle

## Versioning Scheme

| Context | Tag format | Example |
|---------|-----------|---------|
| PR / RC build | `{VERSION}-rc.{PR#}.{SHA}` | `0.4.0-rc.42.a1b2c3d4` |
| Release | `v{VERSION}` | `v0.4.0` |
| Docker latest | `latest` | always points to last release |

## CI Systems

| System | Responsibility |
|--------|---------------|
| **Jenkins** (`.jenkins.yaml`) | Docker build + push to `docker.sunet.se` (has registry credentials) |
| **GitHub Actions** | Go build validation, tests, GitHub Release creation, PR comments |

## Workflows

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `.jenkins.yaml` | Push (all branches) | Docker build + push (RC on branches, release on main) |
| `test.yaml` | Push & PR | Run `make test` |
| `pr-rc-build.yaml` | PR open/sync | Go build validation, comment RC image tags on PR |
| `build.yaml` | PR merged to main | Go build validation, create GitHub Release |
| `version-bump.yaml` | Manual dispatch | Bump VERSION, update CHANGELOG, open PR |

## Docker Image Tags

Every service (`apigw`, `verifier`, `registry`, `mockas`, `issuer`, `ui`) is tagged consistently:

```bash
# RC (from PR #42, commit a1b2c3d4):
docker.sunet.se/iam_vc/verifier:0.4.0-rc.42.a1b2c3d4

# Release:
docker.sunet.se/iam_vc/verifier:0.4.0
docker.sunet.se/iam_vc/verifier:latest
```

## Makefile Targets

```bash
make get_release-tag    # Print current version from VERSION file
make release            # Full release from main (tag + build + push + latest)
make release-rc         # Build RC images (used by CI, needs PR_NUMBER env var)
```

## Quick Reference

```bash
# Check current target version
cat VERSION

# Build RC locally (simulating PR #99)
PR_NUMBER=99 make release-rc

# Manual release from main branch
make release
```
