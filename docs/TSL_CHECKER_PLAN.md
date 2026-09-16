# Plan: `tsl_checker` CLI + release pipeline

Add a standalone diagnostic CLI `tsl_checker` for inspecting Token Status
List (TSL) entries per `draft-ietf-oauth-status-list`. Mirror the existing
pattern of `check_issuer_jwks` / `jwt_issuer`: a single-package Go program
under `developer_tools/scripts/`, a static Linux/amd64 build target in
`Makefile`, and a per-tag GitHub Actions release workflow that builds a
linux/darwin × amd64/arm64 matrix and uploads binaries + SHA-256 checksums
to a GitHub Release.

## Scope

**Included**

- Three invocation modes:
  1. `tsl_checker -idx <int> -uri <string>` — fetch list at URI, print
     status at idx.
  2. `tsl_checker -credential_file <path>` — parse credential, extract
     `status.status_list.{uri,idx}`, fetch, print.
  3. `cat <credential> | tsl_checker` — same as (2), reading credential
     bytes from stdin (auto-detected when no `-uri` / `-credential_file`
     given and stdin is not a TTY).
- Credential formats: SD-JWT VC (trailing `~disclosure~` sequences), plain
  JWT / JWT VC, mdoc (CBOR IssuerSigned; accept raw CBOR, hex, or
  base64url).
- Status-list token formats: JWT (`application/statuslist+jwt`) and CWT
  (`application/statuslist+cwt`) — content-type-based with a fallback
  sniff (CBOR tag `0xD2`).
- Signature verification: **only** when the status-list JWT header
  contains an embedded `jwk`. Otherwise the tool parses without
  verification and prints a warning.
- Output: pretty-printed with colors + icons matching `check_issuer_jwks`
  style. `-json` for machine-readable output. `-no-color`, `-version`
  flags for parity.
- Makefile: `build-tsl-checker` and `release-tsl-checker` targets,
  following the `check-issuer-jwks` / `jwt-issuer` pattern verbatim
  (`BUMP=major|minor|patch`, tag prefix `tsl-checker-v`).
- GitHub workflow `.github/workflows/release-tsl-checker.yaml` triggered
  on `tsl-checker-v*` tags, matrix build, SHA-256 checksums, GH Release
  with binaries.

**Excluded**

- No Docker image.
- No integration with `pkg/status` health aggregator.
- No caching (single-shot CLI, no persistent state).
- No full JWKS-URI signature verification path — kept out to avoid
  pulling in the trust/keyresolver stack.
- No SD-JWT disclosure processing (only the JWT header/payload is
  inspected for the status claim, which is not selectively-disclosable).
- No support for status list Section 8.4 `time=` parameter.

## Steps

1. Create `developer_tools/scripts/tsl_checker/main.go` (single-file,
   mirrors `check_issuer_jwks/main.go`): flags `-idx`, `-uri`,
   `-credential_file`, `-json`, `-no-color`, `-version`; inline color
   helpers; exit codes 0=VALID, 1=INVALID, 2=SUSPENDED, 3=other, 4=tool
   error, 5=usage error.
2. Credential extraction: JWT/SD-JWT via base64url decode of payload +
   `revocation.ExtractStatusListReference`; mdoc via hex / base64url /
   raw CBOR sniff into `DocumentMdoc` or `DeviceResponseMdoc` +
   `mdoc.ExtractStatusReference`.
3. Fetch + parse status list: mirror guardrails in
   `pkg/revocation/status_list.go` (30 s timeout, http(s) only, 10 MB
   body cap). JWT: verify only if `jwk` header embedded (via
   `jose.ParseJWKToPublicKey`); else parse-only + warning. CWT: parse
   only (`tokenstatuslist.ParseCWT` + `GetStatusFromCWT`).
4. Optional short README at
   `developer_tools/scripts/tsl_checker/README.md` (usage only).
5. Makefile: append `build-tsl-checker` and `release-tsl-checker` after
   `release-jwt-issuer`, duplicating the recipe with tag prefix
   `tsl-checker-v` and output `./bin/tsl_checker`.
6. Workflow: `.github/workflows/release-tsl-checker.yaml` copied from
   `release-jwt-issuer.yaml`, trigger `tsl-checker-v*`, matrix
   linux/darwin × amd64/arm64, checksums, GH Release upload.
7. Verify: `go build`, `go vet`, smoke tests per checklist below.

## Verification

1. `go build ./developer_tools/scripts/tsl_checker/...` — compiles clean.
2. `go vet ./developer_tools/scripts/tsl_checker/...` — clean.
3. `make build-tsl-checker` — produces `./bin/tsl_checker`;
   `./bin/tsl_checker -version` prints `tsl_checker dev` (or latest tag).
4. `./bin/tsl_checker -h` — usage lists the three invocation modes.
5. URI mode smoke test: point `-uri` at a locally-served JWT list (see
   `pkg/tokenstatuslist/example_test.go`); `-idx 0` prints `VALID`,
   exit 0.
6. Credential-file mode: feed an SD-JWT VC from `testdata/` with an
   embedded `status.status_list` claim; verify extracted URI + idx match
   the credential and status is fetched.
7. Stdin mode: `cat <credential> | ./bin/tsl_checker` matches (6) output.
8. `-json`: emits one line of valid JSON parseable by `jq`.
9. Error cases: unreachable URI → exit 4; `-uri` without `-idx` → exit 5;
   `-uri` and `-credential_file` together → exit 5.
10. Release plumbing (dry run): `git tag -l "tsl-checker-v*"` returns
    empty → `make release-tsl-checker BUMP=patch` on a clean branch would
    create `tsl-checker-v0.0.1`. Do **not** actually push during
    verification.

## Decisions

- Verification model = B (verify only if JWT `jwk` header is embedded).
  Keeps the tool a self-contained diagnostic with no external
  key-resolution dependency.
- Flag names = as user specified (`-idx`, `-uri`, `-credential_file`).
- Formats = SD-JWT VC + JWT + mdoc.
- Output = pretty by default, `-json` opt-in.
- Location = `developer_tools/scripts/tsl_checker/` (sibling to
  `check_issuer_jwks`), not `cmd/` (which is reserved for microservices).
- Inline CLI color helpers instead of extracting a shared package.
- Exit codes 0/1/2 for VALID/INVALID/SUSPENDED so shell users can
  `if tsl_checker …; then` on the common valid-credential case; errors
  use ≥ 4 to disambiguate.
