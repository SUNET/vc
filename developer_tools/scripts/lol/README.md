# lol

Diagnostic CLI for a List of Trusted Lists (LoTL). It fetches the LoTL, then
every list it points to, and reports per list: whether it is reachable, what
kind of list it is, when it expires, and (with anchors) whether its signature
verifies. Signatures are checked with go-trust's own verifier, so `lol` and
go-trust agree on what counts as valid.

Not to be confused with `tsl_checker`, which checks Token Status Lists.

## Build

```sh
make build-lol    # writes ./bin/lol
```

Releases are built by GitHub Actions when a `lol-vX.Y.Z` tag is pushed
(`make release-lol BUMP=patch`). Binaries for linux, macOS and Windows are
attached to the release with a `checksums-sha256.txt`.

## Usage

```sh
# Expiry and kind of every list (signatures are not checked)
lol

# Also verify signatures against your trust anchors
lol -anchors anchors.pem

# Full details per list, or machine-readable output
lol -v
lol -json | jq '.lists[] | select(.state != "ok")'

# Another LoTL
lol -lotl https://example.org/lotl.json
```

Without `-anchors` the `SIG` column is hidden and the signer is reported as
`not checked`.

## Build a trust_anchor_bundle

```sh
lol -anchors lotl-signer.pem -export-anchors bundle.pem
```

`lotl-signer.pem` must be the LoTL signer certificate that you obtained and
pinned out of band. `lol` verifies the LoTL against it, then adds the
certificate each LoTL pointer names, but only if the list it points to
verifies with that certificate. A list that cannot be backed is left out and
the exit code is 1. The result can be used as go-trust's `trust_anchor_bundle`.

Do not use the certificate from the LoTL's own signature header as the pin:
that only shows the file is consistent with itself, not who published it.

## Flags

| Flag | Meaning |
| ---- | ------- |
| `-lotl URL` | LoTL to check (default: the WE BUILD WP4 LoTL) |
| `-anchors FILE` | PEM trust anchors; turns on signature checks |
| `-export-anchors FILE` | write a bundle as described above (needs `-anchors`) |
| `-json` | JSON report instead of the table |
| `-v` | kind, operator, type, format and URL for every list |
| `-timeout D` | per-request timeout (default `30s`) |
| `-version` | print the version |

Colors are used on a terminal only; set `NO_COLOR` to turn them off. Column
widths follow the terminal width, and piped output is never truncated.

## Exit codes

| Code | Meaning |
| ---- | ------- |
| 0 | every list is current and, with `-anchors`, verified |
| 1 | a list is stale or failed, or the LoTL signature failed |
| 2 | usage, fetch or parse error |
