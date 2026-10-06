# go-cryptoutil
<div align="center">

[![Go Reference](https://pkg.go.dev/badge/github.com/sirosfoundation/go-cryptoutil.svg)](https://pkg.go.dev/github.com/sirosfoundation/go-cryptoutil)
[![Go Report Card](https://goreportcard.com/badge/github.com/sirosfoundation/go-cryptoutil)](https://goreportcard.com/report/github.com/sirosfoundation/go-cryptoutil)
![coverage](https://raw.githubusercontent.com/sirosfoundation/go-cryptoutil/badges/.badges/main/coverage.svg)
[![Build Status](https://github.com/sirosfoundation/go-cryptoutil/actions/workflows/test.yml/badge.svg)](https://github.com/sirosfoundation/go-cryptoutil/actions/workflows/test.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/sirosfoundation/go-cryptoutil/badge)](https://scorecard.dev/viewer/?uri=github.com/sirosfoundation/go-cryptoutil)
[![License](https://img.shields.io/badge/License-BSD_2--Clause-orange.svg)](https://opensource.org/licenses/BSD-2-Clause)
[![Go Version](https://img.shields.io/github/go-mod/go-version/sirosfoundation/go-cryptoutil)](https://github.com/sirosfoundation/go-cryptoutil)

</div>

Extensible Go crypto utilities for certificate parsing, signature verification,
ECDSA encoding, algorithm mapping, and key management — with a plugin architecture
for non-standard curves and future post-quantum algorithms.

## Overview

Go's `crypto/x509` package supports a fixed set of key types and curves.
`go-cryptoutil` provides an extension mechanism that lets you plug in support
for additional algorithms (e.g. brainpool curves, PQ signatures) without
forking the standard library.

### Core Module (`go-cryptoutil`)

Zero external dependencies. Provides:

- **`x509ext.go`** — Extensible certificate parsing and signature verification.
  Falls back to `crypto/x509` first, then tries registered extension parsers/verifiers.
- **`ecdsa.go`** — ECDSA signature format conversion between IEEE P1363 (raw r‖s)
  and ASN.1 DER. Used by XML-DSIG, JWS, COSE, and WebAuthn.
- **`algorithms.go`** — Cross-protocol algorithm registry mapping keys to
  JWS, XML-DSIG, and COSE algorithm identifiers.
- **`keyutil.go`** — Extensible private key parsing (PKCS#8, EC, PKCS#1) plus
  key type inspection helpers.

### Brainpool Plugin (`go-cryptoutil/brainpool`)

Separate Go module with the gematik brainpool dependency. Provides:

- `Register(ext)` — Registers brainpool P256r1, P384r1, P512r1 certificate
  parsing, signature verification, key parsing, and algorithm mappings.

### Explicit EC Parameters Plugin (`go-cryptoutil/ecparams`)

Opt-in, separate Go module (it needs the gematik brainpool curves). Parses
real-world certificates that `crypto/x509` rejects, notably ICAO 9303 eMRTD CSCA
certificates whose SubjectPublicKeyInfo carries **explicit EC domain parameters**
(`specifiedCurve`, RFC 3279 / X9.62) instead of a named-curve OID
(`x509: invalid ECDSA parameters`). Nothing changes unless you call `Register`.

```go
ext := cryptoutil.New()
brainpool.Register(ext) // optional
ecparams.Register(ext)
cert, err := ext.ParseCertificate(der) // cert.PublicKey is the matching *ecdsa.PublicKey
```

What it accepts:

- Explicit parameters whose prime field, curve `a`/`b`, base point, order and
  cofactor **exactly equal** those of NIST P-224/P-256/P-384/P-521 or
  brainpoolP256r1/P384r1/P512r1 (uncompressed or compressed base point; optional
  seed ignored; cofactor may be omitted, otherwise must be 1). The public key
  point must be uncompressed and on the matched curve.
- A negative serial number (`SerialNumber` carries the negative value).
- An RSA public key whose AlgorithmIdentifier lacks the NULL parameters.
- Zero-padded curve constants: the curve `a` and `b` octet strings are compared
  as numbers, so a leading `0x00` pad (for example the 49-byte `a`/`b` of the UAE
  CSCA 02 certificate on P-384) still matches; the value must still equal the
  known one exactly.
- A `basicConstraints` extension whose `cA` BOOLEAN is BER-style TRUE (any
  non-zero octet, for example `0x01` as in CSCA-UKRAINE) instead of DER's `0xFF`.
  Only that octet is normalised for the `crypto/x509` parse; the original
  extension bytes, `Raw` and `RawTBSCertificate` are kept.

What it never accepts: a self-described curve is never trusted. Unknown or
non-matching parameters (different prime, `a`, `b`, generator, order or cofactor,
binary fields, `implicitlyCA`, hybrid points, trailing data, twisted `t1`
Brainpool curves, and the Brainpool curves below 256 bits, which the brainpool
library does not provide) are declined with `ErrNotHandled`, so the certificate
stays rejected. A padded constant that differs from the known value, padding on
the base point, and any other malformed `basicConstraints` (truncated, wrong
BOOLEAN length, non-BOOLEAN `cA`, trailing data) are not repaired either.

The returned certificate keeps the original `Raw`, `RawTBSCertificate`,
`RawSubjectPublicKeyInfo`, `Signature` and `SignatureAlgorithm`; nothing is
re-encoded, so signatures are checked over the original TBS. All other fields
(names, extensions, validity) come from `crypto/x509` parsing a copy of the
certificate in which only the offending element was replaced. `ecparams.Verifier`
(registered by `Register`) verifies ECDSA signatures made by keys on these
curves, in DER or raw r‖s form; with `PublicKey` set, `x509.Certificate.CheckSignature`
also verifies them on Go's standard library.

Master List integration test: `integration_test.go` parses every certificate of
a real CSCA Master List with and without the extensions and reports counts. It
**reads the public list at test time; nothing from it is stored in this
repository or redistributed.** It is skipped unless opted in:

```bash
cd ecparams
GOCRYPTOUTIL_PKD_MASTERLIST=/path/to/list.ml go test -run MasterList -v .   # local file or ZIP
GOCRYPTOUTIL_PKD_MASTERLIST_URL=https://... go test -run MasterList -v .     # download; honours SKIP_NETWORK_TESTS
```

The ICAO PKD Master List (<https://www.icao.int/icao-pkd/icao-master-list>,
download at <https://pkddownload.icao.int/>) is behind terms and a CAPTCHA, so
download it by hand and use the first form. National master lists have the same
format.

## Installation

```bash
# Core module (zero dependencies)
go get github.com/sirosfoundation/go-cryptoutil

# Brainpool plugin (adds gematik dependency)
go get github.com/sirosfoundation/go-cryptoutil/brainpool

# Explicit EC parameters / lenient eMRTD certificate plugin
go get github.com/sirosfoundation/go-cryptoutil/ecparams
```

## Usage

### Basic: Extensible Certificate Parsing

```go
import (
    "github.com/sirosfoundation/go-cryptoutil"
    "github.com/sirosfoundation/go-cryptoutil/brainpool"
)

ext := cryptoutil.New()
brainpool.Register(ext)

// Parse certificates — stdlib curves + brainpool
cert, err := ext.ParseCertificate(derBytes)

// Parse PEM bundles
certs, err := ext.ParseCertificatesPEM(pemData)
```

### ECDSA Signature Conversion

```go
// XML-DSIG / JWS raw r||s → ASN.1 DER (for Go's x509.CheckSignature)
derSig, err := cryptoutil.ECDSARawToASN1(rawSig)

// ASN.1 DER → raw r||s (for signing output)
rawSig, err := cryptoutil.ECDSAASN1ToRaw(derSig, 32) // 32 for P-256
```

### Algorithm Lookup

```go
ext := cryptoutil.New()
alg := ext.Algorithms.ForKey(publicKey)
fmt.Println(alg.JWS)     // "ES256"
fmt.Println(alg.XMLDSIG)  // "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
```

## Architecture

```
go-cryptoutil/           Core module (zero deps)
├── x509ext.go           Extensible cert parsing + sig verification
├── ecdsa.go             ECDSA raw↔ASN.1 conversion
├── algorithms.go        Cross-protocol algorithm registry
├── keyutil.go           Extensible key parsing + helpers
├── brainpool/           Plugin submodule
│   └── brainpool.go     Brainpool P256r1/P384r1/P512r1 support
└── ecparams/            Plugin submodule
    ├── ecparams.go      Explicit EC parameters, negative serial, RSA without NULL
    └── curves.go        Known-curve table (exact-match allowlist)
```

The extension mechanism uses function types (`CertificateParser`, `SignatureVerifier`,
`PrivateKeyParser`) registered on an `Extensions` struct. The core always tries
Go's standard library first and falls back to registered extensions, returning
`ErrNotHandled` to signal the next extension should be tried.

## Writing a Plugin

```go
func Register(ext *cryptoutil.Extensions) {
    ext.Parsers = append(ext.Parsers, func(der []byte) (*x509.Certificate, error) {
        // Try to parse; return cryptoutil.ErrNotHandled if not your cert type
        return myCert, nil
    })
    ext.Verifiers = append(ext.Verifiers, func(cert *x509.Certificate, algo x509.SignatureAlgorithm, signed, sig []byte) error {
        // Verify signature; return cryptoutil.ErrNotHandled if not your algorithm
        return nil
    })
}
```

## Versioning and releases

All modules in this repository are released together under **one common
version number**: the root module and every nested module (`brainpool`,
`ecparams`, `pkcs11pool`). A release `v0.7.0` consists of the tags `v0.7.0`,
`brainpool/v0.7.0`, `ecparams/v0.7.0` and `pkcs11pool/v0.7.0` on the same
commit. Nested modules need the directory-prefixed tag because that is how the
Go toolchain finds a module that lives in a subdirectory.

**Pinning.** Use the same version for the root and for each nested import path
you use:

```bash
go get github.com/sirosfoundation/go-cryptoutil@v0.7.0
go get github.com/sirosfoundation/go-cryptoutil/ecparams@v0.7.0
```

A nested `go.mod` may still require an older published root version; that is
fine under minimal version selection. It is bumped only when the nested code
needs a newer root API. Nested `go.mod` files must not contain `replace`
directives (CI enforces this), since consumers would ignore them.

**Releasing.** Merge the PR, then from an up-to-date `main` run
`scripts/release.sh vX.Y.Z` (dry run: checks the tree, that the version is
greater than every existing tag, and runs vet, race tests and a
`-mod=readonly` build for every module), and then the same command with
`--push` to create the annotated tags and push them together. Only maintainers
with permission to push tags to the repository should release.

**GitHub release.** After pushing the tags, `scripts/release.sh --push`
dispatches `.github/workflows/release.yml` (from `main`) with the new tag via
the `gh` CLI. (GitHub creates no tag push event when a single push carries more
than three tags, and a release pushes four; the workflow also has a tag-push
trigger that only matches the root tag, for tags pushed in smaller batches.)
Both paths are idempotent. The workflow first verifies that all four tags
exist on the remote at the same commit, that the commit is on `main`, and that
vet, tests and build pass for every module; then it creates the GitHub release,
unless one already exists, in which case it is left untouched (so hand-edited
notes are never overwritten). The notes are the fenced
`<!-- release-notes:vX.Y.Z:start -->` block from `RELEASE_NOTES.md` if present,
otherwise GitHub's generated notes, followed by a fixed footer with the four
module tags and pin instructions. A tag with a suffix such as `-rc1` is marked
as a pre-release. If the workflow fails, fix the cause and re-run it from
Actions, Release, "Run workflow" with the tag as input (or
`gh workflow run release.yml --ref main -f tag=vX.Y.Z`, which is also the
fallback when `gh` was unavailable during the release); never delete or move
the tags. Tag creation should be restricted to maintainers (repository tag
ruleset), because a pushed tag selects the commit whose scripts the workflow runs. (The workflow runs the scripts of the tagged commit, so it can only be used
for releases after v0.7.0.) `scripts/check-release-tags.sh vX.Y.Z` runs the tag check locally.

**Retracted version.** `ecparams/v0.1.0` was published under the earlier
per-module versioning. It stays available (tags are never deleted), but
`ecparams/go.mod` retracts it, so use the common version line instead. A
retraction takes effect once a later version containing it is published.

| Common version | Root | brainpool | ecparams | pkcs11pool |
|----------------|------|-----------|----------|------------|
| up to v0.6.0 (independent versions) | v0.2.0 to v0.6.0 | v0.2.0 | v0.1.0 (retracted) | v0.1.0, v0.1.1 |
| v0.7.0 and later | vX.Y.Z | vX.Y.Z | vX.Y.Z | vX.Y.Z |

## Development

```bash
make test          # Run all tests
make test-ecparams # Run ecparams plugin tests
make lint          # Run golangci-lint
make coverage      # Generate coverage report
make check-coverage # Check coverage thresholds
make setup         # Install tools + git hooks
```

## License

BSD 2-Clause. See [LICENSE.txt](LICENSE.txt).
