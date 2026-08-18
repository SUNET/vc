# ZK/PPID Presentation Verification Plan

**Status: Plumbing implemented AND native ZK/PPID verification implemented**
(opt-in, `zknative` Go build tag). See "Native verification (implemented)"
below.

This document covers vc-verifier's support for verifying "mso_mdoc_zk"
presentations - zero-knowledge (Longfellow) proof-of-possession over an mdoc
credential, with an optional pairwise pseudonym (PPID) - and exactly what's
missing before it actually works end to end.

## Background

The wallet SDKs (siros-sdk-kotlin, siros-sdk-swift) and go-wallet-backend can
already generate a ZK proof of possession + optional pairwise pseudonym for
an mdoc credential, wrapped in multipaz's `zkDocuments` extension to the
standard ISO 18013-5 DeviceResponse, and present it as the `vp_token` for a
DCQL query with `format: "mso_mdoc_zk"`. This was tested end-to-end against a
**third-party** verifier (a self-hosted multipaz/Kotlin verifier,
`siros-multipaz-verifier.fly.dev`), which does real Longfellow ZK
verification via Google's own compiled `libzkp.so`.

vc-verifier (this repo's own verifier implementation) had **zero** support
for this - not even the wire-format parsing - before this change. This
document + the accompanying code close as much of that gap as is possible
without a native Longfellow ZK verifier binding for Go, and lay out exactly
what remains.

## What's real / working / tested

All of the following is implemented, unit-tested (round-trip CBOR
encode/decode against hand-built fixtures, not just type-checked), and does
not depend on any native ZK library:

1. **Wire-format parsing** (`pkg/mdoc/zk.go`) - decodes a `zkDocuments`-
   bearing DeviceResponse: `ZkDocumentMdoc` (proof + tag-24-wrapped
   `documentData`), `ZkDocumentDataMdoc` (zkSystemId, docType, timestamp,
   issuerSigned, deviceSigned, msoX5chain), matching multipaz's own
   `ZkDocument.kt`/`ZkDocumentData.kt` CBOR shapes exactly. `DeviceResponseMdoc`
   gained one new `omitempty` field (`ZkDocuments`) - purely additive, a
   plain "mso_mdoc" DeviceResponse is unaffected.

2. **Format detection** (`internal/verifier/apiv1/handlers_verification.go`) -
   `detectCredentialFormat` now distinguishes "mso_mdoc_zk" from "mso_mdoc"
   (both are wire-compatible CBOR at the byte-sniffing level previously used,
   so this required an actual partial decode - `mdoc.PeekIsZkDeviceResponse`).

3. **DCQL request/response model** (`pkg/openid4vp/dcql_zk.go`) -
   `FormatMsoMdocZk`, `MetaQuery.ZKSystemType`/`.PPIDContext`, JSON
   (un)marshaling matching the wire's flat-object `zk_system_type` entries,
   `ValidateCredentialQuery` requiring `doctype_value` + non-empty
   `zk_system_type` for this format, and `MatchZKSystemType` to check a
   presented `zkSystemId` against what a request declared it would accept.
   `copyDCQL` (presentation_builder.go) was updated to deep-copy these new
   fields, and, in the same change, to also deep-copy `DoctypeValue` -
   which it had been silently dropping before this fix (a pre-existing
   gap this format would otherwise have hit immediately). Both are copied
   today; neither is still missing.

4. **Issuer trust evaluation** (`pkg/mdoc/zk_verifier.go`,
   `ZkHandler.verifyOneDocument`) - the presented `msoX5chain` is extracted
   and run through the exact same `TrustEvaluator` used for plain "mso_mdoc"
   presentations (validity period + `Evaluate(...)` call). This is a REAL
   trust decision, not a stub - an untrusted issuer is rejected here, before
   the code ever reaches the native-binding gap.

5. **zk_system_type matching** - a presented `zkSystemId` is checked against
   the request's declared `zk_system_type` array (`MatchZKSystemType`); a
   mismatch is rejected with a specific error, distinct from "not
   implemented".

6. **`verifier_context` derivation** (`ComputeZkVerifierContext`) -
   implements the CONFIRMED wire-format formula (cross-checked 2026-08-17
   against both `siros-sdk-kotlin`'s `ZkProofSystem.kt`
   `DefaultZkPseudonymDeriver` and multipaz's own
   `multipaz-verifier-server/.../verifier.kt`, after direct confirmation from
   zk-cred-longfellow's V8/PPID author):

   ```
   verifier_id_hash  = SHA256(verifier_id_source)     verifier_id_source = session_id, falling back to client_id
   ppid_context_hash = SHA256(ppid_context)            if ppid_context present
                     = 32 zero bytes                   otherwise (NOT SHA256(""))
   verifier_context  = SHA256(verifier_id_hash || ppid_context_hash)
   ```

   Pinned with a byte-level test (`TestComputeZkVerifierContext_MatchesDocumentedFormula`)
   so a future refactor can't silently drift from this. Note the
   **session id**, not the verifier's `client_id`, is the real `verifier_id`
   input - a real reference implementation binds a pseudonym to the
   presentation session specifically so a captured proof can't be
   replayed/cached against a different session.

7. **Native call argument assembly** - issuer public key in SEC1 encoding
   (`sec1PublicKeyFromCert`, via `ecdsa.PublicKey.ECDH().Bytes()`), the
   `[]ZkAttribute` list (element identifier + CBOR-encoded value, mirroring
   zk-cred-longfellow's own `Attribute` FFI record), `device_name_spaces_bytes`
   (CBOR-encoded from `DeviceSigned`, correctly empty-map for the common
   "no device-signed elements" case), and the exact timestamp string (reused
   byte-for-byte from the presented `ZkDocumentDataMdoc.Timestamp`, not
   recomputed) are all assembled and ready to hand to a native verify call.

8. **SessionTranscript construction** (`pkg/mdoc/session_transcript.go`,
   `BuildOID4VPSessionTranscript`) - vc-verifier did not build an ISO
   18013-5 SessionTranscript for ANY mdoc format before this change (plain
   "mso_mdoc" verification doesn't check DeviceAuth/session binding at all
   today - a separate, pre-existing gap, not introduced or fixed here).
   This implements the OpenID4VP redirect-flow handover construction
   (mirrors multipaz's `OpenID4VP.kt` `Version.DRAFT_29` "Invocation via
   Redirects" case exactly). **Caveat**: not yet checked against a real
   wallet's own transcript bytes - treat as a spec-derived best-effort
   construction until confirmed live. The DC API variant and older OpenID4VP
   drafts are not implemented.

## Native verification (implemented)

`nativeVerifyZkProofWithPPID` in `pkg/mdoc/zk_verifier.go` is now a REAL
call, not a stub - when vc-verifier is built with the `zknative` Go build
tag (see README.md's "Native ZK/PPID proof verification" section for
setup). The default build (no `zknative` tag, `CGO_ENABLED=0`, fully
static - unchanged) still returns `ErrNativeZkVerifyNotImplemented`, same
as before; this is purely opt-in, mirroring `pkg/pki`'s PKCS#11 support.

This closes the gap the rest of this document originally described in
detail (kept below, historical, for context on *why* it was hard and what
changed to make it tractable).

### What made this tractable: zk-cred-longfellow's plain C ABI

`zk-cred-longfellow` (`~/work/siros.org/zk-cred-longfellow`) added a
second, hand-written, ordinary `extern "C"` ABI specifically for Go
(`src/go_ffi.rs` / `include/zk_cred_longfellow_go.h`), separate from the
UniFFI/RustBuffer-based ABI (`src/ffi_api.rs`) that generates the
Swift/Kotlin bindings described below. It exposes:

```rust
fn rust_initialize_verifier(circuit: *const u8, circuit_len: usize, circuit_version: u8, num_attributes: u8, error_out: *mut *mut c_char) -> *mut MdocZkVerifier
fn rust_free_verifier(verifier: *mut MdocZkVerifier)
fn rust_free_error_string(ptr: *mut c_char)
fn rust_verify_with_ppid(verifier: *const MdocZkVerifier, issuer_pk: *const u8, issuer_pk_len: usize, attributes: *const CAttribute, attributes_len: usize, doc_type: *const c_char, device_name_spaces_bytes: *const u8, device_name_spaces_bytes_len: usize, session_transcript: *const u8, session_transcript_len: usize, time: *const c_char, verifier_context: *const u8, verifier_context_len: usize, proof: *const u8, proof_len: usize, error_out: *mut *mut c_char) -> i32
```

Plain pointers/lengths/small integers only - no UniFFI RustBuffer
serialization to reimplement by hand, and it accepts a real variable-length
attribute array, a real `device_name_spaces_bytes`, splits (expensive)
circuit loading from verification (so a long-lived process loads each
distinct circuit once and reuses the handle), and returns an owned,
caller-freed error string with the real underlying error message.

This repo's `pkg/mdoc/zknative` package (build tag `zknative`) is a cgo
wrapper around exactly this ABI. `pkg/mdoc/zk_native_cgo.go` (same tag)
resolves a presented document's `zkSystemId` to a circuit via a new Go port
of the wallet SDKs' circuit-catalog client
(`pkg/mdoc/zkcircuit`, fetching from the live
`https://zk-circuits.fly.dev` service by default, SHA-256-verifying and
zstd-decompressing the downloaded artifact), caches the loaded native
verifier per circuit id (`sync.Map`-style, with in-flight de-duplication so
concurrent requests for the same not-yet-loaded circuit don't redundantly
reload it), and calls `VerifyWithPPID`.

### Remaining native-binding gap: non-PPID `nativeVerifyZkProof`

`zk-cred-longfellow`'s Go C ABI only exports `rust_verify_with_ppid` today -
no plain non-PPID verify function exists yet. `nativeVerifyZkProof` (the
non-PPID direction) therefore still returns
`ErrNativeZkVerifyNotImplemented`, even under the `zknative` tag, with a
message naming this specific reason. This was assessed as acceptable scope
for this change: every real presentation from this org's wallets today uses
the deployed 2-attribute (`given_name` + `pairwise_pseudonym`) V8 circuit -
i.e. the PPID path - so this does not block real end-to-end verification.
Adding a `rust_verify` sibling function to zk-cred-longfellow's `go_ffi.rs`
(mirroring `rust_verify_with_ppid` minus the pseudonym/verifier_context
arguments) is a small, separate follow-up once needed.

### Historical background (why this was hard before `go_ffi.rs` existed)

The rest of this subsection is kept for context; it no longer describes the
current state, see above.

`zk-cred-longfellow` also exposes a UniFFI-based ABI (`src/ffi_api.rs`,
feature `uniffi`) for the Swift/Kotlin bindings:

```rust
fn initialize_verifier(circuit: &[u8], circuit_version: CircuitVersion, num_attributes: u8) -> Result<MdocZkVerifier, MdocZkError>
fn verify(verifier: &MdocZkVerifier, issuer_public_key_sec_1: &[u8], attributes: &[Attribute], doc_type: &str, device_name_spaces_bytes: &[u8], session_transcript: &[u8], time: &str, proof: &[u8]) -> Result<(), MdocZkError>
fn verify_with_ppid(verifier: &MdocZkVerifier, ..., verifier_context: &[u8], proof: &[u8]) -> Result<(), MdocZkError>
```

UniFFI does not target Go as a first-class language, and its raw
`RustBuffer`-based C header (`bindings/swift/zk_cred_longfellowFFI.h`) is
not something cgo can consume directly without reimplementing UniFFI's own
internal, versioned wire protocol by hand - real, error-prone, multi-day
work. `src/go_ffi.rs`'s plain C ABI (described above) is what made a Go
binding tractable without that: a second, hand-written, ordinary ABI built
alongside (not instead of) the UniFFI one, from the same crate's default
Cargo features.

## Known simplifications / follow-ups (not native-binding related)

- `MatchZKSystemType` matches by exact `zkSystemId` string equality against
  the request's declared IDs. This is what the DCQL/multipaz wire
  convention assumes in practice (wallet and verifier both use the same
  circuit-catalog naming convention), but isn't spec-guaranteed - a stricter
  implementation could match by `system` + individual params
  (`circuit_hash`, `num_attributes`) instead. Documented as a known
  simplification in `MatchZKSystemType`'s doc comment.
- `BuildOID4VPSessionTranscript` implements only the OpenID4VP Draft 29
  redirect-flow case. The Digital Credentials API variant (`origin` instead
  of `client_id`+`response_uri`) and older draft session-transcript shapes
  are not implemented - needed if/when ZK verification is wired up for
  those flows too.
- The scope-to-DCQL-CredentialQuery lookup in `handlers_verification.go`'s
  new `FormatMDocZK` case uses this codebase's own existing convention
  (`CredentialQuery.ID == scope`, see `buildDCQLQueryFromConfig` in
  `internal/verifier/apiv1/client.go`). If a session's cached `DCQLQuery` is
  absent or has no matching entry, `RequestedZkSystems`/`PPIDContext` come
  back empty rather than erroring outright - every presented document then
  correctly fails `zk_system_type` matching (a clear, specific error),
  rather than silently skipping that check.
- While extending `copyDCQL`, `DoctypeValue` copying was added alongside the
  new ZK fields (it was silently dropped before - a pre-existing gap that
  would otherwise have broken this format via presentation templates using
  `copyDCQL`, since `mso_mdoc_zk`'s own validation requires
  `doctype_value`). Other pre-existing `copyDCQL` gaps (e.g. `TypeValues`,
  `ClaimQuery.ID`) were left as-is - out of scope for this change.
- The non-PPID native verify direction (`nativeVerifyZkProof`) remains
  unimplemented even under the `zknative` build tag - see "Remaining
  native-binding gap" above; this is a zk-cred-longfellow (Rust crate) gap,
  not a Go-side one.
- The W3C Digital Credentials API and older OpenID4VP session-transcript
  variants are still out of scope for native verification, same as for the
  plumbing itself (see `BuildOID4VPSessionTranscript` above) - this change
  targeted specifically the OpenID4VP redirect-flow path.
- `pkg/mdoc/zkcircuit.Client`'s circuit-catalog source(s) are configurable
  via `verifier.zk_circuits.sources` in YAML config (see
  `docs/CONFIGURATION.md`), defaulting to the live
  `https://zk-circuits.fly.dev` service. The verifier cache in
  `zk_native_cgo.go` is keyed by `zkSystemId` (the circuit's own catalog
  id) for the lifetime of the process - there is no eviction/TTL, since the
  known circuit catalog is small and each entry's bytes are immutable once
  published.
- Test coverage: `pkg/mdoc/zkcircuit` has unit tests (mocked HTTP, an
  injectable-fetch-function pattern mirroring siros-sdk-kotlin's
  `ZkCircuitClient` test, plus one real `httptest`-backed round trip).
  `pkg/mdoc/zknative` and `pkg/mdoc/zk_native_cgo.go` each have a REAL,
  live integration test that fetches the actual V8/2-attribute circuit from
  `https://zk-circuits.fly.dev` and verifies a genuine, known-good
  Longfellow V8 PPID proof (sourced from zk-cred-longfellow's own
  `mdoc_zk::prover_v8_test` fixture) end to end through cgo - confirming a
  genuine proof verifies, a tampered proof (one flipped byte) is rejected
  with a real error, and a wrong attribute count is rejected cleanly. These
  tests are skipped (not failed) if the live service is unreachable.
