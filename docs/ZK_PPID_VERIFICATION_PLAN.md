# ZK/PPID Presentation Verification Plan

**Status: Plumbing implemented, native ZK verification NOT implemented.**

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
   fields (plus `DoctypeValue`, which it was silently dropping already - a
   pre-existing gap this format would otherwise have hit immediately).

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

## What's stubbed (plumbing exists, native call doesn't)

`nativeVerifyZkProof` / `nativeVerifyZkProofWithPPID` in
`pkg/mdoc/zk_verifier.go` always return `ErrNativeZkVerifyNotImplemented`.
Every check listed above runs for real first - a malformed/untrusted/
mismatched presentation is rejected for that specific reason, and only a
presentation that would otherwise fully validate reaches this error. Tests
(`TestZkHandler_VerifyAndExtract_ReachesNativeStub`,
`..._PPIDPath`) confirm this precisely: they assert the returned error `Is`
`ErrNativeZkVerifyNotImplemented`, not some other failure.

## What's missing: a native Longfellow ZK verifier binding for Go

This is the real, substantial remaining gap. `zk-cred-longfellow`
(`~/work/siros.org/zk-cred-longfellow`) is a Rust crate exposing, via
UniFFI (`src/ffi_api.rs`, feature `uniffi`):

```rust
fn initialize_verifier(circuit: &[u8], circuit_version: CircuitVersion, num_attributes: u8) -> Result<MdocZkVerifier, MdocZkError>
fn verify(verifier: &MdocZkVerifier, issuer_public_key_sec_1: &[u8], attributes: &[Attribute], doc_type: &str, device_name_spaces_bytes: &[u8], session_transcript: &[u8], time: &str, proof: &[u8]) -> Result<(), MdocZkError>
fn verify_with_ppid(verifier: &MdocZkVerifier, ..., verifier_context: &[u8], proof: &[u8]) -> Result<(), MdocZkError>
```

(`Attribute { identifier: String, value_cbor: Vec<u8> }`, `MdocZkVerifier` a
`uniffi::Object`.) This is exactly the API `pkg/mdoc/zk_verifier.go`'s stub
functions are shaped to call once a binding exists - `zkSystemID`'s
version/num_attributes would resolve which circuit to load via
`initialize_verifier` (with caching across calls, since circuit loading is
expensive - `MdocZkVerifier` should be held, not reconstructed per call).

### Why there's no Go binding today

1. **UniFFI itself doesn't target Go as a first-class language.** The crate
   generates Swift and Kotlin bindings (`make bindings` in the crate's
   Makefile) via UniFFI's own `uniffi-bindgen` machinery. There is no
   official `uniffi-bindgen-go` from Mozilla; third-party Go generators for
   UniFFI exist in the wider ecosystem but are not wired into this crate,
   and adding one is a non-trivial integration project of its own (new
   generator dependency, Go binding template/codegen wiring, CI, testing) -
   explicitly out of scope for this change per the task that produced it.

2. **The raw UniFFI FFI is not a "plain C API" you can bind via cgo
   directly.** Every `#[uniffi::export]`\-generated `extern "C"` function
   (see `bindings/swift/zk_cred_longfellowFFI.h`, UniFFI's own generated C
   header used to compile the Swift/Kotlin scaffolding) takes/returns
   `RustBuffer` (a length-prefixed byte buffer) and an out `RustCallStatus`,
   not idiomatic C types. Complex arguments (`&[Attribute]`, `Option<&[u8;
   32]>`, the `MdocZkVerifier` opaque object) are serialized using UniFFI's
   own internal wire protocol - reimplementing that protocol by hand in cgo
   (to avoid needing a real code generator) means matching an
   internal-and-versioned serialization format not intended for direct
   consumption, for every argument/return type these functions use. That is
   real, error-prone, multi-day work - not something to half-implement.

3. **A narrower, already-started alternative exists in the crate, but it's
   incomplete and not general-purpose.** `zk-cred-longfellow/src/mdoc_zk/prover.rs`
   already has a plain (non-UniFFI) `#[unsafe(no_mangle)] pub extern "C" fn
   rust_verify_with_ppid(...)`, explicitly commented `"C FFI for Go CGo
   verifier"`. This does NOT go through UniFFI's RustBuffer wire format -
   it's a genuine, cgo-callable C ABI function, and the crate's `mdoc_zk`
   module (where it lives) is NOT gated behind the `uniffi` Cargo feature, so
   `cargo build --release` (default features) already produces a
   cdylib/staticlib exporting it as a plain C symbol. However, as it stands
   today it is:
   - **Hardcoded to V8 circuits and exactly 2 fixed attributes**
     (`given_name` + `pairwise_pseudonym`) - not general purpose.
   - **Hardcoded to an empty `device_name_spaces_bytes`** (`b"\xa0"`) -
     can't verify a document with any device-signed elements.
   - **Reloads/recompiles the circuit on every single call** (it calls
     `MdocZkVerifier::new(...)` inline rather than taking an already-
     initialized verifier handle) - circuit loading is expensive; this is
     fine for a quick fuzz/test harness, wrong for a real verifier service
     handling many presentations.
   - **Not referenced from anywhere** - no Go file, build target, or header
     exists for it anywhere in `zk-cred-longfellow` or this repo. It reads
     as a starting marker/scratch stub, not a maintained entry point.
   - Returns only an `i32` status code (0 / -1), losing the underlying
     `anyhow::Error` detail `verify`/`verify_with_ppid` provide via
     `MdocZkError`'s `Display`.

   Generalizing this into something a real Go verifier could depend on -
   splitting circuit load from verify (with caching), accepting a variable
   attribute list from Go instead of two hardcoded slots, real
   `device_name_spaces_bytes`, richer error reporting, a Makefile target
   that builds this specific C ABI export + a hand-written (not
   UniFFI-generated) header, and testing on whatever platform(s)
   vc-verifier actually deploys to - is real, scoped, and worth doing, but
   is Rust-crate work in `zk-cred-longfellow`, a several-hour-to-multi-day
   effort in its own right, and was assessed as too large to prototype
   safely within this change's time budget (per this task's own scope
   discipline: don't half-implement unsafe FFI code). It is the
   recommended path forward - not building a Go UniFFI binding from scratch.

### Recommended next step

Generalize `rust_verify_with_ppid` (or add sibling `rust_initialize_verifier`
/ `rust_verify` / `rust_free_verifier` functions alongside it) in
`zk-cred-longfellow/src/mdoc_zk/prover.rs`, gated the same way (plain
`extern "C"`, NOT behind the `uniffi` feature), to:

1. Split circuit loading (`rust_initialize_verifier(circuit, circuit_len,
   circuit_version, num_attributes) -> *mut MdocZkVerifier` + a matching
   `rust_free_verifier`) from verification, so a long-lived Go process
   loads each distinct circuit once.
2. Accept a real variable-length attribute array (identifier + CBOR value
   pairs) from Go instead of the two hardcoded slots.
3. Accept a real `device_name_spaces_bytes` byte slice.
4. Return an owned, caller-freed error string (or write into a
   caller-provided buffer) instead of just an `i32`.
5. Add a Makefile target building this specific export (default features,
   no `uniffi`) plus a small hand-written header (NOT the UniFFI-generated
   one, which describes a different, RustBuffer-based ABI) - this is the
   "plain C-compatible shared library build target" item 4 of this task
   asked to prototype if tractable; per the above, it is tractable **only
   once the underlying Rust functions are generalized** - the build-tooling
   part alone (Makefile target + header) is a small addition, but wiring it
   to functions that are still 2-attribute/V8-only/no-device-namespaces
   would just move the "not general purpose" problem into Go instead of
   fixing it, so it wasn't added as tooling alone in this change.

Once that exists, `pkg/mdoc/zk_verifier.go`'s `nativeVerifyZkProof` /
`nativeVerifyZkProofWithPPID` become real cgo calls; everything upstream of
them (trust evaluation, zk_system_type matching, argument assembly,
verifier_context derivation) already produces exactly the values those
calls would need.

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
