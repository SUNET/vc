# Wire-format extension: `digestId` on `zkDocuments` issuer-/device-signed items

**Status: implemented in siros-sdk-kotlin (wallet, producer) and this repo
(verifier, consumer). NOT yet proposed upstream to multipaz. Flagging this
document explicitly so it gets raised in the appropriate cross-org
collaboration before/alongside any interop testing against a
non-SIROS-Foundation `zkDocuments` implementation.**

## What changed

`multipaz`'s `zkDocuments` extension to the ISO 18013-5 `DeviceResponse`
(itself pre-standardization - see `ZK_PPID_VERIFICATION_PLAN.md`'s
"Background" section, and the `balfanz/multipaz` `ppid` branch this org has
previously interop-tested against and sent fixes to) represents each
disclosed issuer-signed/device-signed element as:

```
{ "elementIdentifier": tstr, "elementValue": any }
```

This org's implementation (siros-sdk-kotlin's `MdocDeviceResponseBuilder
.buildZkDeviceResponse`, `vc`'s `pkg/mdoc.ZkSignedItemMdoc`) now ADDS an
**optional** third field:

```
{ "elementIdentifier": tstr, "elementValue": any, "digestId": uint / omitted }
```

`digestId` is the credential's own real ISO 18013-5 `IssuerSignedItem
.digestID` for that element (an existing per-item field on the *original*,
un-ZK-wrapped mdoc structure - not something invented for this). It is
`omitempty` on both the CBOR wire and the Go struct field - a verifier that
doesn't know about it (including multipaz's own reference verifier, and
any other unmodified consumer of the pre-existing format) simply never
sees the key, exactly as if this change didn't exist. A plain "mso_mdoc"
`DeviceResponse` and every existing Longfellow-based `zkDocuments`
presentation are both unaffected.

## Why

The existing `zkDocuments` format (and this org's own Longfellow
integration) never needed a claim's `digestID` on the wire: Longfellow's
verifier matches disclosed attributes to circuit slots **by position**,
and the position is derived from the verifier's own request order (see
`vc`'s `ZkPresentationContext.RequestedClaimIDs` doc comment) - a value
both sides already agree on independently, so nothing extra needs to cross
the wire.

Vega (`zk-cred-vega`, a second, general-purpose ZK circuit backend this
org is integrating alongside Longfellow - see
`~/.claude/plans/dreamy-frolicking-chipmunk.md`) does not share that
property. Its circuit has a fixed number of claim slots, but slot
assignment is the **credential's own document order** (stable per
credential, independent of which claims a given presentation discloses -
see `VegaProofSystem.buildWitness`'s doc comment in siros-sdk-kotlin), not
the verifier's request order. A verifier has no independent way to know
which of the circuit's fixed slots corresponds to which requested claim
identifier - the proof itself reports each slot's `digestID` back
(`zk-cred-vega`'s own `DisclosedClaim.digest_id`), and the verifier needs
*something* on the wire, tagged with that same `digestID`, to check the
proof's disclosed plaintext against. That's what this field is for.

## Compatibility / rollout

- **Additive and optional** - no version bump, no breaking change to the
  existing format for any consumer that ignores unknown map keys (CBOR's
  normal decode behavior, and Go's own `cbor:",omitempty"` tag here).
- Currently produced only by siros-sdk-kotlin. **siros-sdk-swift does not
  yet emit `digestId`** - a real parity gap for Vega presentations from an
  iOS wallet (Longfellow presentations are unaffected either way, since
  they never consult this field). Track this alongside the rest of the
  siros-sdk-swift Vega work.
- Consumed only by this repo (`vc`)'s Vega verification path
  (`pkg/mdoc/zk_verifier.go`'s Vega dispatch branch). No other verifier
  (including the third-party multipaz-based one this org has
  interop-tested against, `siros-multipaz-verifier.fly.dev`) reads it.

## What needs to happen before wider interop

This is exactly the kind of change that's easy to get away with unilaterally
inside one org's own wallet+verifier pair, and easy to silently diverge on
if a second implementer (multipaz itself, or any other `zkDocuments`
consumer) later adds its own answer to the same "how does a
non-positionally-matched ZK system's verifier know which slot is which"
question, incompatibly. Before this is relied on for any interop testing
against a party outside this org:

1. Raise it with whoever this org coordinates with on the `balfanz/multipaz`
   `ppid` branch (the existing channel used for prior ZK/PPID fixes sent
   upstream - see `ZK_PPID_VERIFICATION_PLAN.md` and this org's prior PRs
   there) - as a proposed addition to the shared wire format, not a
   unilateral extension.
2. Confirm whether multipaz's own format already has (or is planning) an
   equivalent field under a different name, to avoid two incompatible
   answers to the same problem.
3. Once/if agreed upstream, drop the "not yet proposed upstream" caveat at
   the top of this document and fold the confirmed shape into
   `ZK_PPID_VERIFICATION_PLAN.md` proper instead of keeping it as a
   separate flagged document.
