# go-trust: candidate upstream issues

Status: draft, not yet filed. None of these has been checked against the existing issues in `sirosfoundation/go-trust`. Observed on 2026-11-11 against `sunet-vc-go-trust.fly.dev` (go-trust v0.29.0 in `go.mod`) and the WE BUILD WP4 list of trusted lists.

Context: the [lol](../developer_tools/scripts/lol/main.go) tool fetches the LoTL and reports per-list state. It showed that one of the 13 lists is expired, while go-trust reports the registry as healthy. See [TRUST_COURSE.md](TRUST_COURSE.md) for the background.

## 1. No per-list status endpoint

`GET /readyz?verbose=true` and `GET /registries` return one entry for the whole `webuild-lote` registry:

```json
{"healthy":true,"last_updated":"2026-11-11T12:08:58Z","name":"webuild-lote","resolution_only":true,"resource_types":["jwk","x5c"],"type":"lote"}
```

The registry resolves a LoTL into many lists, but the API does not show which lists were loaded, which were skipped, or why. The only signal is the `lotl_pointers_skipped` count in the refresh log line.

Proposal: expose per-pointer status for LoTE registries, with location, list type, operator, signer subject, `NextUpdate`, state (loaded or skipped), and the skip reason.

## 2. Registry reports healthy while lists are skipped

The Raidiam WRPAC list (`wrpac-providers-lote.json`) had `NextUpdate` 2026-11-06 and was skipped as stale. On 2026-11-11 `/readyz` still returned `ready: true` and `healthy: true`. A skipped list can remove the only trust path for a relying party, and nothing alerts on it.

Proposal: add a degraded state, or a `skipped` count and reasons in the `/readyz?verbose=true` body, and optionally a Prometheus gauge for skipped pointers.

## 3. Verification setup is unclear for per-list signers

`fly/dev/go-trust/config.yaml` states that lists load unverified until go-trust#238 and #239 are fixed. The upstream test `TestWebuildWP4_XMLLoTEsVerify` suggests both are fixed in v0.29.0. This has not been confirmed.

Each pointer target is signed by its own operator, and a LoTL signer anchor does not cover them (see `TestWebuildWP4_VerifiedLoTLPointerNeedsOwnAnchor`). A deployment therefore needs one anchor per list signer in `trust_anchor_bundle`, and there is no published source for that bundle.

Proposal: confirm the status of #238 and #239, and document or publish the anchor bundle for the WE BUILD lists, or support learning list signers from the LoTL pointer entries (`ServiceDigitalIdentities`) with an explicit opt-in.

## 4. `decision: false` has no reason for a skipped list

An `x5c` evaluation that fails returns only `decision: false`. A caller cannot tell "no list covers this chain" from "the covering list was skipped as stale or unverified". The eMRTD registry already returns machine-readable codes in `context.reason.code`.

Proposal: return a reason code from the LoTE registry, for example `no_list`, `list_stale`, `list_unverified`, `chain_invalid`.

## Related gap in this repository

`lol` does not yet verify the XMLDSig signature of the 12 XML lists. go-trust applies strict rules there (one signature, direct child of the root, no SHA-1, `KeyInfo` chain anchored to the bundle), and `lol` should match them before it reports XML lists as verified.
