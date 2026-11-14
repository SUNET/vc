# go-trust: candidate upstream issues

Status: draft, not yet filed, except section 5 (filed as [go-trust#253](https://github.com/sirosfoundation/go-trust/issues/253)). Sections 1 to 4 have not been checked against the existing issues in `sirosfoundation/go-trust`. Observed on 2026-11-11 against `sunet-vc-go-trust.fly.dev` and the WE BUILD WP4 list of trusted lists. Fly dev runs `ghcr.io/sirosfoundation/go-trust:latest`; the vendored copy in this repository is go-trust v0.29.2.

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

## 3. No published trust anchor bundle for the WE BUILD lists

go-trust#238 and #239 are closed, and Fly dev now verifies the lists: `fly/dev/go-trust/config.yaml` sets `verify_jws: true` with `trust_anchor_bundle`, and the deployed go-trust logs `signature verified` for the LoTL and 12 lists.

Each pointer target is signed by its own operator, and a LoTL signer anchor does not cover them (see `TestWebuildWP4_VerifiedLoTLPointerNeedsOwnAnchor`). A deployment therefore needs one anchor per list signer in `trust_anchor_bundle`. WP4 does not publish that bundle. Ours was built with `lol -export-anchors` from the LoTL signer taken from the LoTL's own header, so it is trust on first use.

Open: confirm the LoTL signer fingerprint (SHA-256 `33:97:53:D8:AE:D9:B9:9F:EB:C1:3C:C1:5C:87:E1:E8:92:E3:91:A0:DF:FB:1B:D3:AC:82:0D:73:21:9E:38:E1`) with WP4 out of band.

Proposal: WP4 publishes the LoTL signer certificate and its fingerprint, or go-trust can learn list signers from the LoTL pointer entries (`ServiceDigitalIdentities`) with an explicit opt-in.

## 4. `decision: false` has no reason for a skipped list

An `x5c` evaluation that fails returns only `decision: false`. A caller cannot tell "no list covers this chain" from "the covering list was skipped as stale or unverified". The eMRTD registry already returns machine-readable codes in `context.reason.code`.

Proposal: return a reason code from the LoTE registry, for example `no_list`, `list_stale`, `list_unverified`, `chain_invalid`.

## 5. `require_role` does not cover directly listed entities

`registries.lote.require_role` is documented as denying x5c requests that reach the CA-anchored path without a role. A request whose key is directly listed in an entity is not covered: `roleTypes()` returns `nil` for a missing or unmapped action, `typeAllowed(nil, ...)` returns `true`, and the direct match is accepted against every list type.

Reproduced against go-trust 0.29.1 with the Fly config: a directly listed Pub-EAA entity gets `decision: true` for an unmapped action and for no action, and `false` for a mapped action whose list type does not include it.

In this deployment every action vc sends is mapped in `role_scheme_types`, so no vc request is known to reach this.

Proposal: when `require_role` is set, deny a request whose role does not resolve to LoTE types before the direct entity lookup as well.

Not tested: whether `policies.fail_closed_on_unknown_action` closes this for a LoTE-only configuration.
