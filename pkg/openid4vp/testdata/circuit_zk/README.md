# circuit_zk planner conformance vectors

One JSON file per case. These are the shared conformance file for every
implementation of the `circuit_zk` query planner (Rust here; the Kotlin and
Swift SDKs may reuse them verbatim). Files named `ok_*` must plan; `err_*`
must be rejected.

```json
{
  "description": "what the case shows",
  "query": { },                    // the Credential Query (one element of dcql_query.credentials)
  "query_text": "{not json",       // instead of `query`: raw text, for unparseable input
  "client_metadata": { },          // optional; or "client_metadata_text" for raw text
  "expect": { "plan": { } }        // or { "error": "<code>" }
}
```

Exactly one of `query` / `query_text`; at most one of `client_metadata` /
`client_metadata_text`. Absent client metadata means `None`.

## `expect.plan`

Compared for exact JSON equality with the planner's output **without `raw`**:

- `functions`: `[{function_id, handle, params}]` in request order. `params` is
  flat: known parameters that were present, plus every other parameter
  unchanged (for example the example shape's `source`).
- `circuit_filter`: `{proof_systems?, circuit_ids?}`; a key is absent when the
  verifier did not state it.
- `meta_doctype`: string or `null`.

`raw` must equal the parsed `query`, unchanged (unknown members survive).

## `expect.error`

A stable code, not message text: `query_not_parseable`,
`req_missing_or_empty`, `req_ambiguous`, `item_missing_function_id`,
`item_missing_handle`, `param_wrong_type`, `param_invalid_full_date`,
`duplicate_handle`, `claims_present`, `claim_sets_present`, `req_sets_present`,
`invalid_meta`, `invalid_client_metadata`.

## Scope

The planner judges structure only. `ok_satisfiability_not_judged` pins that
unsatisfiable-but-well-formed requests (date ordering and span, item counts,
holder-binding flag, ...) are accepted: those
rules belong to wallets, and an implementation that rejects them fails the
suite.

## `verifier_id_type`

The `nym_auth` rulebook no longer carries `verifier_id_type` in the request: how
a verifier is identified (`semantic` or an OpenID4VP client_id_type name) is
agreed in the shared trust framework. The planner still accepts the param and
passes it through as an opaque optional string, so a legacy or deliberately bad
request can be sent. Only `ok_legacy_verifier_id_type_accepted` carries it; the
other vectors show the new request shape. Implementations must not reject it.

## Provenance of the 2026-10 change

Request shape aligned with nym_auth_rulebook PR 5 (tests/vectors only, no
planner behaviour change). Changed or added files, with sha256 of each:

| file | change | old sha256 | new sha256 |
|---|---|---|---|
| `err_duplicate_handle.json` | changed | `2c50082a8bdec3d127d8909733adb244830224fe6e020aa2f5ccc4e7cfd1e127` | `0a94dbb8a02535d4ce657b6cdc747bf58de160d91a2a50a80e645c16da8801ed` |
| `err_example_duplicate_handle.json` | changed | `0311712d0e36d86510c95835681660213b8ab682fda2ebf7bfafca2d461a5d22` | `0811cad0d2d7ff7b22697537cb55aafecb4de3415199a512227b1e2142629cd9` |
| `ok_example_envelope.json` | changed | `a34e07a1072cd679bc257b38f310e6d87782f98d22efffaa7a89610711a9b7f4` | `6df46456fc8db63dc1da1c1707916122be8ed153d78f539cf3d14e9f6613e83f` |
| `ok_normative_plain.json` | changed | `77588003116a4bc7f063eb38e5c8dd4845f00cd776a93498a86e01c75ae7454a` | `1cd414d36529eb92d530ff6754779ed8ca600ce459ffdb33a4ee3acd8ac848e5` |
| `ok_opaque_strings.json` | changed | `681d1699a46b5c9e15c6b57adcad0733253d96a051444c2977575d77b2721479` | `c039c8fd0c129d0f6283b1e08d5775e1c490726b2e39e2162ca5b402ad8c9e3e` |
| `ok_legacy_verifier_id_type_accepted.json` | added | - | `0cd2976e365f69ca9830434e2b89a1fb064f1b1a2a7a82e1410c59103e7b643c` |

`ok_example_envelope.json` and `ok_opaque_strings.json` keep their cases; `ok_opaque_strings` now covers `config` and `verifier_context` only. No other vector changed. The capability vectors (`circuit_capabilities/match.json`) are unchanged: sha256 stays `9bee1868fd957fd4ad56a91dbca93b922ede04bfa57bb0f8b3a3c9bd5f383866`.
