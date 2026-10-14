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
`verifier_id_type` presence, holder-binding flag, ...) are accepted: those
rules belong to wallets, and an implementation that rejects them fails the
suite.
