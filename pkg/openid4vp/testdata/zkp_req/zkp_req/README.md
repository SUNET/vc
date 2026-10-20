# zkp_req planner conformance vectors

One JSON file per case. These are the shared conformance file for every
implementation of the `zkp_req` query planner (Rust here; the Kotlin and Swift
SDKs may reuse them verbatim). Files named `ok_*` must plan; `err_*` must be
rejected. The shape is the `nym_auth` rulebook v0.4's: `_req` items
`{fn_id, return, params}`, `meta.source_format`, `vp_formats_supported.zkp_req`
with `proof_system_values` and `system_id_values`. Spec: `docs/zkp_req_request.md`.

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

- `functions`: `[{function_id, handle, params}]` in request order. `function_id`
  is the item's `fn_id`, `handle` its `return`. `params` is flat: known
  parameters that were present, plus every other parameter unchanged.
- `system_filter`: `{proof_systems?, system_ids?}`; a key is absent when the
  verifier did not state it.
- `source_format`: `meta.source_format`.
- `meta_doctype`, `meta_schema_id`: string or `null`.

`raw` must equal the parsed `query`, unchanged (unknown members survive).

## `expect.error`

A stable code, not message text: `query_not_parseable`, `req_missing_or_empty`,
`item_missing_function_id`, `item_missing_handle`, `param_wrong_type`,
`param_invalid_full_date`, `duplicate_handle`, `claims_present`,
`claim_sets_present`, `req_sets_present`, `invalid_meta`,
`invalid_client_metadata`.

## Scope

The planner judges structure only. `ok_satisfiability_not_judged` and
`ok_ver_large_integer_is_an_integer` pin that well-formed but unsatisfiable
requests plan; the unsatisfiability rules are a separate check with their own
vectors in `../zkp_req_unsat/`. `ok_bbs_cd_source_format` and
`ok_source_format_not_judged` pin that `bbs_cd` (held) and a reserved source
format plan. `ok_verifier_id_type_is_an_extra_param` pins that the retired
`verifier_id_type` is just an undeclared parameter.
