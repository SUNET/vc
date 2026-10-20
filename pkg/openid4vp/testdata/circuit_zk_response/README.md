# circuit_zk response conformance vectors

One JSON file per case. These are the shared conformance file for every
implementation that validates a `circuit_zk` presentation (Rust here, as
`circuit_zk_response::validate_response`; the Kotlin and Swift SDKs may reuse
them verbatim). Files named `ok_*` must be accepted; `err_*` must be refused
with the stated reason code. The normative text is
[`docs/circuit_zk_response.md`](../../../../../docs/circuit_zk_response.md).

```json
{
  "description": "what the case shows",
  "query": { },                 // the Credential Query the response answers (as in ../circuit_zk)
  "client_metadata": { },       // optional; omitted means the request offered nothing
  "vp_token": { },              // the vp_token object
  "vp_token_text": "{not json", // instead of `vp_token`: raw text (unparseable input, duplicate members)
  "expect": { "valid": true }   // or { "error": "<code>" }
}
```

Duplicate-key vectors (`err_duplicate_handle`, `err_duplicate_member`) use `vp_token_text` with the key literally repeated: a parsed object cannot hold it. Exactly one of `vp_token` / `vp_token_text`. `query` and `client_metadata` are the
request-side inputs of the planner; every vector's request must plan.

## `expect.error`

A stable code, not message text. The first rule broken is reported, in the
order given in the spec's "Order of checks":

`response_not_parseable`, `duplicate_member`, `query_id_missing`, `presentations_not_array`, `presentations_empty`, `presentations_multiple_not_allowed`, `presentation_not_object`, `presentation_error_member`, `presentation_unknown_member`, `presentation_member_missing`, `presentation_member_wrong_type`, `x5chain_not_array`, `circuit_id_not_offered`, `proof_system_not_offered`, `proof_empty`, `proof_not_base64url`, `x5chain_empty`, `x5chain_too_many`, `x5chain_element_not_string`, `x5chain_element_empty`, `x5chain_element_not_base64`, `x5chain_element_too_large`, `duplicate_handle`, `result_handle_unexpected`, `result_handle_missing`, `result_not_object`, `result_function_unknown`, `result_unknown_member`, `result_member_missing`, `result_member_wrong_type`, `result_not_satisfied`, `pseudonym_not_base64url`, `pseudonym_wrong_length`.

## Scope

Structure and the request/response binding only. The proof is not decoded or
verified; `proof` is checked to be non-empty unpadded base64url. `x5chain` is
checked for encoding (padded standard base64) and limits (8 certificates,
4096 decoded bytes each); certificates are not parsed.
