# zkp_req unsatisfiable-request vectors

The rulebook v0.4 rules by which a well-formed `zkp_req` request is
unsatisfiable, decided from the request alone (`zkp_req::unsatisfiable`).
Spec: `docs/zkp_req_request.md`. Every query here plans; `expect` is
`{"satisfiable": true}` (file `ok_*`) or `{"error": "<code>"}` (file `err_*`),
the first rule broken. A request that passes is not thereby served: which
configurations a system supports is its registry entry's say, not these rules.

```json
{ "description": "...", "query": { }, "expect": { "satisfiable": true } }
```
