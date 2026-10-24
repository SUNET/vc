# proof_time vectors

`proof_time.json`: epoch seconds to the exact 20-byte `YYYY-MM-DDThh:mm:ssZ`
form (epoch, year boundaries, leap days, 2100, 9999-12-31), the refusals of
the parser, and the verifier tolerance check (recommended skew 60 s, age
600 s; both configurable). Spec: `docs/zkp_req_response.md`, "proof_time".
Texts were computed independently of the Rust code.
