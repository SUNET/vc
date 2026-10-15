# EC TS12 payment SCA in the verifier

The standalone verifier can drive a payment Strong Customer Authentication
test against an EUDI wallet (EC TS12 v1.0.1, `urn:eudi:sca:payment:1`).

## Enable

```yaml
verifier:
  ts12:
    enable: true                      # default false
    sca_vct_values:                   # optional: pre-fills the test page
      - "https://psp.example/sca-attestation"
    hash_algs: ["sha-256"]            # optional; sent as transaction_data_hashes_alg
```

`enable` turns on the `payment` member of `POST /ui/interaction` and the test
page. Anyone who can reach `/ui/interaction` can then start a payment request,
so use it on test and PSP verifiers, not on a general-purpose one.

## Start a payment request

Browser: open `https://<verifier>/payment`, fill in amount, currency, payee
and the SCA attestation's `vct`, and scan the QR code (or follow the link) with
the wallet. The page waits for the wallet and shows whether the response was
accepted.

Without a browser:

```sh
curl -s https://<verifier>/ui/interaction -H 'Content-Type: application/json' -d '{
  "dcql_query": {"credentials": [{"id": "sca", "format": "dc+sd-jwt",
                 "meta": {"vct_values": ["https://psp.example/sca-attestation"]}}]},
  "payment": {"amount": "49.99", "currency": "EUR",
              "payee_name": "Shop AB", "payee_id": "SE1234567890",
              "credential_id": "sca"}
}'
# -> {"session_id": ..., "authorization_request": "openid4vp://...", "qr_code": "<base64 png>"}
curl -s "https://<verifier>/ui/completion?session_id=<id>"   # {"status":"pending"} | {"status":"complete","response_code":...}
curl -s "https://<verifier>/ui/result?response_code=<code>"   # the accepted presentation's claims
```

`credential_id` may be omitted when the DCQL query has a single credential
query. `transaction_id` defaults to a fresh UUID. The credential query must be
`dc+sd-jwt` with holder binding (TS12 v1.0.1 covers SD-JWT VC only).

## What is checked on the response

For each credential query a `transaction_data` entry references: the KB-JWT
`transaction_data_hashes` (over the strings as sent, in request order, with a
`transaction_data_hashes_alg` the request allowed), `nonce`, `aud`, `iat`,
`sd_hash`, and for TS12 types `amr` (>= 2 different categories, TS12
vocabulary), `response_mode` (one the request was issued with) and `jti`
(present, never seen before). Anything that cannot be checked is refused with
`invalid_transaction_data`; a refused response leaves the page waiting, and the
reason is in the verifier log.
