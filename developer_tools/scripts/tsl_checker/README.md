# tsl_checker

Diagnostic CLI for inspecting a single Token Status List
(draft-ietf-oauth-status-list) entry.

## Usage

```sh
# By URI and index
tsl_checker -idx 42 -uri https://issuer.example/statuslist/1

# From a credential file (SD-JWT VC, JWT, or mdoc)
tsl_checker -credential_file ./credential.sdjwt

# From stdin
cat credential.sdjwt | tsl_checker

# Machine-readable output
tsl_checker -json -idx 0 -uri https://issuer.example/statuslist/1
```

## Exit codes

| Code | Meaning                                    |
| ---- | ------------------------------------------ |
| 0    | Entry is `VALID`                           |
| 1    | Entry is `INVALID`                         |
| 2    | Entry is `SUSPENDED`                       |
| 3    | Entry has some other status byte           |
| 4    | Tool, network, parsing, or fetch error     |
| 5    | Usage / flag error                         |

## Notes

- JWT status list tokens are signature-verified only when the token
  header carries an embedded `jwk`. Otherwise the tool parses the token
  without verification and prints a warning.
- CWT status list tokens are parsed without signature verification.
