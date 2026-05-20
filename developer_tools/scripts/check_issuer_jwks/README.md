# check_issuer_jwks

CLI tool that validates an OpenID Credential Issuer's JWKS and signed metadata.

## Build

```sh
make build-check-issuer-jwks
```

## Usage

```sh
./bin/check_issuer_jwks [flags] <host-url>
```

### Flags

| Flag         | Description            |
|--------------|------------------------|
| `--no-color` | Disable colored output |

### Example

```sh
./bin/check_issuer_jwks https://issuer.example.com
```

## What it checks

1. Fetches `/.well-known/openid-credential-issuer` metadata
2. Fetches `/jwks` and validates each key (completeness, no private key material)
3. Parses `signed_metadata` JWT from the metadata:
   - Verifies `x5c` header is present
   - Validates certificate chain (issuer/subject linkage, signatures, expiry)
   - Verifies JWT signature using the x5c leaf certificate
   - Confirms the JWKS key (by `kid`) matches the x5c leaf certificate public key

Exits with code 0 on success, 1 if any check fails.
