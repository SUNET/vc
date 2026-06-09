# jwt_issuer

A simple tool for generating JWTs and JWKS files for testing `api_server.api_auth.jwks` without external JWT infrastructure.

## Build

```bash
make build-jwt-issuer
```

## Release

```bash
make release-jwt-issuer BUMP=patch   # or minor, major
```

## Usage

```bash
# Generate with defaults (token.jwt + jwks.json)
./bin/jwt_issuer

# Custom issuer/audience/subject
./bin/jwt_issuer \
  -issuer "https://my-issuer.example.com" \
  -audience "https://apigw.example.com" \
  -subject "alice@example.com" \
  -eppn "alice@university.edu" \
  -expiry 24h

# Custom output files + export private key
./bin/jwt_issuer \
  -jwt-out my-token.jwt \
  -jwk-out my-jwks.json \
  -priv-out my-private.jwk
```

## Flags

| Flag        | Default                            | Description                          |
|-------------|------------------------------------|--------------------------------------|
| `-version`  | n/a                                | Print version and exit               |
| `-issuer`   | `https://jwt-issuer.example.com`   | JWT `iss` claim                      |
| `-audience` | `https://apigw.example.com`        | JWT `aud` claim                      |
| `-subject`  | `test-user@example.com`            | JWT `sub` claim                      |
| `-email`    | (same as subject)                  | `email` claim                        |
| `-eppn`     | (empty)                            | `eppn` claim (eduPersonPrincipalName)|
| `-expiry`   | `1h`                               | Token expiry duration                |
| `-kid`      | `test-key-1`                       | Key ID in JWKS                       |
| `-jwt-out`  | `token.jwt`                        | Output file for the signed JWT       |
| `-jwk-out`  | `jwks.json`                        | Output file for the JWKS             |
| `-priv-out` | (none)                             | Output file for the private JWK      |

## Example apigw config

Using the generated JWKS file directly (no URL needed):

```yaml
api_server:
  api_auth:
    jwks:
      enable: true
      jwks_file_path: "/path/to/jwks.json"
      issuer: "https://jwt-issuer.example.com"
      audience: "https://apigw.example.com"
```

## Testing a request

```bash
curl -H "Authorization: Bearer $(cat token.jwt)" https://apigw.example.com/api/v1/...
```
