# vc_wallet — CLI Manual

`vc_wallet` is a command-line tool for testing OpenID4VCI (credential issuance) and OpenID4VP (credential presentation) flows against a running stack. It wraps the `internal/wallet/apiv1` library into a standalone binary.

## Building

```bash
# Native binary
make build-wallet
# Output: bin/vc_wallet

# Docker image
make docker-build-wallet
# Image: docker.sunet.se/iam_vc/wallet:latest
```

## Usage

```
vc_wallet <command> [flags]

Commands:
  vci    Run an OpenID4VCI credential issuance flow
  vp     Run an OpenID4VP credential presentation flow
  help   Show help
```

---

## `vci` — Credential Issuance

Runs a complete OpenID4VCI flow: metadata discovery → authorization → token → credential request.

```
vc_wallet vci [flags]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-issuer-url` | *(required)* | Issuer base URL (used to fetch `.well-known` metadata) |
| `-credential-offer-uri` | | Credential offer URI to resolve (e.g., from a QR code) |
| `-credential-offer` | | Inline credential offer JSON string |
| `-credential-config-id` | | Credential configuration ID to request |
| `-client-id` | | OAuth2 `client_id` |
| `-redirect-uri` | `http://localhost:8080/callback` | OAuth2 redirect URI |
| `-scope` | | OAuth2 scope to request (e.g., `pid_1_5`) |
| `-use-dpop` | `false` | Use DPoP token binding |
| `-use-par` | `false` | Use Pushed Authorization Requests (PAR) |
| `-pre-authorized-code` | | Pre-authorized code (skips the authorization step) |
| `-tx-code` | | Transaction code for pre-authorized flow |
| `-proof-type` | `jwt` | Proof type: `jwt` or `none` |
| `-send-notification` | `false` | Send notification after credential receipt |
| `-notification-event` | `credential_accepted` | Notification event type |
| `-key-path` | | Path to PEM private key (default: generate ephemeral EC P-256) |
| `-save` | | Save received credential to file (for piping to `vp`) |
| `-v` | `false` | Verbose debug logging |

### Examples

**Pre-authorized code flow:**

```bash
vc_wallet vci \
  -issuer-url http://apigw.vc.docker:8080 \
  -pre-authorized-code "abc123" \
  -credential-config-id "urn:eudi:pid:arf-1.5:1" \
  -v
```

**Authorization code flow with DPoP and PAR:**

```bash
vc_wallet vci \
  -issuer-url http://apigw.vc.docker:8080 \
  -client-id 1003 \
  -scope pid_1_5 \
  -use-dpop \
  -use-par \
  -credential-config-id "urn:eudi:pid:arf-1.5:1" \
  -save /tmp/credential.jwt \
  -v
```

**From a credential offer URI (e.g., scanned QR code):**

```bash
vc_wallet vci \
  -credential-offer-uri "openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22http%3A%2F%2Fapigw.vc.docker%3A8080%22%2C..." \
  -client-id 1003 \
  -save /tmp/credential.jwt \
  -v
```

**From inline credential offer JSON:**

```bash
vc_wallet vci \
  -credential-offer '{"credential_issuer":"http://apigw.vc.docker:8080","credential_configuration_ids":["urn:eudi:pid:arf-1.5:1"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"abc123"}}}' \
  -v
```

---

## `vp` — Credential Presentation

Runs an OpenID4VP flow: fetch request object → build VP token → POST to direct_post endpoint.

```
vc_wallet vp [flags]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-request-uri` | | Request URI to fetch the request object from |
| `-authorization-request-uri` | | Full `openid4vp://` authorization request URI |
| `-credential` | *(required)* | Credential to present — raw string or `@filepath` |
| `-malformed` | `false` | Send a malformed VP token (negative testing) |
| `-wrong-signature` | `false` | Sign the VP with the wrong key (negative testing) |
| `-key-path` | | Path to PEM private key (default: generate ephemeral EC P-256) |
| `-v` | `false` | Verbose debug logging |

### Examples

**Present a credential from file:**

```bash
vc_wallet vp \
  -request-uri "http://verifier.vc.docker:8080/verification/request-object/SESSION_ID" \
  -credential @/tmp/credential.jwt \
  -v
```

**Present from an openid4vp:// URI:**

```bash
vc_wallet vp \
  -authorization-request-uri "openid4vp://?request_uri=http%3A%2F%2Fverifier.vc.docker%3A8080%2Fverification%2Frequest-object%2FSESSION_ID" \
  -credential @/tmp/credential.jwt \
  -v
```

**Negative test — malformed VP token:**

```bash
vc_wallet vp \
  -request-uri "http://verifier.vc.docker:8080/verification/request-object/SESSION_ID" \
  -credential @/tmp/credential.jwt \
  -malformed \
  -v
```

**Negative test — wrong signature:**

```bash
vc_wallet vp \
  -request-uri "http://verifier.vc.docker:8080/verification/request-object/SESSION_ID" \
  -credential @/tmp/credential.jwt \
  -wrong-signature \
  -v
```

---

## End-to-End: Issue then Present

Chain `vci` and `vp` using the `-save` flag:

```bash
# Step 1: Issue a credential and save it
vc_wallet vci \
  -issuer-url http://apigw.vc.docker:8080 \
  -pre-authorized-code "abc123" \
  -credential-config-id "urn:eudi:pid:arf-1.5:1" \
  -save /tmp/credential.jwt

# Step 2: Present it to a verifier
vc_wallet vp \
  -request-uri "http://verifier.vc.docker:8080/verification/request-object/SESSION_ID" \
  -credential @/tmp/credential.jwt
```

---

## Docker Usage

```bash
# Build the image
make docker-build-wallet

# Run VCI flow in Docker
docker run --rm --network vc_vc-dev-net \
  docker.sunet.se/iam_vc/wallet:latest \
  vci -issuer-url http://apigw:8080 -pre-authorized-code "abc123" \
      -credential-config-id "urn:eudi:pid:arf-1.5:1" -v

# Run VP flow in Docker (mount credential file)
docker run --rm --network vc_vc-dev-net \
  -v /tmp/credential.jwt:/cred.jwt \
  docker.sunet.se/iam_vc/wallet:latest \
  vp -request-uri "http://verifier:8080/verification/request-object/SESSION_ID" \
     -credential @/cred.jwt -v
```

---

## Output

Both commands print a JSON result to stdout:

```json
{
  "scenario": "cli-vci",
  "success": true,
  "steps": [ ... ],
  "credentials": [ ... ]
}
```

Logs go to stderr. Use `-v` for debug-level output.

**Exit codes:**
- `0` — flow completed successfully
- `1` — error (details on stderr)

---

## Key Behavior

- **Ephemeral keys**: If `-key-path` is not provided, the tool generates a fresh EC P-256 key pair per invocation.
- **Credential format detection**: Credentials containing `~` are treated as `vc+sd-jwt`; three-part dot-separated strings as `jwt_vc_json`.
- **Credential loading**: The `-credential` flag accepts either a raw string or `@path/to/file` to read from disk.
- **No persistent state**: Each invocation is stateless. Use `-save` and `-credential @file` to pass credentials between commands.
