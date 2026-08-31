# VC

[![Go Reference](https://pkg.go.dev/badge/github.com/SUNET/vc.svg)](https://pkg.go.dev/github.com/SUNET/vc)

A Go-based microservices backend for issuing and verifying digital credentials, originally created within the [DC4EU](https://www.dc4eu.eu/) (Digital Credentials for Europe) project.

The platform implements the OpenID4VCI and OpenID4VP protocols to issue and verify credentials in SD-JWT VC, W3C Verifiable Credentials 2.0, and ISO/IEC 18013-5 mdoc formats.

## Quick Start

```bash
# 1. Generate development PKI certificates
make pki

# 2. Start all services (MongoDB + microservices)
make start

# 3. Verify everything is running
docker compose ps
```

The services will be available on the internal Docker network (`172.16.50.0/24`):

| Service      | Address                          |
| ------------ | -------------------------------- |
| API Gateway  | `http://apigw.vc.docker:8080`    |
| Issuer       | `http://issuer.vc.docker:8080`   |
| Verifier     | `http://verifier.vc.docker:8080` |
| Registry     | `http://registry.vc.docker:8080` |
| MongoDB      | `mongodb://mongo.vc.docker:27017` |

To access a service from the host, use its container IP directly (e.g. `http://172.16.50.2:8080` for apigw) or publish ports in `docker-compose.yaml`.

To stop everything: `make stop`

### Configuration

The main configuration file is `config.yaml`. See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for details.

### Prerequisites

- Docker and Docker Compose
- GNU Make

## Services

| Service    | Description                                                                |
| ---------- | -------------------------------------------------------------------------- |
| **apigw**  | API Gateway with optional SAML and OIDC RP support for relying party integration |
| **issuer** | Issues verifiable credentials via OpenID4VCI with VCTM schema validation  |
| **verifier** | Verifies credential presentations via OpenID4VP, DCQL, and the W3C Digital Credentials API |
| **registry** | Credential registry and status list management                          |

## Architecture

### Credential Verification

A relying party (e.g. Keycloak) connects to the **Verifier** as a standard OIDC Provider.
The Verifier translates the OIDC request into an **OpenID4VP** presentation request toward the wallet.

```text
  ┌────────────┐         OIDC            ┌──────────────────────────┐
  │  Relying   │ ──────────────────────► │        VERIFIER          │
  │  Party     │  authorize, token,      │                          │
  │ (Keycloak) │  userinfo              │  OIDC Provider (OP)      │
  └────────────┘ ◄────────────────────── │  OpenID4VP Verifier      │
                                         └────────────┬─────────────┘
                                                      │
                                                      │ OpenID4VP
                                                      │ (present credential)
                                                      ▼
                                         ┌──────────────────────────┐
                                         │         WALLET           │
                                         │       (phone app)        │
                                         └──────────────────────────┘
```

### Credential Issuance — Two Paths

PID issuance and non-PID issuance follow **different authentication paths**
determined by `auth_method` in the credential configuration.

```text
                           Wallet requests credential
                           via OpenID4VCI (PAR → Authorize)
                                       │
                          ┌────────────┴────────────┐
                          │                         │
                   auth_method: basic        auth_method: openid4vp
                          │                         │
               ┌──────────▼──────────┐   ┌──────────▼───────────────┐
               │  PATH 1: PID        │   │  PATH 2: OTHER           │
               │  (pid)              │   │  (ehic, diploma, pda1,   │
               │                     │   │   elm, eduid, micro...)   │
               │  User authenticates │   │                           │
               │  via external IdP:  │   │  Wallet presents existing │
               │                     │   │  PID credential back to   │
               │  • SAML IdP         │   │  APIGW via OpenID4VP      │
               │  • OIDC Provider    │   │                           │
               │  • Username/Pass    │   │  APIGW verifies PID,      │
               │    (dev/test)       │   │  extracts identity, looks  │
               │                     │   │  up document in datastore  │
               └──────────┬──────────┘   └──────────┬────────────────┘
                          │                         │
                          └────────────┬────────────┘
                                       │
                                       ▼
                          ┌──────────────────────────┐
                          │          APIGW            │
                          │   OAuth AS (OpenID4VCI)   │
                          │   Consent → Token →       │
                          │   Credential              │
                          └─────┬──────────────┬──────┘
                                │ gRPC         │
                                ▼              ▼
                     ┌──────────────┐  ┌──────────────┐
                     │   ISSUER     │  │  REGISTRY    │
                     │              │  │              │
                     │  Signs cred  │  │  Token       │
                     │  (SD-JWT VC, │  │  Status List │
                     │  mdoc,       │  │  (revocation)│
                     │  W3C VC)     │  │              │
                     └──────────────┘  └──────────────┘
```

### Full System Overview

```text
                                                                ┌────────────┐
                                                                │ SAML IdP / │
  ┌────────────┐                                                │ OIDC IdP   │
  │  Relying   │                                                │ (external) │
  │  Party     │                                                └──────┬─────┘
  │ (Keycloak) │                                                       │
  └─────┬──────┘                                   SAML / OIDC RP      │
        │ OIDC                                     (PID issuance auth) │
        ▼                                                              │
  ┌──────────────────┐        OpenID4VP         ┌──────────────┐       │
  │    VERIFIER      │ ◄─────────────────────── │              │       │
  │                  │   (present credential)   │              │       │
  │  OIDC Provider   │ ───────────────────────► │    WALLET    │       │
  │  OpenID4VP       │   (request presentation) │  (phone app) │       │
  └──────────────────┘                          │              │       │
                                                │              │       │
                 OpenID4VCI                      │              │       │
                 (receive new credential)        │              │       │
          ┌──────────────────────────────────────┤              │       │
          │      OpenID4VP                       │              │       │
          │      (present PID for non-PID issue) │              │       │
          │  ┌───────────────────────────────────┤              │       │
          │  │                                   └──────────────┘       │
          ▼  ▼                                                         │
  ┌────────────────────────────────────────────────────────────────┐    │
  │                           APIGW                                │    │
  │                                                                │◄───┘
  │  OAuth AS (OpenID4VCI)   — issue credentials to wallet         │
  │  OpenID4VP Verifier      — verify PID before non-PID issuance  │
  │  SAML SP (optional)      — authenticate for PID issuance       │
  │  OIDC RP (optional)      — authenticate for PID issuance       │
  └──────────┬──────────────────────────────┬──────────────────────┘
             │ gRPC                         │
             ▼                              ▼
  ┌──────────────────┐           ┌──────────────────┐
  │     ISSUER       │           │    REGISTRY      │
  │  Signs creds     │           │  Token Status    │
  │  (SD-JWT VC,     │           │  List            │
  │   mdoc, W3C VC)  │           │  (revocation)    │
  └──────────────────┘           └──────────────────┘

  ┌──────────────────┐           ┌──────────────────┐
  │       UI         │           │    MOCK AS       │
  │  Admin web       │──────────►│  Test users &    │
  │  interface       │           │  bootstrapping   │
  └──────────────────┘           └──────────────────┘
```

| Component    | Server Role                               | Client Role                                           |
| ------------ | ----------------------------------------- | ----------------------------------------------------- |
| **Verifier** | OIDC Provider (OP) toward relying parties  | OpenID4VP verifier toward wallets                     |
| **APIGW**    | OAuth AS (OpenID4VCI) toward wallets       | SAML SP + OIDC RP toward external IdPs (PID issuance) |
|              | OpenID4VP verifier (non-PID issuance auth) |                                                       |
| **Issuer**   | gRPC credential signing service            | —                                                     |
| **Registry** | Token Status List (revocation)             | —                                                     |

## Capabilities

- Issue verifiable credentials via [OpenID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- Verify credential presentations via [OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) with `direct_post` response mode
- [SD-JWT VC](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/) ([draft-ietf-oauth-sd-jwt-vc-13](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/13/)), [W3C Verifiable Credentials 2.0](https://www.w3.org/TR/vc-data-model-2.0/), and [ISO/IEC 18013-5](https://www.iso.org/standard/69084.html) mdoc credential formats
- Browser-native credential presentation via the [W3C Digital Credentials API](https://wicg.github.io/digital-credentials/) (`navigator.credentials.get()`)
- [DCQL](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-digital-credentials-query-l) (Digital Credentials Query Language) for flexible presentation requests
- Credential revocation via [Token Status List](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/) ([draft-ietf-oauth-status-list](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/)) with JWT ([RFC 7519](https://www.rfc-editor.org/rfc/rfc7519)) and CWT ([RFC 8392](https://www.rfc-editor.org/rfc/rfc8392)) formats
- VCTM schema validation before credential issuance ([draft-ietf-oauth-sd-jwt-vc-13 §6](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/13/))
- PKCS#11 / HSM support for hardware-backed key protection
- [SAML 2.0](https://docs.oasis-open.org/security/saml/v2.0/), [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html), and [OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749) Relying Party authentication with [PKCE](https://www.rfc-editor.org/rfc/rfc7636) ([RFC 7636](https://www.rfc-editor.org/rfc/rfc7636)), [DPoP](https://www.rfc-editor.org/rfc/rfc9449) ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)), and [JAR](https://datatracker.ietf.org/doc/html/rfc9101) ([RFC 9101](https://datatracker.ietf.org/doc/html/rfc9101))
- gRPC inter-service communication
- Kafka-based message brokering
- MongoDB storage backend
- OpenTelemetry distributed tracing
- Static Linux/amd64 binaries for containerized deployment

## Verifier Dynamic Client Registration Authorization

The verifier exposes OAuth 2.0 Dynamic Client Registration at `POST /register`.
You can protect this endpoint with an initial access token policy.

Supported modes:

- `open` (default): registration is open (rate-limited)
- `static`: requires a fixed bearer token loaded from local file
- `jwt`: requires a signed JWT bearer token validated with configured `issuer`, `audience`, and `jwks_uri`

Example (`config.yaml`):

```yaml
verifier:
      oidc:
            dynamic_registration_auth:
                  mode: "static"
                  static_bearer_token_file: "/run/secrets/verifier_dcr_initial_access_token"
```

```yaml
verifier:
      oidc:
            dynamic_registration_auth:
                  mode: "jwt"
                  jwt:
                        jwks_uri: "https://auth.example.com/.well-known/jwks.json"
                        issuer: "https://auth.example.com"
                        audience: "vc-verifier-register"
                        allowed_signing_algs: ["RS256", "ES256"]
                        clock_skew_seconds: 60
```

Note: `introspection` is reserved for future implementation and is not enabled yet.

## Docker release version

`latest` tracks the latest tag available and is built from branch `main`.

## Branches

`main` is the stable development branch.

## How to build

### Build targets

| Service          | Command                       | Description                 |
| ---------------- | ----------------------------- | --------------------------- |
| All              | `make build`                  | Build all services          |
| apigw            | `make build-apigw`            | API Gateway                 |
| issuer           | `make build-issuer`           | Credential Issuer           |
| verifier         | `make build-verifier`         | Credential Verifier         |
| registry         | `make build-registry`         | Registry                    |
| vc20-test-server | `make build-vc20-test-server` | W3C VC 2.0 test server      |

All standard builds produce static binaries (`CGO_ENABLED=0`) for `linux/amd64`. Output goes to `./bin/`.

### Build tags

Optional features are enabled via Go build tags. The following tags are available:

| Tag           | Description                    | Affected service(s) | CGO         | Make target                   |
| ------------- | ------------------------------ | ------------------- | ----------- | ----------------------------- |
| `saml`        | SAML IdP support               | apigw               | static      | `make build-apigw-saml`       |
| `oidcrp`      | OpenID Connect Relying Party   | apigw               | static      | `make build-apigw-oidcrp`     |
| `saml,oidcrp` | All optional apigw features    | apigw               | static      | `make build-apigw-all`        |
| `pkcs11`      | PKCS#11 HSM signing            | issuer              | **dynamic** | `make build-issuer-hsm`       |
| `vc20`        | W3C Verifiable Credentials 2.0 | vc20-test-server    | static      | `make build-vc20-test-server` |
| `zknative`    | Native ZK/PPID proof verification (mso_mdoc_zk) | verifier | **dynamic** | `make build-verifier-zknative` |

> **Note:** The `pkcs11` and `zknative` tags require CGO (`CGO_ENABLED=1`) and produce dynamically linked binaries. See "Native ZK/PPID proof verification" below for `zknative` setup.

### Docker

For convenience all services can be built inside a Docker container.

| Command                          | Description                                 |
| -------------------------------- | ------------------------------------------- |
| `make docker-build`              | Build all Docker images                     |
| `make docker-build-<service>`    | Build a specific service image              |
| `make docker-build-apigw-saml`   | apigw image with SAML support               |
| `make docker-build-apigw-oidcrp` | apigw image with OIDC RP support            |
| `make docker-build-apigw-all`    | apigw image with all features               |
| `make docker-build-issuer-hsm`   | issuer image with PKCS#11 HSM support       |
| `make docker-push`               | Push all standard images to registry        |
| `make docker-push-apigw-saml`    | Push apigw SAML image                       |
| `make docker-push-apigw-oidcrp`  | Push apigw OIDC RP image                    |
| `make docker-push-apigw-all`     | Push apigw all-features image               |
| `make docker-push-issuer-hsm`    | Push issuer HSM image                       |
| `make docker-tag`                | Tag all images                              |

Set the image version with `VERSION=x.x.x` (default: `latest`).

### Native ZK/PPID proof verification

vc-verifier can verify "mso_mdoc_zk" presentations (zero-knowledge
Longfellow proof-of-possession, with an optional pairwise pseudonym over an
mdoc credential) natively, via a cgo binding to
[zk-cred-longfellow](https://github.com/sirosfoundation/zk-cred-longfellow)'s
plain C-ABI Go verifier build. This is **opt-in** (the `zknative` build
tag) - the default `make build-verifier`/Docker build stays
`CGO_ENABLED=0` and fully static, exactly like the `pkcs11` tag above, and
for the same reason: cgo requires a C compiler/linker and a locally built
shared library that a static build has no use for.

Setup:

```sh
# 1. Clone + build zk-cred-longfellow's `go-cabi` target, staging the
#    resulting shared library + header under third_party/zk-cred-longfellow/
#    (gitignored - never committed). Override ZK_CRED_LONGFELLOW_REPO/_REF
#    to build a fork or pin a specific tag, branch, OR commit SHA - the
#    target fetches whichever ref is given directly (`git fetch --depth 1
#    origin $(REF)`), which works for all three ref types.
make zk-native-lib

# 2. Build the verifier with native ZK/PPID verification.
make build-verifier-zknative

# 3. Run it (needs the shared library on the loader path).
LD_LIBRARY_PATH=$(pwd)/third_party/zk-cred-longfellow/lib ./bin/vc_verifier-zknative

# ...or run pkg/mdoc's zknative-tagged tests directly:
make test-zknative
```

Configuration: the circuit catalog service vc-verifier fetches circuits
from is configurable via `verifier.zk_circuits.sources` in YAML config
(defaults to the live `https://zk-circuits.fly.dev` service if unset) -
see `docs/CONFIGURATION.md`'s `zk_circuits` section.

See `docs/ZK_PPID_VERIFICATION_PLAN.md` for the full design writeup: what
this verifies, the confirmed `verifier_context`/pseudonym-derivation wire
formula, and exactly what's still out of scope (the W3C Digital
Credentials API and older OpenID4VP session-transcript variants).

## Start, Stop & Restart

| Command          | Description                                 |
| ---------------- | ------------------------------------------- |
| `make start`     | Start all services via docker-compose       |
| `make stop`      | Stop all services                           |
| `make restart`   | Restart all services                        |
| `make pki`       | Generate PKI infrastructure                 |
| `make pki-clean` | Remove PKI material                         |

## Testing

| Command              | Description                                                   |
| -------------------- | ------------------------------------------------------------- |
| `make test`          | Run all service tests                                         |
| `make test-saml`     | Test with `saml` build tag                                    |
| `make test-oidcrp`   | Test with `oidcrp` build tag                                  |
| `make test-vc20`     | Test with `vc20` build tag                                    |
| `make test-pkcs11`   | Test with `pkcs11` build tag (requires `make test-env`)       |
| `make test-zknative` | Test with `zknative` build tag (requires `make zk-native-lib`) |
| `make test-all-tags` | Test with all build tags                                      |
| `make test-env`      | Install test dependencies (softhsm2, opensc)                  |

## Development Tools

| Command              | Description                               |
| -------------------- | ----------------------------------------- |
| `make install-tools` | Install protoc, swag, and Go gRPC plugins |
| `make vscode`        | Full VS Code dev environment setup        |
| `make proto`         | Regenerate protobuf files                 |
| `make swagger`       | Regenerate Swagger documentation          |
| `make gosec`         | Run security scanner                      |
| `make staticcheck`   | Run static analysis                       |
| `make vulncheck`     | Run vulnerability checker                 |

## Supported Signature Types

### SD-JWT VC (`dc+sd-jwt`)

The signing algorithm is auto-detected from the loaded key (`pkg/pki/keyloader.go`):

| Key Type | Curve / Size | Algorithm |
| -------- | ------------ | --------- |
| ECDSA    | P-256        | ES256     |
| ECDSA    | P-384        | ES384     |
| ECDSA    | P-521        | ES512     |
| RSA      | < 3072 bits  | RS256     |
| RSA      | >= 3072 bits | RS384     |
| RSA      | >= 4096 bits | RS512     |

### mDOC (`mso_mdoc`)

Uses COSE algorithm identifiers (`pkg/mdoc/cose.go`):

| COSE ID | Algorithm |
| ------- | --------- |
| -7      | ES256     |
| -35     | ES384     |
| -36     | ES512     |
| -8      | EdDSA     |

### Key Sources

- **Software keys**: PEM files (PKCS#8, SEC1/EC, PKCS#1/RSA)
- **Hardware keys**: HSM via PKCS#11 (requires `pkcs11` build tag)

ECDSA signatures use IEEE P1363 format (fixed-size R||S) per JWT RFC 7518. RSA signatures use PKCS#1 v1.5.

### Metadata

The issuer advertises supported algorithms via:
- `/.well-known/jwt-vc-issuer`
- `/.well-known/openid-configuration`

Default configured algorithms: `["ES256", "ES384"]`. See `config.yaml` under `apigw.issuer_metadata.credential_signing_alg_values_supported`.

## Swagger

### Endpoint

`GET http://<apigw-url>/swagger/doc.json`

or with web browser: `http://<apigw-url>/swagger/index.html`
