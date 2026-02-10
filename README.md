# VC

A Go-based microservices backend for issuing and verifying digital credentials, originally created within the [DC4EU](https://www.dc4eu.eu/) (Digital Credentials for Europe) project.

The platform implements the OpenID4VCI and OpenID4VP protocols to issue and verify credentials in SD-JWT VC, W3C Verifiable Credentials 2.0, and ISO/IEC 18013-5 mdoc formats.

## Services

| Service    | Description                                                                |
| ---------- | -------------------------------------------------------------------------- |
| **apigw**  | API Gateway with optional SAML and OIDC RP support for relying party integration |
| **issuer** | Issues verifiable credentials via OpenID4VCI with VCTM schema validation  |
| **verifier** | Verifies credential presentations via OpenID4VP, DCQL, and the W3C Digital Credentials API |
| **registry** | Credential registry and status list management                          |
| **mockas** | Mock Authorization Server for development and testing                     |
| **ui**     | Web UI for credential issuance and presentation                           |

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
| mockas           | `make build-mockas`           | Mock Authentication Service |
| ui               | `make build-ui`               | Web UI                      |
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

> **Note:** The `pkcs11` tag requires CGO (`CGO_ENABLED=1`) and produces a dynamically linked binary.

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

## Swagger

### Endpoint

`GET http://<apigw-url>/swagger/doc.json`

or with web browser: `http://<apigw-url>/swagger/index.html`
