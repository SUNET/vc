# Configuration Reference

**Generated:** 2026-02-13

Complete reference for all configuration parameters in the VC system.

<!-- Auto-generated from Go source code. DO NOT EDIT MANUALLY. -->
<!-- Regenerate with: go run developer_tools/scripts/gen_config_docs/main.go -->

## Table of Contents

- [Common](#common-top-level)
- [Authentication Methods](#auth_methods-top-level)
- [API Gateway (APIGW)](#apigw-top-level)
- [Issuer](#issuer-top-level)
- [Verifier](#verifier-top-level)
- [Registry](#registry-top-level)
- [Mock AS](#mock_as-top-level)
- [UI](#ui-top-level)
- [Credential Constructor](#credential_constructor-top-level)
- [Secrets File Reference](#secrets-file-reference)

## `common` (Top-level)

Shared configuration used across all services.

### `common`

> **Path:** `.common`

| Field                 | Type     | Description                                                                                                                                                      | Example                  | Default | Required |
| --------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------ | ------- | -------- |
| `production`          | `bool`   | Production mode                                                                                                                                                  | -                        | `true`  | No       |
| `log`                 | `object` | Logging configuration                                                                                                                                            | -                        | -       | No       |
| `mongo`               | `object` | MongoDB configuration                                                                                                                                            | -                        | -       | No       |
| `tracing`             | `object` | OpenTelemetry tracing configuration                                                                                                                              | -                        | -       | No       |
| `kafka`               | `object` | Kafka message broker configuration                                                                                                                               | -                        | -       | No       |
| `credential_offer_qr` | `object` | Credential offer QR code settings                                                                                                                                | -                        | -       | No       |
| `secret_file_path`    | `string` | Path to a separate YAML file containing secrets; when set, secret values in config.yaml are cleared and only non-empty fields from the secrets file are applied. | `"/etc/vc/secrets.yaml"` | -       | No       |
| `ha`                  | `bool`   | High-availability mode. When true, caches use MongoDB (Common.Mongo.URI)                                                                                         | -                        | `false` | No       |

### `log`

> **Path:** `.common.log`

| Field         | Type     | Description            | Example         | Default | Required |
| ------------- | -------- | ---------------------- | --------------- | ------- | -------- |
| `folder_path` | `string` | Path to the log folder | `"/var/log/vc"` | -       | No       |

### `mongo`

> **Path:** `.common.mongo`

| Field | Type     | Description            | Example                                    | Default | Required |
| ----- | -------- | ---------------------- | ------------------------------------------ | ------- | -------- |
| `uri` | `string` | MongoDB connection URI | `"mongodb://user:password@mongo:27017/vc"` | -       | Yes      |

### `tracing`

> **Path:** `.common.tracing`

| Field     | Type     | Description                            | Example         | Default | Required               |
| --------- | -------- | -------------------------------------- | --------------- | ------- | ---------------------- |
| `enable`  | `bool`   | Enable activates OpenTelemetry tracing | -               | `false` | No                     |
| `addr`    | `string` | OTEL collector address                 | `"jaeger:4318"` | -       | Yes (if enable = true) |
| `timeout` | `int64`  | Timeout in seconds                     | -               | `10`    | No                     |

### `kafka`

> **Path:** `.common.kafka`

| Field     | Type       | Description                    | Example | Default                          | Required |
| --------- | ---------- | ------------------------------ | ------- | -------------------------------- | -------- |
| `enabled` | `bool`     | Kafka integration              | -       | `false`                          | No       |
| `brokers` | `[]string` | List of Kafka broker addresses | -       | `["kafka0:9092", "kafka1:9092"]` | No       |

### `credential_offer_qr`

> **Path:** `.common.credential_offer_qr`

| Field  | Type     | Description                                                         | Example | Default            | Required |
| ------ | -------- | ------------------------------------------------------------------- | ------- | ------------------ | -------- |
| `type` | `string` | Credential offer type: "credential_offer" or "credential_offer_uri" | -       | `credential_offer` | No       |
| `qr`   | `object` | QR code generation settings                                         | -       | -                  | No       |

### `qr`

> **Path:** `.common.credential_offer_qr.qr`

| Field            | Type  | Description                  | Example | Default | Required |
| ---------------- | ----- | ---------------------------- | ------- | ------- | -------- |
| `recovery_level` | `int` | Error correction level (0-3) | -       | `2`     | No       |
| `size`           | `int` | QR code size in pixels       | -       | `256`   | No       |

## `auth_methods` (Top-level)

The authentication method configuration for credential issuance.

### `auth_methods`

> **Path:** `.auth_methods.<key>`

This specifies what credentials the wallet must present for authentication
The format of the credentials is determined by looking up the VCTs in the credential_constructor

| Field    | Type       | Description                                                           | Example | Default | Required |
| -------- | ---------- | --------------------------------------------------------------------- | ------- | ------- | -------- |
| `vcts`   | `[]string` | List of acceptable Verifiable Credential Type URNs for authentication | -       | -       | Yes      |
| `claims` | `[]string` | Identity claims to extract from the authentication credential         | -       | -       | Yes      |

## `apigw` (Top-level)

Configuration for the API Gateway service that handles credential issuance requests.

### `apigw`

> **Path:** `.apigw`

| Field                 | Type     | Description                                                          | Example                       | Default | Required |
| --------------------- | -------- | -------------------------------------------------------------------- | ----------------------------- | ------- | -------- |
| `api_server`          | `object` | HTTP API server configuration                                        | -                             | -       | Yes      |
| `key_config`          | `object` | Signing key configuration                                            | -                             | -       | Yes      |
| `credential_offers`   | `object` | Credential offer wallet configurations                               | -                             | -       | No       |
| `oauth_server`        | `object` | OAuth2 server configuration                                          | -                             | -       | No       |
| `issuer_metadata`     | `object` | OpenID4VCI issuer metadata                                           | -                             | -       | No       |
| `public_url`          | `string` | Public URL of this service (must be valid HTTP/HTTPS URL)            | `"https://issuer.sunet.se"`   | -       | Yes      |
| `registry_public_url` | `string` | Public URL of the registry service for constructing status list URIs | `"https://registry.sunet.se"` | -       | Yes      |
| `saml`                | `object` | SAML Service Provider configuration                                  | -                             | -       | No       |
| `oidcrp`              | `object` | OIDC Relying Party configuration                                     | -                             | -       | No       |
| `issuer_client`       | `object` | GRPC client config for issuer                                        | -                             | -       | Yes      |
| `registry_client`     | `object` | GRPC client config for registry                                      | -                             | -       | Yes      |

### `api_server`

> **Path:** `.apigw.api_server`, `.issuer.api_server`, `.verifier.api_server`, `.registry.api_server`, `.mock_as.api_server`, `.ui.api_server`

| Field        | Type     | Description                        | Example | Default | Required |
| ------------ | -------- | ---------------------------------- | ------- | ------- | -------- |
| `addr`       | `string` | Listen address for the HTTP server | -       | `:8080` | No       |
| `tls`        | `object` | TLS                                | -       | -       | No       |
| `basic_auth` | `object` | Basic Auth                         | -       | -       | No       |
| `cors`       | `object` | CORS                               | -       | -       | No       |

### `tls`

> **Path:** `.apigw.api_server.tls`, `.issuer.api_server.tls`, `.verifier.api_server.tls`, `.registry.api_server.tls`, `.mock_as.api_server.tls`, `.ui.api_server.tls`

| Field            | Type     | Description                 | Example | Default | Required |
| ---------------- | -------- | --------------------------- | ------- | ------- | -------- |
| `enabled`        | `bool`   | TLS                         | -       | `false` | No       |
| `cert_file_path` | `string` | Path to the TLS certificate | -       | -       | Yes      |
| `key_file_path`  | `string` | Path to the TLS private key | -       | -       | Yes      |

### `basic_auth`

> **Path:** `.apigw.api_server.basic_auth`, `.issuer.api_server.basic_auth`, `.verifier.api_server.basic_auth`, `.registry.api_server.basic_auth`, `.mock_as.api_server.basic_auth`, `.ui.api_server.basic_auth`

| Field     | Type     | Description                  | Example | Default | Required |
| --------- | -------- | ---------------------------- | ------- | ------- | -------- |
| `users`   | `object` | Username to password mapping | -       | -       | No       |
| `enabled` | `bool`   | HTTP Basic authentication    | -       | `false` | No       |

### `cors`

> **Path:** `.apigw.api_server.cors`, `.issuer.api_server.cors`, `.verifier.api_server.cors`, `.registry.api_server.cors`, `.mock_as.api_server.cors`, `.ui.api_server.cors`

| Field             | Type       | Description                  | Example                                               | Default | Required |
| ----------------- | ---------- | ---------------------------- | ----------------------------------------------------- | ------- | -------- |
| `allowed_origins` | `[]string` | List of allowed CORS origins | `["https://wallet.sunet.se", "https://app.sunet.se"]` | `[]`    | No       |

### `key_config`

> **Path:** `.apigw.key_config`, `.issuer.key_config`, `.verifier.key_config`, `.registry.token_status_lists.key_config`

Supports both file-based and HSM-based keys with explicit control.

| Field              | Type     | Description                                            | Example                                                                        | Default | Required                          |
| ------------------ | -------- | ------------------------------------------------------ | ------------------------------------------------------------------------------ | ------- | --------------------------------- |
| `private_key_path` | `string` | File-based configuration                               | -                                                                              | -       | Yes (if pkcs11 not set)           |
| `chain_path`       | `string` | Path to certificate chain (optional)                   | -                                                                              | -       | No                                |
| `pkcs11`           | `object` | HSM-based configuration                                | -                                                                              | -       | Yes (if private_key_path not set) |
| `source`           | `object` | Source selection (determines which config to use)      | -                                                                              | -       | No                                |
| `enable_file`      | `bool`   | File-based key loading (default: true if FilePath set) | -                                                                              | -       | No                                |
| `enable_hsm`       | `bool`   | HSM-based key loading (default: true if HSM set)       | -                                                                              | -       | No                                |
| `priority`         | `array`  | Fallback order when both are enabled                   | `[]KeySource{KeySourceHSM, KeySourceFile} tries HSM first, falls back to file` | -       | No                                |

### `pkcs11`

> **Path:** `.apigw.key_config.pkcs11`, `.issuer.key_config.pkcs11`, `.verifier.key_config.pkcs11`, `.registry.token_status_lists.key_config.pkcs11`

| Field         | Type     | Description                       | Example                             | Default | Required |
| ------------- | -------- | --------------------------------- | ----------------------------------- | ------- | -------- |
| `module_path` | `string` | Path to the PKCS#11 library       | `"/usr/lib/softhsm/libsofthsm2.so"` | -       | No       |
| `slot_id`     | `uint`   | HSM slot ID                       | `0`                                 | -       | No       |
| `pin`         | `string` | User PIN for the slot             | `"1234"`                            | -       | No       |
| `key_label`   | `string` | Label of the key to use           | `"my-signing-key"`                  | -       | No       |
| `key_id`      | `string` | Identifier for the JWT kid header | `"key-1"`                           | -       | No       |

### `credential_offers`

> **Path:** `.apigw.credential_offers`

| Field        | Type     | Description                      | Example | Default | Required |
| ------------ | -------- | -------------------------------- | ------- | ------- | -------- |
| `issuer_url` | `string` | Issuer URL for credential offers | -       | -       | Yes      |
| `wallets`    | `object` | Wallet redirect configurations   | -       | -       | Yes      |

### `wallets` entry

> **Path:** `.apigw.credential_offers.wallets.<key>`

| Field          | Type     | Description                  | Example                            | Default | Required |
| -------------- | -------- | ---------------------------- | ---------------------------------- | ------- | -------- |
| `label`        | `string` | Display label for the wallet | -                                  | -       | Yes      |
| `redirect_uri` | `string` | Wallet redirect URI          | `"eudi-wallet://credential-offer"` | -       | Yes      |

### `oauth_server`

> **Path:** `.apigw.oauth_server`, `.verifier.oauth_server`

| Field            | Type     | Description                  | Example                             | Default | Required |
| ---------------- | -------- | ---------------------------- | ----------------------------------- | ------- | -------- |
| `token_endpoint` | `string` | OAuth2 token endpoint URL    | `"https://verifier.sunet.se/token"` | -       | Yes      |
| `clients`        | `object` | OAuth2 client configurations | -                                   | -       | Yes      |

### `clients` entry

> **Path:** `.apigw.oauth_server.clients.<key>`, `.verifier.oauth_server.clients.<key>`

| Field          | Type       | Description                                  | Example                          | Default | Required |
| -------------- | ---------- | -------------------------------------------- | -------------------------------- | ------- | -------- |
| `type`         | `string`   | Client type                                  | `"public"`                       | -       | Yes      |
| `redirect_uri` | `string`   | Allowed redirect URI for the client          | `"https://example.com/callback"` | -       | Yes      |
| `scopes`       | `[]string` | List of OAuth2 scopes allowed for the client | -                                | -       | Yes      |

### `issuer_metadata`

> **Path:** `.apigw.issuer_metadata`

| Field                                     | Type       | Description                       | Example | Default | Required |
| ----------------------------------------- | ---------- | --------------------------------- | ------- | ------- | -------- |
| `authorization_servers`                   | `[]string` | The authorization server URLs     | -       | -       | No       |
| `deferred_credential_endpoint`            | `string`   | Deferred credential endpoint      | -       | -       | No       |
| `notification_endpoint`                   | `string`   | Notification endpoint             | -       | -       | No       |
| `cryptographic_binding_methods_supported` | `[]string` | The supported binding methods     | -       | -       | No       |
| `credential_signing_alg_values_supported` | `[]string` | The supported signing algorithms  | -       | -       | No       |
| `proof_signing_alg_values_supported`      | `[]string` | The supported proof algorithms    | -       | -       | No       |
| `credential_response_encryption`          | `object`   | Response encryption configuration | -       | -       | No       |
| `batch_credential_issuance`               | `object`   | Batch issuance configuration      | -       | -       | No       |
| `display`                                 | `array`    | Display metadata                  | -       | -       | No       |

### `credential_response_encryption`

> **Path:** `.apigw.issuer_metadata.credential_response_encryption`

| Field                  | Type       | Description                                                                                                                                                                                                                                                                                                                                                                                                                               | Example | Default | Required |
| ---------------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- | ------- | -------- |
| `alg_values_supported` | `[]string` | AlgValuesSupported: REQUIRED. Array containing a list of the JWE [RFC7516] encryption algorithms (alg values) [RFC7518] supported by the Credential and Batch Credential Endpoint to encode the Credential or Batch Credential Response in a JWT [RFC7519].                                                                                                                                                                               | -       | -       | Yes      |
| `enc_values_supported` | `[]string` | EncValuesSupported: REQUIRED. Array containing a list of the JWE [RFC7516] encryption algorithms (enc values) [RFC7518] supported by the Credential and Batch Credential Endpoint to encode the Credential or Batch Credential Response in a JWT [RFC7519].                                                                                                                                                                               | -       | -       | Yes      |
| `encryption_required`  | `bool`     | EncryptionRequired: REQUIRED. Boolean value specifying whether the Credential Issuer requires the additional encryption on top of TLS for the Credential Response. If the value is true, the Credential Issuer requires encryption for every Credential Response and therefore the Wallet MUST provide encryption keys in the Credential Request. If the value is false, the Wallet MAY chose whether it provides encryption keys or not. | -       | -       | No       |

### `batch_credential_issuance`

> **Path:** `.apigw.issuer_metadata.batch_credential_issuance`

| Field        | Type  | Description                                                                                                            | Example | Default | Required |
| ------------ | ----- | ---------------------------------------------------------------------------------------------------------------------- | ------- | ------- | -------- |
| `batch_size` | `int` | BatchSize: REQUIRED. Integer value specifying the maximum array size for the proofs parameter in a Credential Request. | -       | -       | Yes      |

### `display` entry

> **Path:** `.apigw.issuer_metadata.display[]`

| Field    | Type     | Description                                                                                                                                                                                                        | Example | Default | Required |
| -------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------- | ------- | -------- |
| `name`   | `string` | Name: OPTIONAL. String value of a display name for the Credential Issuer.                                                                                                                                          | -       | -       | No       |
| `locale` | `string` | Locale: OPTIONAL. String value that identifies the language of this object represented as a language tag taken from values defined in BCP47 [RFC5646]. There MUST be only one object for each language identifier. | -       | -       | No       |
| `logo`   | `object` | Logo: OPTIONAL. Object with information about the logo of the Credential Issuer. Below is a non-exhaustive list of parameters that MAY be included:                                                                | -       | -       | No       |

### `logo`

> **Path:** `.apigw.issuer_metadata.display[].logo`

| Field      | Type     | Description                                                                                                                                                                                                                      | Example | Default | Required |
| ---------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- | ------- | -------- |
| `uri`      | `string` | URI: REQUIRED. String value that contains a URI where the Wallet can obtain the logo of the Credential Issuer. The Wallet needs to determine the scheme, since the URI value could use the https: scheme, the data: scheme, etc. | -       | -       | Yes      |
| `alt_text` | `string` | AltText: OPTIONAL. String value of the alternative text for the logo image.                                                                                                                                                      | -       | -       | No       |

### `saml`

> **Path:** `.apigw.saml`

| Field                 | Type     | Description                                                                           | Example                                             | Default | Required                |
| --------------------- | -------- | ------------------------------------------------------------------------------------- | --------------------------------------------------- | ------- | ----------------------- |
| `enabled`             | `bool`   | SAML support (default: false)                                                         | -                                                   | `false` | No                      |
| `entity_id`           | `string` | SAML SP entity identifier (typically the metadata URL)                                | `"https://issuer.sunet.se/saml/metadata"`           | -       | Yes (if enabled = true) |
| `metadata_url`        | `string` | Public URL where SP metadata is served (optional, auto-generated if empty)            | -                                                   | -       | No                      |
| `mdq_server`          | `string` | Base URL for MDQ (Metadata Query Protocol) server                                     | `"https://md.sunet.se/entities/" (must end with /)` | -       | No                      |
| `static_idp_metadata` | `object` | A single static IdP as alternative to MDQ                                             | -                                                   | -       | No                      |
| `certificate_path`    | `string` | Path to X.509 certificate for SAML signing/encryption                                 | -                                                   | -       | Yes (if enabled = true) |
| `private_key_path`    | `string` | Path to private key for SAML signing/encryption                                       | -                                                   | -       | Yes (if enabled = true) |
| `acs_endpoint`        | `string` | Assertion Consumer Service URL where IdP sends SAML responses                         | `"https://issuer.sunet.se/saml/acs"`                | -       | Yes (if enabled = true) |
| `session_duration`    | `int`    | SessionDuration in seconds (default: 3600)                                            | -                                                   | -       | No                      |
| `credential_mappings` | `object` | How to map external attributes to credential claims                                   | -                                                   | -       | Yes (if enabled = true) |
| `metadata_cache_ttl`  | `int`    | MetadataCacheTTL in seconds (default: 3600) - how long to cache IdP metadata from MDQ | -                                                   | -       | No                      |

### `static_idp_metadata`

> **Path:** `.apigw.saml.static_idp_metadata`

| Field           | Type     | Description                                                                   | Example | Default | Required                      |
| --------------- | -------- | ----------------------------------------------------------------------------- | ------- | ------- | ----------------------------- |
| `entity_id`     | `string` | IdP entity identifier                                                         | -       | -       | Yes                           |
| `metadata_path` | `string` | File path to IdP metadata XML (mutually exclusive with MetadataURL)           | -       | -       | Yes (if metadata_url not set) |
| `metadata_url`  | `string` | HTTP(S) URL to fetch IdP metadata from (mutually exclusive with MetadataPath) | -       | -       | No                            |

### `credential_mappings` entry

> **Path:** `.apigw.saml.credential_mappings.<key>`, `.apigw.oidcrp.credential_mappings.<key>`

The credential type identifier (map key) is used in API requests and session state

| Field                  | Type     | Description                                                  | Example                                                                | Default | Required |
| ---------------------- | -------- | ------------------------------------------------------------ | ---------------------------------------------------------------------- | ------- | -------- |
| `credential_config_id` | `string` | OpenID4VCI credential configuration identifier               | `"urn:eudi:pid:1"`                                                     | -       | Yes      |
| `attributes`           | `object` | SAML attribute OIDs to claim paths with transformation rules | `"urn:oid:2.5.4.42" -> {claim: "identity.given_name", required: true}` | -       | Yes      |
| `default_idp`          | `string` | Optional default IdP entityID for this credential type       | -                                                                      | -       | No       |

### `attributes` entry

> **Path:** `.apigw.saml.credential_mappings.<key>.attributes.<key>`, `.apigw.oidcrp.credential_mappings.<key>.attributes.<key>`

Generic across protocols (SAML, OIDC, etc.) - uses protocol-specific identifiers as keys

| Field       | Type     | Description                                                                    | Example                                 | Default | Required |
| ----------- | -------- | ------------------------------------------------------------------------------ | --------------------------------------- | ------- | -------- |
| `claim`     | `string` | Target claim name (supports dot-notation for nesting)                          | `"given_name" or "identity.given_name"` | -       | Yes      |
| `required`  | `bool`   | Required indicates if this attribute must be present in the assertion/response | -                                       | `false` | No       |
| `transform` | `string` | Optional transformation to apply                                               | -                                       | -       | No       |
| `default`   | `string` | Optional default value if attribute is missing                                 | -                                       | -       | No       |

### `oidcrp`

> **Path:** `.apigw.oidcrp`

| Field                  | Type       | Description                                                           | Example                                     | Default                          | Required                |
| ---------------------- | ---------- | --------------------------------------------------------------------- | ------------------------------------------- | -------------------------------- | ----------------------- |
| `enabled`              | `bool`     | OIDC RP support (default: false)                                      | -                                           | `false`                          | No                      |
| `dynamic_registration` | `object`   | Dynamic Registration (RFC 7591) support                               | -                                           | -                                | No                      |
| `client_id`            | `string`   | OIDC client identifier (required if not using dynamic registration)   | -                                           | -                                | No                      |
| `client_secret`        | `string`   | OIDC client secret (required if not using dynamic registration)       | -                                           | -                                | No                      |
| `redirect_uri`         | `string`   | Callback URL where the OIDC Provider sends the authorization response | `"https://issuer.sunet.se/oidcrp/callback"` | -                                | Yes (if enabled = true) |
| `issuer_url`           | `string`   | OIDC Provider's issuer URL for discovery                              | `"https://accounts.google.com"`             | -                                | Yes (if enabled = true) |
| `scopes`               | `[]string` | OAuth2/OIDC scopes to request                                         | -                                           | `["openid", "profile", "email"]` | No                      |
| `session_duration`     | `int`      | SessionDuration in seconds (default: 3600)                            | -                                           | `3600`                           | No                      |
| `client_name`          | `string`   | Client metadata for dynamic registration or display purposes          | -                                           | -                                | No                      |
| `client_uri`           | `string`   | Client URI                                                            | -                                           | -                                | No                      |
| `logo_uri`             | `string`   | Logo URI                                                              | -                                           | -                                | No                      |
| `contacts`             | `[]string` | Contacts                                                              | -                                           | -                                | No                      |
| `tos_uri`              | `string`   | Tos URI                                                               | -                                           | -                                | No                      |
| `policy_uri`           | `string`   | Policy URI                                                            | -                                           | -                                | No                      |
| `credential_mappings`  | `object`   | How to map OIDC claims to credential claims                           | -                                           | -                                | Yes (if enabled = true) |

### `dynamic_registration`

> **Path:** `.apigw.oidcrp.dynamic_registration`

| Field                  | Type     | Description                                    | Example                                  | Default | Required |
| ---------------------- | -------- | ---------------------------------------------- | ---------------------------------------- | ------- | -------- |
| `enabled`              | `bool`   | Dynamic client registration                    | -                                        | `false` | No       |
| `initial_access_token` | `string` | Optional bearer token for registration         | -                                        | -       | No       |
| `storage_path`         | `string` | Where registered client credentials are cached | `"/var/lib/vc/oidcrp-registration.json"` | -       | No       |

### `issuer_client`

> **Path:** `.apigw.issuer_client`, `.apigw.registry_client`, `.issuer.registry_client`

| Field            | Type     | Description                                 | Example         | Default | Required |
| ---------------- | -------- | ------------------------------------------- | --------------- | ------- | -------- |
| `addr`           | `string` | GRPC server address                         | `"issuer:8090"` | -       | Yes      |
| `tls`            | `bool`   | TLS                                         | -               | `false` | No       |
| `cert_file_path` | `string` | Client certificate for mTLS                 | -               | -       | No       |
| `key_file_path`  | `string` | Client private key for mTLS                 | -               | -       | No       |
| `ca_file_path`   | `string` | CA certificate to verify the server         | -               | -       | No       |
| `server_name`    | `string` | Server name for TLS verification (optional) | -               | -       | No       |

## `issuer` (Top-level)

Configuration for the Issuer service that signs and issues verifiable credentials.

### `issuer`

> **Path:** `.issuer`

| Field             | Type     | Description                            | Example                     | Default | Required |
| ----------------- | -------- | -------------------------------------- | --------------------------- | ------- | -------- |
| `api_server`      | `object` | HTTP API server configuration          | -                           | -       | Yes      |
| `grpc_server`     | `object` | GRPC server configuration              | -                           | -       | Yes      |
| `key_config`      | `object` | Signing key configuration              | -                           | -       | Yes      |
| `jwt_attribute`   | `object` | JWT credential attribute configuration | -                           | -       | Yes      |
| `issuer_url`      | `string` | Issuer identifier URL                  | `"https://issuer.sunet.se"` | -       | Yes      |
| `registry_client` | `object` | Registry gRPC client config            | -                           | -       | No       |
| `mdoc`            | `object` | MDL/mdoc configuration                 | -                           | -       | No       |
| `audit_log`       | `object` | Audit log configuration                | -                           | -       | No       |

### `grpc_server`

> **Path:** `.issuer.grpc_server`, `.registry.grpc_server`

| Field  | Type     | Description                | Example | Default | Required |
| ------ | -------- | -------------------------- | ------- | ------- | -------- |
| `addr` | `string` | GRPC server listen address | -       | `:8090` | No       |
| `tls`  | `object` | MTLS configuration         | -       | -       | No       |

### `tls`

> **Path:** `.issuer.grpc_server.tls`, `.registry.grpc_server.tls`

| Field                         | Type     | Description                                                                        | Example | Default                | Required |
| ----------------------------- | -------- | ---------------------------------------------------------------------------------- | ------- | ---------------------- | -------- |
| `enabled`                     | `bool`   | Enabled                                                                            | -       | `false`                | No       |
| `cert_file_path`              | `string` | Server certificate                                                                 | -       | `/pki/grpc_server.crt` | No       |
| `key_file_path`               | `string` | Server private key                                                                 | -       | `/pki/grpc_server.key` | No       |
| `client_ca_path`              | `string` | CA to verify client certificates (for mTLS)                                        | -       | `/pki/client_ca.crt`   | No       |
| `allowed_client_fingerprints` | `object` | SHA256 fingerprint -> friendly name (e.g., "a1b2c3..." -> "issuer-prod")           | -       | -                      | No       |
| `allowed_client_dns`          | `object` | Certificate Subject DN -> friendly name (e.g., "CN=apigw,O=SUNET" -> "apigw-prod") | -       | -                      | No       |

### `jwt_attribute`

> **Path:** `.issuer.jwt_attribute`

In a later state this should be placed under authentic source in order to issue credentials based on that configuration.

| Field                        | Type     | Description                                                    | Example                                           | Default | Required |
| ---------------------------- | -------- | -------------------------------------------------------------- | ------------------------------------------------- | ------- | -------- |
| `issuer`                     | `string` | Issuer of the token                                            | `https://issuer.sunet.se`                         | -       | Yes      |
| `static_host`                | `string` | Static host of the issuer, expose static files, like pictures. | -                                                 | -       | No       |
| `enable_not_before`          | `bool`   | The time not before which the token is valid                   | -                                                 | `false` | No       |
| `valid_duration`             | `int64`  | Valid duration of the token in seconds                         | -                                                 | `3600`  | No       |
| `verifiable_credential_type` | `string` | VerifiableCredentialType URL                                   | `https://credential.sunet.se/identity_credential` | -       | Yes      |
| `status`                     | `string` | Status status of the Verifiable Credential                     | -                                                 | -       | No       |
| `kid`                        | `string` | Kid key id of the signing key                                  | -                                                 | -       | No       |

### `mdoc`

> **Path:** `.issuer.mdoc`

| Field                    | Type       | Description                                          | Example | Default   | Required |
| ------------------------ | ---------- | ---------------------------------------------------- | ------- | --------- | -------- |
| `certificate_chain_path` | `string`   | Path to the PEM certificate chain                    | -       | -         | Yes      |
| `default_validity`       | `duration` | Default credential validity (default: 365 days)      | -       | `8760h`   | No       |
| `digest_algorithm`       | `string`   | Digest algorithm: "SHA-256", "SHA-384", or "SHA-512" | -       | `SHA-256` | No       |

### `audit_log`

> **Path:** `.issuer.audit_log`

| Field                | Type       | Description                                                       | Example                                                              | Default | Required                |
| -------------------- | ---------- | ----------------------------------------------------------------- | -------------------------------------------------------------------- | ------- | ----------------------- |
| `enabled`            | `bool`     | Audit logging                                                     | -                                                                    | `false` | No                      |
| `destinations`       | `[]string` | List of log destinations (console/stdout, file path, or HTTP URL) | `["stdout", "/var/log/audit.log", "https://audit.sunet.se/webhook"]` | -       | Yes (if enabled = true) |
| `file_sync_interval` | `duration` | Fsync behavior for file destinations.                             | -                                                                    | `5s`    | No                      |

## `verifier` (Top-level)

Configuration for the Verifier service that verifies credentials and acts as an OIDC Provider.

### `verifier`

> **Path:** `.verifier`

| Field                    | Type     | Description                                                  | Example                       | Default | Required |
| ------------------------ | -------- | ------------------------------------------------------------ | ----------------------------- | ------- | -------- |
| `api_server`             | `object` | HTTP API server configuration                                | -                             | -       | Yes      |
| `public_url`             | `string` | Public URL of this service (must be valid HTTP/HTTPS URL)    | `"https://verifier.sunet.se"` | -       | Yes      |
| `key_config`             | `object` | Signing key configuration                                    | -                             | -       | Yes      |
| `oauth_server`           | `object` | OAuth2 server configuration                                  | -                             | -       | Yes      |
| `preferred_vp_formats`   | `object` | Informational VP formats and algorithms supported by wallets | -                             | -       | No       |
| `supported_wallets`      | `object` | Supported wallet configurations                              | -                             | -       | No       |
| `oidc`                   | `object` | OIDC Provider configuration                                  | -                             | -       | No       |
| `openid4vp`              | `object` | OpenID4VP configuration                                      | -                             | -       | No       |
| `digital_credentials`    | `object` | W3C Digital Credentials API configuration                    | -                             | -       | No       |
| `authorization_page_css` | `object` | Authorization page styling configuration                     | -                             | -       | No       |
| `credential_display`     | `object` | Credential display settings                                  | -                             | -       | No       |
| `trust`                  | `object` | Trust evaluation configuration                               | -                             | -       | No       |

### `preferred_vp_formats`

> **Path:** `.verifier.preferred_vp_formats`

Used in client_metadata and Wallet metadata to indicate supported formats and algorithms.

| Field         | Type     | Description                                             | Example | Default | Required |
| ------------- | -------- | ------------------------------------------------------- | ------- | ------- | -------- |
| `ldp_vc`      | `object` | Configuration for W3C VC Data Integrity format (ldp_vc) | -       | -       | No       |
| `jwt_vc_json` | `object` | Configuration for JWT-based W3C VC format (jwt_vc_json) | -       | -       | No       |
| `dc+sd-jwt`   | `object` | Configuration for SD-JWT VC format (dc+sd-jwt)          | -       | -       | No       |
| `mso_mdoc`    | `object` | Configuration for ISO mdoc format (mso_mdoc)            | -       | -       | No       |

### `ldp_vc`

> **Path:** `.verifier.preferred_vp_formats.ldp_vc`

| Field                | Type       | Description                                                        | Example | Default | Required |
| -------------------- | ---------- | ------------------------------------------------------------------ | ------- | ------- | -------- |
| `proof_type_values`  | `[]string` | Non-empty array containing identifiers of proof types supported.   | -       | -       | No       |
| `cryptosuite_values` | `[]string` | Non-empty array containing identifiers of crypto suites supported. | -       | -       | No       |

### `jwt_vc_json`

> **Path:** `.verifier.preferred_vp_formats.jwt_vc_json`

| Field        | Type       | Description                                                                   | Example | Default | Required |
| ------------ | ---------- | ----------------------------------------------------------------------------- | ------- | ------- | -------- |
| `alg_values` | `[]string` | Non-empty array containing identifiers of cryptographic algorithms supported. | -       | -       | No       |

### `dc+sd-jwt`

> **Path:** `.verifier.preferred_vp_formats.dc+sd-jwt`

| Field               | Type       | Description                                                    | Example | Default | Required |
| ------------------- | ---------- | -------------------------------------------------------------- | ------- | ------- | -------- |
| `sd-jwt_alg_values` | `[]string` | Non-empty array containing cryptographic algorithm identifiers | -       | -       | No       |
| `kb-jwt_alg_values` | `[]string` | Non-empty array containing cryptographic algorithm identifiers | -       | -       | No       |

### `mso_mdoc`

> **Path:** `.verifier.preferred_vp_formats.mso_mdoc`

| Field                   | Type    | Description                                                    | Example | Default | Required |
| ----------------------- | ------- | -------------------------------------------------------------- | ------- | ------- | -------- |
| `issuerauth_alg_values` | `[]int` | Non-empty array containing cryptographic algorithm identifiers | -       | -       | No       |
| `deviceauth_alg_values` | `[]int` | Non-empty array containing cryptographic algorithm identifiers | -       | -       | No       |

### `oidc`

> **Path:** `.verifier.oidc`

This configures how the verifier issues ID tokens and access tokens to relying parties.
Note: This is NOT related to verifiable credential issuance (see IssuerConfig for VC issuance).
The signing key is shared from the parent Verifier.KeyConfig.

| Field                    | Type     | Description                                                                | Example                       | Default | Required |
| ------------------------ | -------- | -------------------------------------------------------------------------- | ----------------------------- | ------- | -------- |
| `issuer`                 | `string` | OIDC Provider identifier that appears in ID tokens and discovery metadata. | `"https://verifier.sunet.se"` | -       | Yes      |
| `session_duration`       | `int`    | Session duration in seconds                                                | -                             | `3600`  | No       |
| `code_duration`          | `int`    | Authorization code duration in seconds                                     | -                             | `300`   | No       |
| `access_token_duration`  | `int`    | Access token duration in seconds                                           | -                             | `3600`  | No       |
| `id_token_duration`      | `int`    | ID token duration in seconds                                               | -                             | `3600`  | No       |
| `refresh_token_duration` | `int`    | Refresh token duration in seconds                                          | -                             | `86400` | No       |
| `subject_type`           | `string` | Subject type: "public" or "pairwise"                                       | -                             | -       | Yes      |
| `subject_salt`           | `string` | Salt for pairwise subject generation                                       | -                             | -       | Yes      |

### `openid4vp`

> **Path:** `.verifier.openid4vp`

| Field                       | Type     | Description                                            | Example | Default | Required |
| --------------------------- | -------- | ------------------------------------------------------ | ------- | ------- | -------- |
| `presentation_timeout`      | `int`    | Presentation timeout in seconds                        | -       | `300`   | No       |
| `supported_credentials`     | `array`  | Supported credential configurations                    | -       | -       | Yes      |
| `presentation_requests_dir` | `string` | Optional directory with presentation request templates | -       | -       | No       |

### `supported_credentials` entry

> **Path:** `.verifier.openid4vp.supported_credentials[]`

| Field    | Type       | Description                                      | Example            | Default | Required |
| -------- | ---------- | ------------------------------------------------ | ------------------ | ------- | -------- |
| `vct`    | `string`   | Verifiable credential type                       | `"urn:eudi:pid:1"` | -       | Yes      |
| `scopes` | `[]string` | OIDC scopes that grant access to this credential | -                  | -       | Yes      |

### `digital_credentials`

> **Path:** `.verifier.digital_credentials`

| Field               | Type       | Description                                              | Example            | Default                                  | Required |
| ------------------- | ---------- | -------------------------------------------------------- | ------------------ | ---------------------------------------- | -------- |
| `enabled`           | `bool`     | W3C Digital Credentials API support in browser           | -                  | `false`                                  | No       |
| `use_jar`           | `bool`     | JWT Authorization Request (JAR) for wallet communication | -                  | `false`                                  | No       |
| `preferred_formats` | `[]string` | The order of preference for credential formats           | -                  | `["vc+sd-jwt", "dc+sd-jwt", "mso_mdoc"]` | No       |
| `response_mode`     | `string`   | The OpenID4VP response mode for DC API flows             | -                  | `dc_api.jwt`                             | No       |
| `allow_qr_fallback` | `bool`     | Automatic fallback to QR code if DC API is unavailable   | -                  | `true`                                   | No       |
| `deep_link_scheme`  | `string`   | DeepLinkScheme for mobile wallet integration             | `"eudi-wallet://"` | -                                        | No       |

### `authorization_page_css`

> **Path:** `.verifier.authorization_page_css`

| Field             | Type     | Description                                                          | Example     | Default | Required |
| ----------------- | -------- | -------------------------------------------------------------------- | ----------- | ------- | -------- |
| `custom_css`      | `string` | Inline CSS that will be injected into the authorization page         | -           | -       | No       |
| `css_file`        | `string` | Path to an external CSS file to include                              | -           | -       | No       |
| `theme`           | `string` | Predefined color scheme: "light" (default), "dark", "blue", "purple" | -           | `light` | No       |
| `primary_color`   | `string` | PrimaryColor overrides the primary brand color                       | `"#667eea"` | -       | No       |
| `secondary_color` | `string` | SecondaryColor overrides the secondary brand color                   | `"#764ba2"` | -       | No       |
| `logo_url`        | `string` | A URL to a custom logo image                                         | -           | -       | No       |
| `title`           | `string` | Title overrides the page title (default: "Wallet Authorization")     | -           | -       | No       |
| `subtitle`        | `string` | Subtitle overrides the page subtitle                                 | -           | -       | No       |

### `credential_display`

> **Path:** `.verifier.credential_display`

| Field                  | Type   | Description                                                                 | Example | Default | Required |
| ---------------------- | ------ | --------------------------------------------------------------------------- | ------- | ------- | -------- |
| `enabled`              | `bool` | Users to optionally view credential details before completing authorization | -       | `false` | No       |
| `require_confirmation` | `bool` | Users to review credentials before proceeding                               | -       | `false` | No       |
| `show_raw_credential`  | `bool` | The raw VP token/credential in the display page                             | -       | `false` | No       |
| `show_claims`          | `bool` | The parsed claims that will be sent to the RP                               | -       | `true`  | No       |
| `allow_edit`           | `bool` | Users to redact certain claims before sending to RP (future feature)        | -       | `false` | No       |

### `trust`

> **Path:** `.verifier.trust`

This is used for validating W3C VC Data Integrity proofs and other trust-related operations.

| Field               | Type       | Description                                                 | Example                        | Default                  | Required |
| ------------------- | ---------- | ----------------------------------------------------------- | ------------------------------ | ------------------------ | -------- |
| `go_trust_url`      | `string`   | URL of the go-trust PDP (Policy Decision Point) service.    | `"https://trust.sunet.se/pdp"` | -                        | No       |
| `local_did_methods` | `[]string` | Which DID methods can be resolved locally without go-trust. | -                              | `["did:key", "did:jwk"]` | No       |
| `trust_policies`    | `object`   | Per-role trust evaluation policies.                         | -                              | -                        | No       |
| `enabled`           | `bool`     | Whether trust evaluation is enabled.                        | -                              | `true`                   | No       |

### `trust_policies` entry

> **Path:** `.verifier.trust.trust_policies.<key>`

| Field                      | Type       | Description                                                               | Example | Default | Required |
| -------------------------- | ---------- | ------------------------------------------------------------------------- | ------- | ------- | -------- |
| `trust_frameworks`         | `[]string` | The accepted trust frameworks for this role.                              | -       | -       | No       |
| `trust_anchors`            | `[]string` | Trusted root entities for this role.                                      | -       | -       | No       |
| `require_revocation_check` | `bool`     | RequireRevocationCheck enforces revocation status checking for this role. | -       | `false` | No       |

## `registry` (Top-level)

Configuration for the Registry service that manages credential status.

### `registry`

> **Path:** `.registry`

| Field                | Type     | Description                                               | Example                       | Default | Required |
| -------------------- | -------- | --------------------------------------------------------- | ----------------------------- | ------- | -------- |
| `api_server`         | `object` | HTTP API server configuration                             | -                             | -       | Yes      |
| `public_url`         | `string` | Public URL of this service (must be valid HTTP/HTTPS URL) | `"https://registry.sunet.se"` | -       | Yes      |
| `grpc_server`        | `object` | GRPC server configuration                                 | -                             | -       | Yes      |
| `token_status_lists` | `object` | Token Status List configuration                           | -                             | -       | No       |
| `admin_gui`          | `object` | Admin GUI configuration                                   | -                             | -       | No       |

### `token_status_lists`

> **Path:** `.registry.token_status_lists`

| Field                            | Type     | Description                                                                                  | Example | Default   | Required |
| -------------------------------- | -------- | -------------------------------------------------------------------------------------------- | ------- | --------- | -------- |
| `key_config`                     | `object` | Key configuration for signing Token Status List tokens.                                      | -       | -         | Yes      |
| `token_refresh_interval`         | `int64`  | How often (in seconds) new Token Status List tokens are generated. Default: 43200 (12 hours) | -       | `43200`   | No       |
| `section_size`                   | `int64`  | Number of entries (decoys) per section. Default: 1000000 (1 million)                         | -       | `1000000` | No       |
| `rate_limit_requests_per_minute` | `int`    | Maximum requests per minute per IP for token status list endpoints. Default: 60              | -       | `60`      | No       |

### `admin_gui`

> **Path:** `.registry.admin_gui`

| Field            | Type     | Description                | Example | Default | Required                |
| ---------------- | -------- | -------------------------- | ------- | ------- | ----------------------- |
| `enabled`        | `bool`   | The admin GUI              | -       | `true`  | No                      |
| `username`       | `string` | Admin username             | -       | `admin` | No                      |
| `password`       | `string` | Admin password             | -       | -       | Yes (if enabled = true) |
| `session_secret` | `string` | Secret for session cookies | -       | -       | Yes (if enabled = true) |

## `mock_as` (Top-level)

Configuration for the Mock Authentic Source service used for testing.

### `mock_as`

> **Path:** `.mock_as`

| Field             | Type       | Description                              | Example                   | Default          | Required |
| ----------------- | ---------- | ---------------------------------------- | ------------------------- | ---------------- | -------- |
| `api_server`      | `object`   | HTTP API server configuration            | -                         | -                | Yes      |
| `datastore_url`   | `string`   | Datastore service URL                    | `"http://datastore:8080"` | -                | Yes      |
| `bootstrap_users` | `[]string` | List of user IDs to bootstrap on startup | -                         | `["100", "102"]` | No       |

## `ui` (Top-level)

Configuration for the User Interface service.

### `ui`

> **Path:** `.ui`

| Field                                   | Type     | Description                           | Example | Default | Required |
| --------------------------------------- | -------- | ------------------------------------- | ------- | ------- | -------- |
| `api_server`                            | `object` | HTTP API server configuration         | -       | -       | Yes      |
| `username`                              | `string` | UI login username                     | -       | -       | Yes      |
| `password`                              | `string` | UI login password                     | -       | -       | Yes      |
| `session_cookie_authentication_key`     | `string` | Session cookie HMAC key               | -       | -       | Yes      |
| `session_store_encryption_key`          | `string` | Session cookie encryption key         | -       | -       | Yes      |
| `session_inactivity_timeout_in_seconds` | `int`    | Session inactivity timeout in seconds | -       | -       | Yes      |
| `services`                              | `object` | Services                              | -       | -       | No       |

### `services`

> **Path:** `.ui.services`

| Field      | Type     | Description | Example | Default | Required |
| ---------- | -------- | ----------- | ------- | ------- | -------- |
| `apigw`    | `object` | APIGW       | -       | -       | No       |
| `mockas`   | `object` | Mock AS     | -       | -       | No       |
| `verifier` | `object` | Verifier    | -       | -       | No       |

### `apigw`

> **Path:** `.ui.services.apigw`

| Field      | Type     | Description | Example | Default | Required |
| ---------- | -------- | ----------- | ------- | ------- | -------- |
| `base_url` | `string` | Base URL    | -       | -       | No       |

### `mockas`

> **Path:** `.ui.services.mockas`

| Field      | Type     | Description | Example | Default | Required |
| ---------- | -------- | ----------- | ------- | ------- | -------- |
| `base_url` | `string` | Base URL    | -       | -       | No       |

### `verifier`

> **Path:** `.ui.services.verifier`

| Field      | Type     | Description | Example | Default | Required |
| ---------- | -------- | ----------- | ------- | ------- | -------- |
| `base_url` | `string` | Base URL    | -       | -       | No       |

## `credential_constructor` (Top-level)

### `credential_constructor`

> **Path:** `.credential_constructor.<key>`

| Field            | Type     | Description    | Example | Default | Required |
| ---------------- | -------- | -------------- | ------- | ------- | -------- |
| `vctm_file_path` | `string` | VCTM File Path | -       | -       | Yes      |
| `format`         | `string` | Format         | -       | -       | Yes      |
| `auth_method`    | `string` | Auth Method    | -       | -       | Yes      |
| `attributes`     | `object` | Attributes     | -       | -       | Yes      |

## Secrets File Reference

The structure of the separate secrets file.

### Secrets file structure

> **Path:** `(root)`

When Common.SecretFilePath is set, secret values in config.yaml are
cleared; only non-empty fields from this file are applied.
Fields omitted or left empty here remain at their zero value.

| Field      | Type     | Description | Example | Default | Required |
| ---------- | -------- | ----------- | ------- | ------- | -------- |
| `common`   | `object` | Common      | -       | -       | No       |
| `apigw`    | `object` | APIGW       | -       | -       | No       |
| `registry` | `object` | Registry    | -       | -       | No       |
| `verifier` | `object` | Verifier    | -       | -       | No       |
| `ui`       | `object` | UI          | -       | -       | No       |

### `common`

> **Path:** `.common`

| Field   | Type     | Description | Example | Default | Required |
| ------- | -------- | ----------- | ------- | ------- | -------- |
| `mongo` | `object` | Mongo       | -       | -       | No       |

### `mongo`

> **Path:** `.common.mongo`

| Field | Type     | Description | Example | Default | Required |
| ----- | -------- | ----------- | ------- | ------- | -------- |
| `uri` | `string` | URI         | -       | -       | No       |

### `apigw`

> **Path:** `.apigw`

| Field        | Type     | Description | Example | Default | Required |
| ------------ | -------- | ----------- | ------- | ------- | -------- |
| `api_server` | `object` | API Server  | -       | -       | No       |
| `oidcrp`     | `object` | OIDCRP      | -       | -       | No       |

### `api_server`

> **Path:** `.apigw.api_server`

| Field        | Type     | Description | Example | Default | Required |
| ------------ | -------- | ----------- | ------- | ------- | -------- |
| `basic_auth` | `object` | Basic Auth  | -       | -       | No       |

### `basic_auth`

> **Path:** `.apigw.api_server.basic_auth`

| Field   | Type     | Description | Example | Default | Required |
| ------- | -------- | ----------- | ------- | ------- | -------- |
| `users` | `object` | Users       | -       | -       | No       |

### `oidcrp`

> **Path:** `.apigw.oidcrp`

| Field           | Type     | Description   | Example | Default | Required |
| --------------- | -------- | ------------- | ------- | ------- | -------- |
| `client_secret` | `string` | Client Secret | -       | -       | No       |

### `registry`

> **Path:** `.registry`

| Field       | Type     | Description | Example | Default | Required |
| ----------- | -------- | ----------- | ------- | ------- | -------- |
| `admin_gui` | `object` | Admin GUI   | -       | -       | No       |

### `admin_gui`

> **Path:** `.registry.admin_gui`

| Field            | Type     | Description    | Example | Default | Required |
| ---------------- | -------- | -------------- | ------- | ------- | -------- |
| `password`       | `string` | Password       | -       | -       | No       |
| `session_secret` | `string` | Session Secret | -       | -       | No       |

### `verifier`

> **Path:** `.verifier`

| Field  | Type     | Description | Example | Default | Required |
| ------ | -------- | ----------- | ------- | ------- | -------- |
| `oidc` | `object` | OIDC        | -       | -       | No       |

### `oidc`

> **Path:** `.verifier.oidc`

| Field          | Type     | Description  | Example | Default | Required |
| -------------- | -------- | ------------ | ------- | ------- | -------- |
| `subject_salt` | `string` | Subject Salt | -       | -       | No       |

### `ui`

> **Path:** `.ui`

| Field                               | Type     | Description                       | Example | Default | Required |
| ----------------------------------- | -------- | --------------------------------- | ------- | ------- | -------- |
| `password`                          | `string` | Password                          | -       | -       | No       |
| `session_cookie_authentication_key` | `string` | Session Cookie Authentication Key | -       | -       | No       |
| `session_store_encryption_key`      | `string` | Session Store Encryption Key      | -       | -       | No       |

### Example `secrets.yaml`

> **Path:** `file referenced by .common.secret_file_path`

```yaml
common:
  mongo:
    uri: "mongodb://user:password@mongo:27017/vc"
apigw:
  api_server:
    basic_auth:
      users:
        <username>: "<password>"
  oidcrp:
    client_secret: "your-oidc-client-secret"
registry:
  admin_gui:
    password: "change-me-in-production"
    session_secret: "random-32-byte-secret"
verifier:
  oidc:
    subject_salt: "random-salt-for-pairwise-subjects"
ui:
  password: "change-me-in-production"
  session_cookie_authentication_key: "64-char-hex-hmac-key"
  session_store_encryption_key: "32-char-hex-encryption-key"
```


