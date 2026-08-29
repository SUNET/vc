# Configuration Reference

Complete reference for all configuration parameters in the VC system.

<!-- Auto-generated from Go source code. DO NOT EDIT MANUALLY. -->
<!-- Regenerate with: go run developer_tools/scripts/gen_config_docs/main.go -->

## Table of Contents

- [Environment Variables](#environment-variables)
- [Common](#common-top-level)
- [API Gateway (APIGW)](#apigw-top-level)
- [Issuer](#issuer-top-level)
- [Verifier](#verifier-top-level)
- [Registry](#registry-top-level)
- [Secrets File Reference](#secrets-file-reference)

## Environment Variables

These environment variables control service behavior outside of the YAML configuration file.

| Variable         | Description                                                                                                                                                                   | Example           |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- |
| `VC_CONFIG_YAML` | Path to the YAML configuration file. Each service reads this on startup.                                                                                                      | `config.yaml`     |
| `SSL_CERT_FILE`  | Path to a CA certificate file that Go's `crypto/x509` trusts for TLS verification. Required when services use self-signed or private CA certificates for inter-service HTTPS. | `/pki/rootCA.crt` |

## `common` (Top-level)

Shared configuration used across all services.

### `common`

> **Path:** `.common`

> **Constraint** (`mongo`, `sql`, `ha`): Mongo.URI is required when SQL.Backend is 'mongo' (the default primary-store backend) or when HA.Enable is true (HA caching has no relational backend yet, so it always uses Mongo); not required for a pure relational deployment (a non-mongo SQL.Backend with HA disabled).

| Field                 | Type     | Description                                                                                                                                                                                                                                                                                                                                             | Example                  | Default | Required |
| --------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------ | ------- | -------- |
| `production`          | `bool`   | Production mode                                                                                                                                                                                                                                                                                                                                         | -                        | `true`  | No       |
| `log`                 | `object` | Logging configuration                                                                                                                                                                                                                                                                                                                                   | -                        | -       | No       |
| `mongo`               | `object` | MongoDB configuration                                                                                                                                                                                                                                                                                                                                   | -                        | -       | No       |
| `sql`                 | `object` | Relational database configuration, used by services that support a relational storage backend as an alternative to MongoDB.                                                                                                                                                                                                                             | -                        | -       | No       |
| `tracing`             | `object` | OpenTelemetry tracing configuration                                                                                                                                                                                                                                                                                                                     | -                        | -       | No       |
| `metrics`             | `object` | OpenTelemetry metrics configuration                                                                                                                                                                                                                                                                                                                     | -                        | -       | No       |
| `kafka`               | `object` | Kafka message broker configuration                                                                                                                                                                                                                                                                                                                      | -                        | -       | No       |
| `secret_file_path`    | `string` | Path to a separate YAML file containing secrets; when set, secret values in config.yaml are cleared and only non-empty fields from the secrets file are applied.                                                                                                                                                                                        | `"/etc/vc/secrets.yaml"` | -       | No       |
| `ha`                  | `object` | High-availability mode. When Enable is true, caches use MongoDB (Common.Mongo.URI) instead of in-memory storage so state is shared across instances.                                                                                                                                                                                                    | -                        | -       | No       |
| `credential_registry` | `object` | An optional TS11 credential metadata registry client, used as an add-on to (not a replacement for) the existing vctm_file_path/vctm_url/mddl_file_path/mddl_url per-scope configuration: disabled by default, so existing deployments are unaffected until this is explicitly enabled and at least one scope sets vct or doctype instead of a file/URL. | -                        | -       | No       |
| `branding`            | `object` | Custom branding configuration (logo and favicon paths)                                                                                                                                                                                                                                                                                                  | -                        | -       | No       |
| `credential_metadata` | `object` | OAuth2 scope values to their credential configuration, required by apigw, issuer, and verifier Key: OAuth2 scope (e.g., "pid", "ehic", "diploma") - matches AuthorizationContext.Scope Each entry contains the VCTM reference, format, and other configuration for that credential type                                                                 | -                        | -       | No       |

### `log`

> **Path:** `.common.log`

| Field         | Type     | Description            | Example         | Default | Required |
| ------------- | -------- | ---------------------- | --------------- | ------- | -------- |
| `folder_path` | `string` | Path to the log folder | `"/var/log/vc"` | -       | No       |

### `mongo`

> **Path:** `.common.mongo`

| Field            | Type     | Description                                                                                                                                                                                                                                                                                                                                                                                                                   | Example                                    | Default | Required                    |
| ---------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------ | ------- | --------------------------- |
| `uri`            | `string` | MongoDB connection URI. Required when Common.SQL.Backend is "mongo" (the default primary-store backend) or when Common.HA.Enable is true (pkg/cache has no relational backend yet, so HA caching always uses Mongo regardless of the primary store's backend). Enforced by a Common-level struct validation rather than a plain "required" tag here, since the requirement depends on sibling fields of Common, not of Mongo. | `"mongodb://user:password@mongo:27017/vc"` | -       | No                          |
| `tls`            | `bool`   | TLS for the MongoDB connection. Can also be enabled via the connection URI parameter "tls=true".                                                                                                                                                                                                                                                                                                                              | -                                          | `false` | No                          |
| `ca_file_path`   | `string` | Path to a PEM-encoded CA certificate used to verify the MongoDB server's certificate. When empty, the system root CAs are used.                                                                                                                                                                                                                                                                                               | -                                          | -       | No                          |
| `cert_file_path` | `string` | Path to a PEM-encoded client certificate for mutual TLS (mTLS).                                                                                                                                                                                                                                                                                                                                                               | -                                          | -       | Yes (if key_file_path set)  |
| `key_file_path`  | `string` | Path to a PEM-encoded client private key for mutual TLS (mTLS).                                                                                                                                                                                                                                                                                                                                                               | -                                          | -       | Yes (if cert_file_path set) |

### `sql`

> **Path:** `.common.sql`

> **Constraint** (`postgres`, `mariadb`): When Backend is 'postgres', Postgres.Host and Postgres.User are required; when Backend is 'mariadb', MariaDB.Host and MariaDB.User are required. Enforced at the SQL struct level (rather than required_if tags on PostgresConfig/MariaDBConfig themselves) because 'Backend' lives on the parent SQL struct, not on those nested structs.

support a relational storage backend as an alternative to MongoDB.
Backend selection is config-time only: a running service uses exactly
one backend for its whole lifetime.

| Field      | Type     | Description                                                                                                                                                                                                                                 | Example | Default | Required                       |
| ---------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- | ------- | ------------------------------ |
| `backend`  | `string` | Backend selects the storage backend for services that support relational storage. "mongo" (default, current behavior) keeps existing Mongo-backed behavior unchanged; "postgres" and "mariadb" select the corresponding relational backend. | -       | `mongo` | No                             |
| `postgres` | `object` | Postgres-specific connection settings, used when Backend is "postgres".                                                                                                                                                                     | -       | -       | Yes (if backend is "postgres") |
| `mariadb`  | `object` | MariaDB/MySQL-specific connection settings, used when Backend is "mariadb".                                                                                                                                                                 | -       | -       | Yes (if backend is "mariadb")  |

### `postgres`

> **Path:** `.common.sql.postgres`

| Field            | Type     | Description                                                                                                                                                                                                                                                                               | Example      | Default   | Required                    |
| ---------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------ | --------- | --------------------------- |
| `host`           | `string` | Postgres server hostname. Required when Common.SQL.Backend is "postgres"; enforced by a SQL-level struct validation rather than a plain "required_if" tag here, since "Backend" lives on the parent SQL struct, not on PostgresConfig, and required_if can only reference sibling fields. | `"postgres"` | -         | No                          |
| `port`           | `int`    | Postgres server port                                                                                                                                                                                                                                                                      | -            | `5432`    | No                          |
| `user`           | `string` | Postgres connection user. Required when Common.SQL.Backend is "postgres" (see Host doc comment for why this isn't a required_if tag).                                                                                                                                                     | -            | -         | No                          |
| `password`       | `string` | Postgres connection password. May also be set via secrets.yaml (Common.SQL.Postgres.Password), following the same split as Mongo.URI.                                                                                                                                                     | -            | -         | No                          |
| `database`       | `string` | Postgres database name                                                                                                                                                                                                                                                                    | `"vc"`       | `vc`      | No                          |
| `ssl_mode`       | `string` | Postgres SSL mode: disable, require, verify-ca, or verify-full                                                                                                                                                                                                                            | -            | `disable` | No                          |
| `ca_file_path`   | `string` | Path to a PEM-encoded CA certificate used to verify the server's certificate.                                                                                                                                                                                                             | -            | -         | No                          |
| `cert_file_path` | `string` | Path to a PEM-encoded client certificate for mutual TLS (mTLS).                                                                                                                                                                                                                           | -            | -         | Yes (if key_file_path set)  |
| `key_file_path`  | `string` | Path to a PEM-encoded client private key for mutual TLS (mTLS).                                                                                                                                                                                                                           | -            | -         | Yes (if cert_file_path set) |
| `max_open_conns` | `int`    | Maximum number of open connections to the database.                                                                                                                                                                                                                                       | -            | `25`      | No                          |
| `max_idle_conns` | `int`    | Maximum number of idle connections in the pool.                                                                                                                                                                                                                                           | -            | `5`       | No                          |

### `mariadb`

> **Path:** `.common.sql.mariadb`

Kept as a separate struct from PostgresConfig (rather than shared) since
default port and TLS parameter semantics differ enough between the two
drivers to want independent validation tags.

| Field            | Type     | Description                                                                                                                                                                                                                                                                            | Example     | Default | Required                    |
| ---------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- | ------- | --------------------------- |
| `host`           | `string` | MariaDB server hostname. Required when Common.SQL.Backend is "mariadb"; enforced by a SQL-level struct validation rather than a plain "required_if" tag here, since "Backend" lives on the parent SQL struct, not on MariaDBConfig, and required_if can only reference sibling fields. | `"mariadb"` | -       | No                          |
| `port`           | `int`    | MariaDB server port                                                                                                                                                                                                                                                                    | -           | `3306`  | No                          |
| `user`           | `string` | MariaDB connection user. Required when Common.SQL.Backend is "mariadb" (see Host doc comment for why this isn't a required_if tag).                                                                                                                                                    | -           | -       | No                          |
| `password`       | `string` | MariaDB connection password. May also be set via secrets.yaml (Common.SQL.MariaDB.Password), following the same split as Mongo.URI.                                                                                                                                                    | -           | -       | No                          |
| `database`       | `string` | MariaDB database name                                                                                                                                                                                                                                                                  | `"vc"`      | `vc`    | No                          |
| `tls`            | `bool`   | TLS for the MariaDB connection.                                                                                                                                                                                                                                                        | -           | `false` | No                          |
| `ca_file_path`   | `string` | Path to a PEM-encoded CA certificate used to verify the server's certificate.                                                                                                                                                                                                          | -           | -       | No                          |
| `cert_file_path` | `string` | Path to a PEM-encoded client certificate for mutual TLS (mTLS).                                                                                                                                                                                                                        | -           | -       | Yes (if key_file_path set)  |
| `key_file_path`  | `string` | Path to a PEM-encoded client private key for mutual TLS (mTLS).                                                                                                                                                                                                                        | -           | -       | Yes (if cert_file_path set) |
| `max_open_conns` | `int`    | Maximum number of open connections to the database.                                                                                                                                                                                                                                    | -           | `25`    | No                          |
| `max_idle_conns` | `int`    | Maximum number of idle connections in the pool.                                                                                                                                                                                                                                        | -           | `5`     | No                          |

### `tracing`

> **Path:** `.common.tracing`, `.common.metrics`

| Field     | Type     | Description                            | Example         | Default | Required         |
| --------- | -------- | -------------------------------------- | --------------- | ------- | ---------------- |
| `enable`  | `bool`   | Enable activates OpenTelemetry tracing | -               | `false` | No               |
| `addr`    | `string` | OTEL collector address                 | `"jaeger:4318"` | -       | Yes (if enabled) |
| `timeout` | `int64`  | Timeout in seconds                     | -               | `10`    | No               |

### `kafka`

> **Path:** `.common.kafka`

| Field     | Type       | Description                                    | Example                          | Default | Required         |
| --------- | ---------- | ---------------------------------------------- | -------------------------------- | ------- | ---------------- |
| `enable`  | `bool`     | Kafka integration                              | -                                | `false` | No               |
| `brokers` | `[]string` | List of Kafka broker addresses                 | `["kafka0:9092", "kafka1:9092"]` | -       | Yes (if enabled) |
| `sasl`    | `object`   | SASL authentication for Kafka connections      | -                                | -       | No               |
| `mtls`    | `object`   | Mutual TLS (mTLS) for Kafka broker connections | -                                | -       | No               |

### `sasl`

> **Path:** `.common.kafka.sasl`

| Field       | Type     | Description                                          | Example | Default         | Required         |
| ----------- | -------- | ---------------------------------------------------- | ------- | --------------- | ---------------- |
| `enable`    | `bool`   | Enable activates SASL authentication                 | -       | `false`         | No               |
| `mechanism` | `string` | SASL mechanism (PLAIN, SCRAM-SHA-256, SCRAM-SHA-512) | -       | `SCRAM-SHA-512` | No               |
| `username`  | `string` | SASL username                                        | -       | -               | Yes (if enabled) |
| `password`  | `string` | SASL password                                        | -       | -               | Yes (if enabled) |

### `mtls`

> **Path:** `.common.kafka.mtls`

| Field                  | Type     | Description                                                                                     | Example | Default | Required         |
| ---------------------- | -------- | ----------------------------------------------------------------------------------------------- | ------- | ------- | ---------------- |
| `enable`               | `bool`   | MTLS for the connection                                                                         | -       | `false` | No               |
| `ca_cert_path`         | `string` | Path to a CA certificate for verifying the remote peer (optional; uses system roots if empty)   | -       | -       | No               |
| `cert_file_path`       | `string` | Path to a client certificate for mutual authentication                                          | -       | -       | Yes (if enabled) |
| `key_file_path`        | `string` | Path to the client private key                                                                  | -       | -       | Yes (if enabled) |
| `insecure_skip_verify` | `bool`   | InsecureSkipVerify disables certificate verification (TESTING ONLY — never use in production)   | -       | `false` | No               |

### `ha`

> **Path:** `.common.ha`

| Field                 | Type     | Description                                                                   | Example | Default    | Required |
| --------------------- | -------- | ----------------------------------------------------------------------------- | ------- | ---------- | -------- |
| `enable`              | `bool`   | HA mode; when true caches are backed by MongoDB instead of in-memory storage. | -       | `false`    | No       |
| `cache_database_name` | `string` | MongoDB database name used for caches.                                        | -       | `vc_cache` | No       |

### `credential_registry`

> **Path:** `.common.credential_registry`

| Field              | Type       | Description                                                                                                                                                                                                   | Example | Default | Required         |
| ------------------ | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- | ------- | ---------------- |
| `enable`           | `bool`     | Registry-backed resolution for any scope that sets vct or doctype instead of a local file/URL. Existing vctm_file_path/vctm_url/mddl_file_path/mddl_url-configured scopes are entirely unaffected either way. | -       | `false` | No               |
| `registries`       | `array`    | Ordered list of logical (independent) registries. A later entry overrides an earlier one for the same vct/doctype. Required if Enable is true.                                                                | -       | -       | Yes (if enabled) |
| `refresh_interval` | `duration` | How long a registry's discovery index is trusted before being re-fetched. Zero means fetch once and cache forever for the lifetime of this process.                                                           | -       | `1h`    | No               |

### `registries` entry

> **Path:** `.common.credential_registry.registries[]`

| Field     | Type    | Description                                                                         | Example | Default | Required |
| --------- | ------- | ----------------------------------------------------------------------------------- | ------- | ------- | -------- |
| `mirrors` | `array` | Set of endpoints serving this logical registry's content. At least one is required. | -       | -       | Yes      |

### `mirrors` entry

> **Path:** `.common.credential_registry.registries[].mirrors[]`

| Field      | Type       | Description                                           | Example                        | Default | Required |
| ---------- | ---------- | ----------------------------------------------------- | ------------------------------ | ------- | -------- |
| `base_url` | `string`   | Registry's origin, e.g. "https://registry.siros.org". | `"https://registry.siros.org"` | -       | Yes      |
| `timeout`  | `duration` | Timeout bounds each HTTP request to this registry.    | -                              | `10s`   | No       |

### `branding`

> **Path:** `.common.branding`

| Field          | Type     | Description                                                                             | Example | Default | Required |
| -------------- | -------- | --------------------------------------------------------------------------------------- | ------- | ------- | -------- |
| `logo_path`    | `string` | File path to a custom logo PNG image; when empty, the built-in SUNET logo is used       | -       | -       | No       |
| `favicon_path` | `string` | File path to a custom favicon PNG image; when empty, the built-in SUNET favicon is used | -       | -       | No       |

### `credential_metadata` entry

> **Path:** `.common.credential_metadata.<credential scope>`

| Field               | Type     | Description                                                                                                                                                                                                                                                                                                          | Example       | Default     | Required                                                                         |
| ------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------- | ----------- | -------------------------------------------------------------------------------- |
| `vctm_file_path`    | `string` | Path to a local VCTM JSON file. When set, apigw will publish the VCTM at /type-metadata/:scope. Used for every format except mso_mdoc.                                                                                                                                                                               | -             | -           | Yes (if none of vctm_url, mddl_file_path, mddl_url, vct, doctype set)            |
| `vctm_url`          | `string` | URL where the VCTM is already published externally. When set, the VCTM is fetched from this URL at startup for internal use but NOT re-published by apigw. Used for every format except mso_mdoc.                                                                                                                    | -             | -           | Yes (if none of vctm_file_path, mddl_file_path, mddl_url, vct, doctype set)      |
| `vct`               | `string` | Vct claim value to resolve via Common.CredentialRegistry (a TS11 registry client), used only when neither VCTMFilePath nor VCTMUrl is set. Requires Common.CredentialRegistry.Enable - this field being present in a scope's config does not itself turn registry lookups on. Used for every format except mso_mdoc. | -             | -           | Yes (if none of vctm_file_path, vctm_url, mddl_file_path, mddl_url, doctype set) |
| `mddl_file_path`    | `string` | Path to a local MDDL (mso_mdoc) schema JSON file, as produced by registry-cli's mddl format generator.                                                                                                                                                                                                               | -             | -           | Yes (if none of vctm_file_path, vctm_url, mddl_url, vct, doctype set)            |
| `mddl_url`          | `string` | URL where the MDDL schema is already published externally. The mso_mdoc analogue of vctm_url.                                                                                                                                                                                                                        | -             | -           | Yes (if none of vctm_file_path, vctm_url, mddl_file_path, vct, doctype set)      |
| `doctype`           | `string` | Mdoc doctype value to resolve via Common.CredentialRegistry, used only when neither MDDLFilePath nor MDDLUrl is set. Requires Common.CredentialRegistry.Enable, same as VCT. Used only for mso_mdoc.                                                                                                                 | -             | -           | Yes (if none of vctm_file_path, vctm_url, mddl_file_path, mddl_url, vct set)     |
| `format`            | `string` | Credential format to issue                                                                                                                                                                                                                                                                                           | `"dc+sd-jwt"` | `dc+sd-jwt` | No                                                                               |
| `disclosure_policy` | `object` | The embedded disclosure policy for this credential type. Per ARF 3.0 §6.6.2.8 and CIR 2024/2979 Annex III. Only applicable to QEAAs and PuB-EAAs (not PIDs). When omitted, the metadata publishes policy_type "none" (no restrictions).                                                                              | -             | -           | No                                                                               |
| `attributes`        | `object` | Claim names to their source fields and transformation rules for credential issuance                                                                                                                                                                                                                                  | -             | -           | No                                                                               |

### `disclosure_policy`

> **Path:** `.common.credential_metadata.<credential scope>.disclosure_policy`

Per CIR 2024/2979 Annex III, three common policy types are defined.

| Field                        | Type       | Description                                                                                                                                                                                                                                                                                           | Example | Default | Required                                             |
| ---------------------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- | ------- | ---------------------------------------------------- |
| `policy_type`                | `string`   | PolicyType identifies the disclosure policy type. One of: - "none": no policy applies (default) - "authorized_relying_parties": only RPs in the allowlist may receive this attestation - "specific_root_of_trust": only RPs with access certificates from specific roots may receive this attestation | -       | `none`  | No                                                   |
| `authorized_relying_parties` | `[]string` | List of EU-wide unique Relying Party identifiers (as found in the Wallet-Relying Party Registration Certificate). Required when policy_type is "authorized_relying_parties".                                                                                                                          | -       | -       | Yes (if policy_type is "authorized_relying_parties") |
| `trusted_roots`              | `[]string` | List of root or intermediate certificate SHA-256 fingerprints (hex-encoded, 64 characters) from which the RP's access certificate must be derived. Required when policy_type is "specific_root_of_trust".                                                                                             | -       | -       | Yes (if policy_type is "specific_root_of_trust")     |

## `apigw` (Top-level)

Configuration for the API Gateway service that handles credential issuance requests.

### `apigw`

> **Path:** `.apigw`

| Field                     | Type     | Description                                                                                                                                                                                                         | Example                     | Default | Required |
| ------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------- | ------- | -------- |
| `api_server`              | `object` | HTTP API server configuration                                                                                                                                                                                       | -                           | -       | Yes      |
| `admin_ui_enable`         | `bool`   | The admin web UI. When false (default), the /ui routes are not registered. This must be explicitly set to true to enable the admin interface.                                                                       | -                           | `false` | No       |
| `key_config`              | `object` | Signing key configuration                                                                                                                                                                                           | -                           | -       | Yes      |
| `data_sources`            | `object` | Credential types to their data sources                                                                                                                                                                              | -                           | -       | Yes      |
| `auth_providers`          | `object` | How users authenticate (SAML, OIDC)                                                                                                                                                                                 | -                           | -       | No       |
| `remotes`                 | `object` | Named external API connections referenced by DataSources.ExternalAPI                                                                                                                                                | `"ladok"`                   | -       | No       |
| `delivery`                | `object` | Delivery groups credential delivery to wallets (OpenID4VCI, credential offers)                                                                                                                                      | -                           | -       | Yes      |
| `issuer_metadata`         | `object` | OpenID4VCI issuer metadata                                                                                                                                                                                          | -                           | -       | No       |
| `public_url`              | `string` | Public URL of this service (must be valid HTTP/HTTPS URL)                                                                                                                                                           | `"https://issuer.sunet.se"` | -       | Yes      |
| `issuer_client`           | `object` | GRPC client config for issuer                                                                                                                                                                                       | -                           | -       | Yes      |
| `registry_client`         | `object` | GRPC client config for registry                                                                                                                                                                                     | -                           | -       | Yes      |
| `identity_mapping_import` | `object` | Automatic import of identity mappings from JSON files at startup. When configured, APIGW reads JSON files and imports them into the identity mappings collection on first startup (skipped if data already exists). | -                           | -       | No       |
| `trust`                   | `object` | Trust evaluation configuration for OpenID4VP credential validation. When configured, credentials presented via VP are validated against a PDP.                                                                      | -                           | -       | No       |
| `federation`              | `object` | OpenID Federation entity configuration. When enabled, serves /.well-known/openid-federation as a self-signed JWT.                                                                                                   | -                           | -       | No       |
| `rate_limit`              | `object` | Per-endpoint rate limiting for the APIGW.                                                                                                                                                                           | -                           | -       | No       |

### `api_server`

> **Path:** `.apigw.api_server`, `.issuer.api_server`, `.verifier.api_server`, `.registry.api_server`

| Field              | Type     | Description                                                                                                                                                      | Example | Default | Required |
| ------------------ | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- | ------- | -------- |
| `addr`             | `string` | Listen address for the HTTP server                                                                                                                               | -       | `:8080` | No       |
| `served_by_header` | `string` | The X-Served-By response header value for HA troubleshooting. Empty (default): header is not set. "hostname": uses os.Hostname(). Any other value is used as-is. | -       | -       | No       |
| `tls`              | `object` | TLS                                                                                                                                                              | -       | -       | No       |
| `api_auth`         | `object` | API Auth                                                                                                                                                         | -       | -       | No       |
| `cors`             | `object` | CORS                                                                                                                                                             | -       | -       | No       |
| `trust_proxy_tls`  | `bool`   | The Secure flag on session cookies even when TLS is not enabled on this server. Use this when running behind a TLS-terminating reverse proxy.                    | -       | `false` | No       |

### `tls`

> **Path:** `.apigw.api_server.tls`, `.issuer.api_server.tls`, `.verifier.api_server.tls`, `.registry.api_server.tls`

| Field            | Type     | Description                 | Example | Default | Required         |
| ---------------- | -------- | --------------------------- | ------- | ------- | ---------------- |
| `enable`         | `bool`   | TLS                         | -       | `false` | No               |
| `cert_file_path` | `string` | Path to the TLS certificate | -       | -       | Yes (if enabled) |
| `key_file_path`  | `string` | Path to the TLS private key | -       | -       | Yes (if enabled) |

### `api_auth`

> **Path:** `.apigw.api_server.api_auth`, `.issuer.api_server.api_auth`, `.verifier.api_server.api_auth`, `.registry.api_server.api_auth`

> **Constraint** (`jwks`, `oidc`): JWKS and OIDC are mutually exclusive — enable at most one.
>
> **Constraint** (`rules`, `rules_file`): Authorization rules require JWKS or OIDC to be enabled.

JWKS and OIDC are mutually exclusive
If neither is enabled, no authentication is applied (open access)

When Rules (and/or RulesFile) are configured, each authenticated request is
checked against a SPOCP engine. A query of the form

(vc (service <SERVICE>)(method <HTTP_METHOD>)(path <REQUEST_PATH>)(subject <JWT_SUBJECT>)(authentic_source <SOURCE>)(scope <SCOPE>))

is evaluated; the request is allowed only if a matching rule exists.
All six parts are required in every rule. Use * as wildcard for fields
you don't want to restrict.
The <SERVICE> value is supplied by the calling service at middleware
registration time. When two services share endpoints, rules for one
service do not grant access to the other.
When no rules are configured, any valid Bearer JWT grants access.

| Field        | Type       | Description                                                                                                                                                                                                                                                                                    | Example                                                                                                          | Default | Required |
| ------------ | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | ------- | -------- |
| `jwks`       | `object`   | Static JWKS Bearer token authentication configuration When enabled, requests are validated against a manually configured JWKS URL                                                                                                                                                              | -                                                                                                                | -       | No       |
| `oidc`       | `object`   | OIDC Bearer token authentication configuration When enabled, the JWKS endpoint is auto-discovered from the issuer's .well-known/openid-configuration and Bearer JWTs are validated locally The RP fields (client_id, redirect_uri, etc.) also enable the admin UI login flow via OIDC redirect | -                                                                                                                | -       | No       |
| `rules`      | `[]string` | SPOCP S-expression authorization rules loaded into an in-process engine. All six parts (service, method, path, subject, authentic_source, scope) are mandatory in every rule — use * for wildcards. Rules apply regardless of whether JWKS or OIDC is the active auth method                   | `["(vc (service apigw)(method POST)(path /api/v1/upload)(subject alice)(authentic_source SUNET)(scope eduid))"]` | -       | No       |
| `rules_file` | `string`   | Optional path to a file containing SPOCP rules (one per line) Rules from this file are loaded in addition to the inline Rules list                                                                                                                                                             | -                                                                                                                | -       | No       |

### `jwks`

> **Path:** `.apigw.api_server.api_auth.jwks`, `.issuer.api_server.api_auth.jwks`, `.verifier.api_server.api_auth.jwks`, `.registry.api_server.api_auth.jwks`

> **Constraint** (`jwks_url`, `jwks_file_path`): Exactly one of jwks_url or jwks_file_path must be set when enable is true.

| Field            | Type     | Description                                                                 | Example                                            | Default | Required                                    |
| ---------------- | -------- | --------------------------------------------------------------------------- | -------------------------------------------------- | ------- | ------------------------------------------- |
| `enable`         | `bool`   | Static JWKS Bearer token authentication                                     | -                                                  | `false` | No                                          |
| `jwks_url`       | `string` | URL of the JSON Web Key Set used to validate token signatures.              | `"https://auth.example.com/.well-known/jwks.json"` | -       | No (mutually exclusive with jwks_file_path) |
| `jwks_file_path` | `string` | Local file path to a JWKS JSON file used to validate token signatures.      | -                                                  | -       | No (mutually exclusive with jwks_url)       |
| `issuer`         | `string` | Expected "iss" claim. Tokens with a different issuer are rejected           | -                                                  | -       | Yes (if enabled)                            |
| `audience`       | `string` | Expected "aud" claim. Tokens that do not contain this audience are rejected | -                                                  | -       | Yes (if enabled)                            |

### `oidc`

> **Path:** `.apigw.api_server.api_auth.oidc`, `.issuer.api_server.api_auth.oidc`, `.verifier.api_server.api_auth.oidc`, `.registry.api_server.api_auth.oidc`

It serves two purposes:
- API auth: Bearer JWTs in Authorization headers are validated locally
against the provider's JWKS (auto-discovered from IssuerURL).
- Admin UI login: the RP fields (ClientID, RedirectURI, Scopes) enable
an authorization-code redirect flow so admins log in via the OIDC provider.

| Field           | Type       | Description                                                                  | Example                                   | Default | Required         |
| --------------- | ---------- | ---------------------------------------------------------------------------- | ----------------------------------------- | ------- | ---------------- |
| `enable`        | `bool`     | OIDC authentication                                                          | -                                         | `false` | No               |
| `issuer_url`    | `string`   | OIDC provider's issuer URL used for discovery and "iss" claim validation.    | `"https://auth.example.com"`              | -       | Yes (if enabled) |
| `audience`      | `string`   | Expected "aud" claim. Tokens that do not contain this audience are rejected. | -                                         | -       | Yes (if enabled) |
| `client_id`     | `string`   | OAuth2 client identifier registered with the OIDC provider.                  | -                                         | -       | Yes (if enabled) |
| `client_secret` | `string`   | OAuth2 client secret. May be empty for public clients.                       | -                                         | -       | No               |
| `redirect_uri`  | `string`   | Callback URL for the admin UI OIDC login flow.                               | `"https://apigw.example.com/ui/callback"` | -       | Yes (if enabled) |
| `scopes`        | `[]string` | OAuth2/OIDC scopes to request (default: ["openid"]).                         | -                                         | -       | No               |

### `cors`

> **Path:** `.apigw.api_server.cors`, `.issuer.api_server.cors`, `.verifier.api_server.cors`, `.registry.api_server.cors`

| Field             | Type       | Description                  | Example                                               | Default | Required |
| ----------------- | ---------- | ---------------------------- | ----------------------------------------------------- | ------- | -------- |
| `allowed_origins` | `[]string` | List of allowed CORS origins | `["https://wallet.sunet.se", "https://app.sunet.se"]` | `[]`    | No       |

### `key_config`

> **Path:** `.apigw.key_config`, `.issuer.key_config`, `.issuer.access_certificate.key_config`, `.verifier.key_config`, `.registry.token_status_lists.key_config`

Supports both file-based and HSM-based keys with explicit control.

| Field              | Type     | Description                                                                                                               | Example           | Default | Required                          |
| ------------------ | -------- | ------------------------------------------------------------------------------------------------------------------------- | ----------------- | ------- | --------------------------------- |
| `private_key_path` | `string` | File-based configuration                                                                                                  | -                 | -       | Yes (if pkcs11 not set)           |
| `chain_path`       | `string` | Path to certificate chain (optional)                                                                                      | -                 | -       | No                                |
| `pkcs11`           | `object` | HSM-based configuration                                                                                                   | -                 | -       | Yes (if private_key_path not set) |
| `source`           | `object` | Source selection (determines which config to use) If empty, tries in order: File (if FilePath set), then HSM (if HSM set) | -                 | -       | No                                |
| `enable_file`      | `bool`   | File-based key loading (default: true if FilePath set)                                                                    | -                 | -       | No                                |
| `enable_hsm`       | `bool`   | HSM-based key loading (default: true if HSM set)                                                                          | -                 | -       | No                                |
| `priority`         | `array`  | Fallback order when both are enabled If nil, uses Source field or auto-detects based on what's configured                 | `["hsm", "file"]` | -       | No                                |

### `pkcs11`

> **Path:** `.apigw.key_config.pkcs11`, `.issuer.key_config.pkcs11`, `.issuer.access_certificate.key_config.pkcs11`, `.verifier.key_config.pkcs11`, `.registry.token_status_lists.key_config.pkcs11`

| Field         | Type     | Description                       | Example                             | Default | Required |
| ------------- | -------- | --------------------------------- | ----------------------------------- | ------- | -------- |
| `module_path` | `string` | Path to the PKCS#11 library       | `"/usr/lib/softhsm/libsofthsm2.so"` | -       | No       |
| `slot_id`     | `uint`   | HSM slot ID                       | `0`                                 | -       | No       |
| `pin`         | `string` | User PIN for the slot             | `"1234"`                            | -       | No       |
| `key_label`   | `string` | Label of the key to use           | `"my-signing-key"`                  | -       | No       |
| `key_id`      | `string` | Identifier for the JWT kid header | `"key-1"`                           | -       | No       |

### `data_sources`

> **Path:** `.apigw.data_sources`

Each key under a data source is a credential type.

| Field          | Type     | Description                                                                                                   | Example | Default | Required |
| -------------- | -------- | ------------------------------------------------------------------------------------------------------------- | ------- | ------- | -------- |
| `datastore`    | `object` | Credential types backed by a pre-loaded datastore (e.g. MongoDB)                                              | -       | -       | No       |
| `assertion`    | `object` | Credential types backed by authentication assertions (SAML attributes or OIDC claims)                         | -       | -       | No       |
| `external_api` | `object` | Credential types backed by an external API Each credential references a named remote defined in APIGW.Remotes | -       | -       | No       |

### `datastore`

> **Path:** `.apigw.data_sources.datastore`

| Field    | Type     | Description                                                                                                                                                                      | Example | Default | Required |
| -------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- | ------- | -------- |
| `scopes` | `object` | Credential scope names to their datastore configuration                                                                                                                          | -       | -       | No       |
| `import` | `object` | Automatic data import from JSON files at startup. When configured, APIGW reads JSON files and imports them into the datastore on first startup (skipped if data already exists). | -       | -       | No       |

### `scopes` entry

> **Path:** `.apigw.data_sources.datastore.scopes.<credential scope>`

| Field           | Type       | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Example                                 | Default | Required |
| --------------- | ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------- | ------- | -------- |
| `auth_provider` | `string`   | Auth provider for this credential type (openid4vp, saml, or oidc)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | -                                       | -       | Yes      |
| `auth_claims`   | `[]string` | The normalized claim names used for datastore identity lookup when auth_provider is saml or oidc. Not used for openid4vp (use AuthScopes instead). These names must match the BSON field names under "identities." in the datastore. Use attribute_mappings (in auth_providers) to normalize provider-specific attribute names (e.g. SAML urn:oid:2.5.4.42, eIDAS date_of_birth) to these canonical names. Available identity fields: given_name, family_name, birth_date, birth_place, authentic_source_person_id, personal_administrative_number. | `[given_name, family_name, birth_date]` | -       | No       |
| `auth_scopes`   | `object`   | Credential scope keys to their per-scope authentication config. Used only for openid4vp: the wallet must present a credential matching any one of the listed scopes (OR logic). Each entry specifies which claims to extract from that particular credential type.                                                                                                                                                                                                                                                                                  | -                                       | -       | No       |

### `auth_scopes` entry

> **Path:** `.apigw.data_sources.datastore.scopes.<credential scope>.auth_scopes.<key>`

Each entry represents one acceptable credential type the wallet can present.

| Field         | Type       | Description                                               | Example                                 | Default | Required |
| ------------- | ---------- | --------------------------------------------------------- | --------------------------------------- | ------- | -------- |
| `auth_claims` | `[]string` | The identity claims to extract from this credential type. | `[given_name, family_name, birth_date]` | -       | Yes      |

### `import`

> **Path:** `.apigw.data_sources.datastore.import`

| Field        | Type       | Description                                                                                                                                                                       | Example                                                     | Default | Required |
| ------------ | ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- | ------- | -------- |
| `file_paths` | `[]string` | JSON files to import into the datastore. Each JSON file should contain a map of person IDs to CompleteDocument objects. Import is skipped if the datastore already contains data. | `["./bootstrapping/pid.json", "./bootstrapping/ehic.json"]` | -       | Yes      |
| `users`      | `[]string` | Users limits which person IDs to import. If empty, all persons are imported.                                                                                                      | `["100", "102"]`                                            | -       | No       |

### `assertion`

> **Path:** `.apigw.data_sources.assertion`

| Field    | Type     | Description                                             | Example | Default | Required |
| -------- | -------- | ------------------------------------------------------- | ------- | ------- | -------- |
| `scopes` | `object` | Credential scope names to their assertion configuration | -       | -       | No       |

### `scopes` entry

> **Path:** `.apigw.data_sources.assertion.scopes.<credential scope>`

The data comes directly from the SAML attributes or OIDC claims.

| Field           | Type     | Description                                           | Example | Default | Required |
| --------------- | -------- | ----------------------------------------------------- | ------- | ------- | -------- |
| `auth_provider` | `string` | Auth provider for this credential type (saml or oidc) | -       | -       | Yes      |

### `external_api`

> **Path:** `.apigw.data_sources.external_api`

| Field    | Type     | Description                                                | Example | Default | Required |
| -------- | -------- | ---------------------------------------------------------- | ------- | ------- | -------- |
| `scopes` | `object` | Credential scope names to their external API configuration | -       | -       | No       |

### `scopes` entry

> **Path:** `.apigw.data_sources.external_api.scopes.<credential scope>`

| Field               | Type     | Description                                       | Example | Default | Required |
| ------------------- | -------- | ------------------------------------------------- | ------- | ------- | -------- |
| `remote`            | `string` | Name of a remote defined in Remotes               | -       | -       | Yes      |
| `auth_provider`     | `string` | Auth provider to identify the user (saml or oidc) | -       | -       | Yes      |
| `attribute_mapping` | `object` | How to map API response data to credential claims | -       | -       | No       |

### `attribute_mapping` entry

> **Path:** `.apigw.data_sources.external_api.scopes.<credential scope>.attribute_mapping.<attribute>`, `.apigw.auth_providers.saml.attribute_mapping.<attribute>`, `.apigw.auth_providers.oidc.attribute_mapping.<attribute>`

Generic across protocols (SAML, OIDC, etc.) - uses protocol-specific identifiers as keys

| Field       | Type     | Description                                                                                                                                              | Example                 | Default | Required |
| ----------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------- | ------- | -------- |
| `claim`     | `string` | Target claim name (supports dot-notation for nesting)                                                                                                    | `"identity.given_name"` | -       | Yes      |
| `required`  | `bool`   | Required indicates if this attribute must be present in the assertion/response                                                                           | -                       | `false` | No       |
| `transform` | `string` | Optional transformation to apply Supported: "lowercase", "uppercase", "trim", "country_alpha2", "country_alpha3"                                         | -                       | -       | No       |
| `default`   | `string` | Optional default value if attribute is missing                                                                                                           | -                       | -       | No       |
| `as_array`  | `bool`   | AsArray wraps a scalar value in a single-element array before setting the claim. No-op when the value is already a slice (e.g. multi-valued OIDC claim). | -                       | -       | No       |

### `auth_providers`

> **Path:** `.apigw.auth_providers`

| Field  | Type     | Description               | Example | Default | Required |
| ------ | -------- | ------------------------- | ------- | ------- | -------- |
| `saml` | `object` | The SAML SP auth provider | -       | -       | No       |
| `oidc` | `object` | The OIDC RP auth provider | -       | -       | No       |

### `saml`

> **Path:** `.apigw.auth_providers.saml`

> **Constraint** (`mdq_server`, `static_idp_metadata`): Exactly one of mdq_server or static_idp_metadata must be set when enable is true. Mutual exclusivity is enforced by field tags.

| Field                        | Type     | Description                                                                                                                                                                                                                                                                                                                                               | Example                                   | Default | Required                                         |
| ---------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------- | ------- | ------------------------------------------------ |
| `enable`                     | `bool`   | SAML support (default: false)                                                                                                                                                                                                                                                                                                                             | -                                         | `false` | No                                               |
| `entity_id`                  | `string` | SAML SP entity identifier (typically the metadata URL)                                                                                                                                                                                                                                                                                                    | `"https://issuer.sunet.se/saml/metadata"` | -       | Yes (if enabled)                                 |
| `metadata_url`               | `string` | Public URL where SP metadata is served (optional, auto-generated if empty)                                                                                                                                                                                                                                                                                | -                                         | -       | No                                               |
| `mdq_server`                 | `string` | Base URL for MDQ (Metadata Query Protocol) server (must end with /)                                                                                                                                                                                                                                                                                       | `"https://md.sunet.se/entities/"`         | -       | No (mutually exclusive with static_idp_metadata) |
| `static_idp_metadata`        | `object` | A single static IdP as alternative to MDQ                                                                                                                                                                                                                                                                                                                 | -                                         | -       | No (mutually exclusive with mdq_server)          |
| `certificate_path`           | `string` | Path to X.509 certificate for SAML signing/encryption TODO(pki): Migrate to pki.KeyConfig for consistency with other services and to enable HSM-backed SAML signing keys in the future.                                                                                                                                                                   | -                                         | -       | Yes (if enabled)                                 |
| `private_key_path`           | `string` | Path to private key for SAML signing/encryption TODO(pki): See CertificatePath TODO — both fields would be replaced by a single KeyConfig.                                                                                                                                                                                                                | -                                         | -       | Yes (if enabled)                                 |
| `acs_endpoint`               | `string` | Assertion Consumer Service URL where IdP sends SAML responses                                                                                                                                                                                                                                                                                             | `"https://issuer.sunet.se/saml/acs"`      | -       | Yes (if enabled)                                 |
| `session_duration`           | `int`    | Maximum time in seconds an in-flight SAML authentication flow (AuthnRequest → Response) may remain active before it expires                                                                                                                                                                                                                               | -                                         | `300`   | No                                               |
| `attribute_mapping`          | `object` | AttributeMapping normalizes provider-specific attribute names (e.g. SAML OIDs) to canonical claim names. Applied to ALL attributes in the assertion. Which normalized attributes are used depends on the data source: - assertion: VCTM determines which go into the credential - datastore: auth_claims determines which are used for DB identity lookup | -                                         | -       | Yes (if enabled)                                 |
| `metadata_signing_cert_path` | `string` | Path to the X.509 certificate used to verify metadata signatures. When set, all fetched metadata (MDQ and static) must carry a valid XML signature from this certificate.                                                                                                                                                                                 | -                                         | -       | No                                               |
| `allow_unsigned_metadata`    | `bool`   | AllowUnsignedMetadata permits MDQ/URL metadata without signature verification. This is INSECURE (MITM → fake IdP) and should only be used in development. When false (default), MDQ and URL metadata sources require MetadataSigningCertPath. Local metadata files are allowed unsigned regardless (with a startup warning).                              | -                                         | `false` | No                                               |
| `metadata_cache_ttl`         | `int`    | MetadataCacheTTL in seconds (default: 3600) - how long to cache IdP metadata from MDQ                                                                                                                                                                                                                                                                     | -                                         | -       | No                                               |

### `static_idp_metadata`

> **Path:** `.apigw.auth_providers.saml.static_idp_metadata`

| Field           | Type     | Description                                                                   | Example | Default | Required                                          |
| --------------- | -------- | ----------------------------------------------------------------------------- | ------- | ------- | ------------------------------------------------- |
| `entity_id`     | `string` | IdP entity identifier                                                         | -       | -       | Yes                                               |
| `metadata_path` | `string` | File path to IdP metadata XML                                                 | -       | -       | Yes (if metadata_url not set; mutually exclusive) |
| `metadata_url`  | `string` | HTTP(S) URL to fetch IdP metadata from (mutually exclusive with MetadataPath) | -       | -       | No                                                |

### `oidc`

> **Path:** `.apigw.auth_providers.oidc`

> **Constraint** (`scopes`): The 'openid' scope is mandatory when OIDC RP is enabled.

| Field               | Type       | Description                                                                                                                                                                                                                                                                                                                                                        | Example                                     | Default                          | Required         |
| ------------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------- | -------------------------------- | ---------------- |
| `enable`            | `bool`     | OIDC RP support (default: false)                                                                                                                                                                                                                                                                                                                                   | -                                           | `false`                          | No               |
| `registration`      | `object`   | How the client obtains credentials from the OIDC Provider. Exactly one of preconfigured or dynamic must be set: - preconfigured: pre-registered client_id and client_secret - dynamic: RFC 7591 dynamic client registration (credentials obtained at startup)                                                                                                      | -                                           | -                                | Yes (if enabled) |
| `redirect_uri`      | `string`   | Callback URL where the OIDC Provider sends the authorization response                                                                                                                                                                                                                                                                                              | `"https://issuer.sunet.se/oidcrp/callback"` | -                                | Yes (if enabled) |
| `issuer_url`        | `string`   | OIDC Provider's issuer URL for discovery Used for .well-known/openid-configuration discovery                                                                                                                                                                                                                                                                       | `"https://accounts.google.com"`             | -                                | Yes (if enabled) |
| `scopes`            | `[]string` | OAuth2/OIDC scopes to request                                                                                                                                                                                                                                                                                                                                      | -                                           | `["openid", "profile", "email"]` | No               |
| `session_duration`  | `int`      | Maximum time in seconds an in-flight OIDC authorization flow (state, nonce, PKCE verifier) may remain active before it expires                                                                                                                                                                                                                                     | -                                           | `300`                            | No               |
| `client_name`       | `string`   | Human-readable name for the OIDC client, shown during dynamic registration or consent                                                                                                                                                                                                                                                                              | -                                           | -                                | No               |
| `client_uri`        | `string`   | URL to the client's homepage, used for display during consent                                                                                                                                                                                                                                                                                                      | -                                           | -                                | No               |
| `logo_uri`          | `string`   | URL to the client's logo image, shown during consent screens                                                                                                                                                                                                                                                                                                       | -                                           | -                                | No               |
| `contacts`          | `[]string` | List of email addresses for responsible parties of this client                                                                                                                                                                                                                                                                                                     | -                                           | -                                | No               |
| `tos_uri`           | `string`   | URL to the client's Terms of Service document                                                                                                                                                                                                                                                                                                                      | -                                           | -                                | No               |
| `policy_uri`        | `string`   | URL to the client's Privacy Policy document                                                                                                                                                                                                                                                                                                                        | -                                           | -                                | No               |
| `attribute_mapping` | `object`   | AttributeMapping normalizes OIDC claim names to canonical claim names. Optional: when omitted, OIDC claims pass through as-is (standard names already match). Which normalized attributes are used depends on the data source: - assertion: VCTM determines which go into the credential - datastore: auth_claims determines which are used for DB identity lookup | -                                           | -                                | No               |

### `registration`

> **Path:** `.apigw.auth_providers.oidc.registration`

| Field           | Type     | Description                                                                                                                  | Example | Default | Required                                           |
| --------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------- | ------- | ------- | -------------------------------------------------- |
| `preconfigured` | `object` | Preconfigured uses pre-registered client credentials. Set this when the client is already registered with the OIDC Provider. | -       | -       | Yes (if dynamic not set; mutually exclusive)       |
| `dynamic`       | `object` | Dynamic uses RFC 7591 dynamic client registration. Set this when the client should register itself at startup.               | -       | -       | Yes (if preconfigured not set; mutually exclusive) |

### `preconfigured`

> **Path:** `.apigw.auth_providers.oidc.registration.preconfigured`

| Field           | Type     | Description                                       | Example | Default | Required         |
| --------------- | -------- | ------------------------------------------------- | ------- | ------- | ---------------- |
| `enable`        | `bool`   | Enable activates preconfigured client credentials | -       | -       | No               |
| `client_id`     | `string` | OIDC client identifier                            | -       | -       | Yes (if enabled) |
| `client_secret` | `string` | OIDC client secret                                | -       | -       | Yes (if enabled) |

### `dynamic`

> **Path:** `.apigw.auth_providers.oidc.registration.dynamic`

When set, client credentials are obtained automatically at startup and
persisted in the database.

| Field                  | Type     | Description                                                                    | Example | Default | Required         |
| ---------------------- | -------- | ------------------------------------------------------------------------------ | ------- | ------- | ---------------- |
| `enable`               | `bool`   | Enable activates dynamic client registration                                   | -       | -       | No               |
| `initial_access_token` | `string` | Bearer token for registration Required by some OIDC Providers (e.g., Keycloak) | -       | -       | Yes (if enabled) |

### `remotes` entry

> **Path:** `.apigw.remotes.<remote name>`

| Field           | Type                     | Description                                           | Example                               | Default | Required |
| --------------- | ------------------------ | ----------------------------------------------------- | ------------------------------------- | ------- | -------- |
| `type`          | `string` (eduapi\|ooapi) | API protocol type                                     | -                                     | -       | Yes      |
| `base_url`      | `string`                 | Base URL of the API endpoint                          | `"https://api.ladok.se/eduapi"`       | -       | Yes      |
| `token_url`     | `string`                 | OAuth 2.0 token endpoint for Client Credentials Grant | `"https://api.ladok.se/oauth2/token"` | -       | Yes      |
| `client_id`     | `string`                 | OAuth 2.0 client identifier                           | -                                     | -       | Yes      |
| `client_secret` | `string`                 | OAuth 2.0 client secret                               | -                                     | -       | Yes      |
| `scopes`        | `[]string`               | OAuth 2.0 scopes to request                           | -                                     | -       | No       |
| `timeout`       | `duration`               | HTTP client timeout                                   | -                                     | `10s`   | No       |

### `delivery`

> **Path:** `.apigw.delivery`

| Field               | Type     | Description                                                        | Example | Default | Required |
| ------------------- | -------- | ------------------------------------------------------------------ | ------- | ------- | -------- |
| `openid4vci`        | `object` | The OpenID4VCI Authorization Server for wallet credential issuance | -       | -       | Yes      |
| `credential_offers` | `object` | Credential offer wallet configurations                             | -       | -       | Yes      |

### `openid4vci`

> **Path:** `.apigw.delivery.openid4vci`

| Field                               | Type       | Description                                                                                                                                                                                                                                                                                | Example                             | Default                                                                          | Required |
| ----------------------------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------- | -------------------------------------------------------------------------------- | -------- |
| `token_endpoint`                    | `string`   | OAuth2 token endpoint URL                                                                                                                                                                                                                                                                  | `"https://verifier.sunet.se/token"` | -                                                                                | Yes      |
| `clients`                           | `object`   | OAuth2 client configurations                                                                                                                                                                                                                                                               | -                                   | -                                                                                | Yes      |
| `allow_unverified_client_assertion` | `bool`     | Accepting client_assertion (private_key_jwt) WITHOUT signature verification. This is INSECURE and only intended for conformance testing environments. When false (default), client_assertion is rejected. TODO(security): Remove this flag once full RFC 7523 verification is implemented. | -                                   | `false`                                                                          | No       |
| `grant_types`                       | `[]string` | List of grant types this issuer supports. Supported values: authorization_code, urn:ietf:params:oauth:grant-type:pre-authorized_code, refresh_token                                                                                                                                        | -                                   | `["authorization_code", "urn:ietf:params:oauth:grant-type:pre-authorized_code"]` | No       |
| `refresh_token_duration`            | `int`      | Refresh token duration in seconds. Only applicable when grant_types includes "refresh_token".                                                                                                                                                                                              | -                                   | `86400`                                                                          | No       |

### `clients` entry

> **Path:** `.apigw.delivery.openid4vci.clients.<client id>`, `.verifier.inbound.openid4vp.clients.<client id>`

| Field          | Type       | Description                                                                                                                                                                                                     | Example                          | Default  | Required                        |
| -------------- | ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------- | -------- | ------------------------------- |
| `type`         | `string`   | Client type per RFC 6749 Section 2.1 ("public" or "confidential"). Defaults to "public" since registered clients are wallets (native/web apps) that cannot securely store credentials and rely on PKCE instead. | -                                | `public` | No                              |
| `redirect_uri` | `[]string` | List of allowed redirect URIs for the client. Accepts either a single string or an array of strings in YAML/JSON.                                                                                               | `"https://example.com/callback"` | -        | Yes                             |
| `scopes`       | `[]string` | List of OAuth2 scopes allowed for the client                                                                                                                                                                    | -                                | -        | Yes                             |
| `jwks_uri`     | `string`   | URL to the client's JWKS for verifying client_assertion signatures (RFC 7523). Required for confidential clients using private_key_jwt authentication.                                                          | -                                | -        | Yes (if type is "confidential") |

### `credential_offers`

> **Path:** `.apigw.delivery.credential_offers`

| Field        | Type     | Description                      | Example | Default | Required |
| ------------ | -------- | -------------------------------- | ------- | ------- | -------- |
| `issuer_url` | `string` | Issuer URL for credential offers | -       | -       | Yes      |
| `wallets`    | `object` | Wallet redirect configurations   | -       | -       | Yes      |

### `wallets` entry

> **Path:** `.apigw.delivery.credential_offers.wallets.<wallet name>`

| Field          | Type     | Description                  | Example                            | Default | Required |
| -------------- | -------- | ---------------------------- | ---------------------------------- | ------- | -------- |
| `label`        | `string` | Display label for the wallet | -                                  | -       | Yes      |
| `redirect_uri` | `string` | Wallet redirect URI          | `"eudi-wallet://credential-offer"` | -       | Yes      |

### `issuer_metadata`

> **Path:** `.apigw.issuer_metadata`

| Field                                     | Type       | Description                                                                                                                                                                                                                          | Example | Default | Required |
| ----------------------------------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------- | ------- | -------- |
| `authorization_servers`                   | `[]string` | The authorization server URLs                                                                                                                                                                                                        | -       | -       | No       |
| `deferred_credential_endpoint`            | `string`   | Deferred credential endpoint                                                                                                                                                                                                         | -       | -       | No       |
| `notification_endpoint`                   | `string`   | Notification endpoint                                                                                                                                                                                                                | -       | -       | No       |
| `cryptographic_binding_methods_supported` | `[]string` | The supported binding methods                                                                                                                                                                                                        | -       | -       | No       |
| `credential_signing_alg_values_supported` | `[]string` | The supported signing algorithms                                                                                                                                                                                                     | -       | -       | No       |
| `proof_signing_alg_values_supported`      | `[]string` | The supported proof algorithms                                                                                                                                                                                                       | -       | -       | No       |
| `credential_response_encryption`          | `object`   | Response encryption configuration                                                                                                                                                                                                    | -       | -       | No       |
| `batch_credential_issuance`               | `object`   | Batch issuance configuration                                                                                                                                                                                                         | -       | -       | No       |
| `display`                                 | `array`    | Display metadata                                                                                                                                                                                                                     | -       | -       | No       |
| `mdoc_iacas_uri`                          | `string`   | URL where IACA certificates are published for mDOC verification. When configured, this is included in .well-known/openid-credential-issuer metadata so verifiers can dynamically discover trust anchors for ISO 18013-5 credentials. | -       | -       | No       |

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

### `identity_mapping_import`

> **Path:** `.apigw.identity_mapping_import`

| Field        | Type       | Description                                                                                                                                                                                                             | Example                                      | Default | Required |
| ------------ | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- | ------- | -------- |
| `file_paths` | `[]string` | JSON files containing identity mappings to import. Each JSON file should contain a map of person IDs to arrays of IdentityMapping objects. Import is skipped if the identity mappings collection already contains data. | `["./bootstrapping/identity_mappings.json"]` | -       | Yes      |
| `users`      | `[]string` | Users limits which person IDs to import. If empty, all persons are imported.                                                                                                                                            | `["100", "102"]`                             | -       | No       |

### `trust`

> **Path:** `.apigw.trust`, `.verifier.trust`

This is used for validating W3C VC Data Integrity proofs and other trust-related operations.

Trust evaluation operates in one of two modes:
- When PDPURL is configured: "default deny" mode - all trust decisions go through the PDP
- When PDPURL is empty: "allow all" mode - keys are resolved but always considered trusted

| Field                          | Type       | Description                                                                                                                                                                                                                                                    | Example                                | Default                  | Required |
| ------------------------------ | ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------- | ------------------------ | -------- |
| `pdp_url`                      | `string`   | URL of the AuthZEN PDP (Policy Decision Point) service for trust evaluation. When set, operates in "default deny" mode - trust decisions require PDP approval. When empty, operates in "allow all" mode - resolved keys are always considered trusted.         | `"https://trust.sunet.se/pdp"`         | -                        | No       |
| `local_did_methods`            | `[]string` | Which DID methods can be resolved locally without go-trust. Self-contained methods like "did:key" and "did:jwk" are always resolved locally.                                                                                                                   | -                                      | `["did:key", "did:jwk"]` | No       |
| `trust_policies`               | `object`   | Per-role trust evaluation policies. The key is the role (e.g., "issuer", "verifier") and the value contains policy settings.                                                                                                                                   | -                                      | -                        | No       |
| `allowed_signature_algorithms` | `[]string` | AllowedSignatureAlgorithms restricts which JWT signature algorithms are accepted. If empty, defaults to a secure set: ES256, ES384, ES512, RS256, RS384, RS512, PS256, PS384, PS512, EdDSA. The "none" algorithm is NEVER allowed regardless of configuration. | `["ES256", "ES384", "ES512", "EdDSA"]` | -                        | No       |
| `wallet_attestation`           | `object`   | Wallet attestation-based client authentication. This is a trust-evaluation mechanism (delegates to the PDP above), so it lives here rather than under delivery.openid4vci.                                                                                     | -                                      | -                        | No       |

### `trust_policies` entry

> **Path:** `.apigw.trust.trust_policies.<role>`, `.verifier.trust.trust_policies.<role>`

| Field                      | Type       | Description                                                                                                                           | Example                                                           | Default | Required |
| -------------------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- | ------- | -------- |
| `trust_frameworks`         | `[]string` | The accepted trust frameworks for this role.                                                                                          | `["did:web", "did:ebsi", "etsi-tl", "openid-federation", "x509"]` | -       | No       |
| `trust_anchors`            | `[]string` | Trusted root entities for this role. Format depends on the trust framework (e.g., DID for did:web, federation entity for OpenID Fed). | -                                                                 | -       | No       |
| `require_revocation_check` | `bool`     | RequireRevocationCheck enforces revocation status checking for this role. Default: false                                              | -                                                                 | `false` | No       |

### `wallet_attestation`

> **Path:** `.apigw.trust.wallet_attestation`, `.verifier.trust.wallet_attestation`

| Field     | Type     | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Example | Default | Required |
| --------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- | ------- | -------- |
| `enabled` | `bool`   | Wallet attestation-based authentication. When true and PDPURL is configured, wallets can authenticate using a provider-signed attestation JWT instead of pre-registration in Clients. The PDP validates the wallet provider against configured trust lists/federation. PKCE remains mandatory as the primary code-binding mechanism.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | -       | `false` | No       |
| `policy`  | `object` | SPOCP-based authorization for wallet attestation. When configured, after the PDP validates the wallet provider, the SPOCP engine checks whether the attestation tier (attestation_source) is authorized for the requested scope. When empty, all trusted wallets are authorized (default open).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | -       | -       | No       |
| `mode`    | `string` | Mode restricts which WIA trust model this deployment accepts, matching the same "etsi"/"ietf" terminology used by go-wallet-backend's WIAConfig.Mode: - "etsi": require x5c (EC TS03 v1.5.2 / ETSI TS 119 472-3 model, identity verified against the Trusted List for Wallet Providers). A WIA without x5c is rejected before signature verification. - "ietf": require iss + no x5c (the plain IETF draft-ietf-oauth-attestation-based-client-auth format, resolved via JWKS discovery — no ARF/ETSI counterpart). A WIA with x5c is rejected before signature verification. - "" (default): accept either format, as determined by whether the WIA carries an x5c header or an iss claim — preserves pre-Mode behavior for deployments that haven't opted into pinning one trust model. Any other value is treated the same as "" (a warning is logged, not a startup failure — this package has no config.Validate() convention to hard-fail against). Pinning this matters beyond documentation: without it, an operator expecting only ARF-conformant ("etsi") wallets would still silently accept an iss/JWKS-based ("ietf") WIA from a misconfigured or malicious wallet, trusting a JWKS discovery chain instead of the Trusted List for Wallet Providers PKI anchor.       | -       | -       | No       |

### `policy`

> **Path:** `.apigw.trust.wallet_attestation.policy`, `.verifier.trust.wallet_attestation.policy`

Each rule is an S-expression of the form:

(wallet (attestation_source <tier>)(scope <scope>)(issuer <provider>))

Use * as wildcard. When no rules are configured, any trusted wallet is authorized.
Example rules:

(wallet (attestation_source ios_app_attest)(scope pid)(issuer *))       — allow iOS Tier 4+ for PID
(wallet (attestation_source android_play_integrity)(scope pid)(issuer *)) — allow Android Tier 4+ for PID
(wallet (attestation_source *)(scope ehic)(issuer *))                   — allow any tier for EHIC

| Field        | Type       | Description                                                       | Example | Default | Required |
| ------------ | ---------- | ----------------------------------------------------------------- | ------- | ------- | -------- |
| `rules`      | `[]string` | Inline SPOCP rules.                                               | -       | -       | No       |
| `rules_file` | `string`   | Path to a file containing SPOCP rules (one per line, # comments). | -       | -       | No       |

### `federation`

> **Path:** `.apigw.federation`, `.verifier.federation`

| Field               | Type       | Description                                                                        | Example | Default | Required |
| ------------------- | ---------- | ---------------------------------------------------------------------------------- | ------- | ------- | -------- |
| `enabled`           | `bool`     | The federation entity configuration endpoint.                                      | -       | `false` | No       |
| `entity_id`         | `string`   | Entity identifier (defaults to PublicURL if empty).                                | -       | -       | No       |
| `authority_hints`   | `[]string` | Superior authority entity identifiers.                                             | -       | -       | No       |
| `organization_name` | `string`   | Human-readable organization name.                                                  | -       | -       | No       |
| `logo_uri`          | `string`   | Organization logo URL.                                                             | -       | -       | No       |
| `trust_marks`       | `array`    | TrustMarks contains pre-issued trust mark JWTs.                                    | -       | -       | No       |
| `ttl`               | `int64`    | Validity period of the entity configuration in seconds. Default: 86400 (24 hours). | -       | `86400` | No       |

### `trust_marks` entry

> **Path:** `.apigw.federation.trust_marks[]`, `.verifier.federation.trust_marks[]`

| Field | Type     | Description            | Example | Default | Required |
| ----- | -------- | ---------------------- | ------- | ------- | -------- |
| `id`  | `string` | Trust mark identifier. | -       | -       | Yes      |
| `jwt` | `string` | Trust mark JWT string. | -       | -       | Yes      |

### `rate_limit`

> **Path:** `.apigw.rate_limit`

| Field                            | Type  | Description                                                         | Example | Default | Required |
| -------------------------------- | ----- | ------------------------------------------------------------------- | ------- | ------- | -------- |
| `token_requests_per_minute`      | `int` | Maximum token endpoint requests per minute per IP. Default: 20      | -       | `20`    | No       |
| `credential_requests_per_minute` | `int` | Maximum credential endpoint requests per minute per IP. Default: 30 | -       | `30`    | No       |
| `datastore_requests_per_minute`  | `int` | Maximum datastore endpoint requests per minute per IP. Default: 60  | -       | `60`    | No       |

## `issuer` (Top-level)

Configuration for the Issuer service that signs and issues verifiable credentials.

### `issuer`

> **Path:** `.issuer`

| Field                      | Type     | Description                                                                                                                                                                                                       | Example                     | Default | Required |
| -------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------- | ------- | -------- |
| `api_server`               | `object` | HTTP API server configuration                                                                                                                                                                                     | -                           | -       | Yes      |
| `grpc_server`              | `object` | GRPC server configuration                                                                                                                                                                                         | -                           | -       | Yes      |
| `key_config`               | `object` | Signing key configuration                                                                                                                                                                                         | -                           | -       | Yes      |
| `jwt_attribute`            | `object` | JWT credential attribute configuration                                                                                                                                                                            | -                           | -       | Yes      |
| `issuer_url`               | `string` | Issuer identifier URL                                                                                                                                                                                             | `"https://issuer.sunet.se"` | -       | Yes      |
| `registry_client`          | `object` | Registry gRPC client config                                                                                                                                                                                       | -                           | -       | No       |
| `mdoc`                     | `object` | MDL/mdoc configuration                                                                                                                                                                                            | -                           | -       | No       |
| `audit_log`                | `object` | Audit log configuration                                                                                                                                                                                           | -                           | -       | No       |
| `sign_metadata_rate_limit` | `object` | The rate limiter for the SignMetadata gRPC endpoint. In HA setups each APIGW node refreshes two documents (VCI+OAuth2), so the defaults should accommodate the expected cluster size. Default: 2 req/s, burst 20. | -                           | -       | No       |
| `pseudonym_seed`           | `bool`   | PseudonymSeed, if true, makes the issuer attach a random seed as the pseudonym_seed claim.                                                                                                                        | -                           | -       | No       |
| `access_certificate`       | `object` | The EUDI access certificate (WRPAC) the issuer presents to wallets, optionally with its own key separate from KeyConfig. Off by default; deployments outside an ARF trust framework are unaffected.               | -                           | -       | No       |

### `grpc_server`

> **Path:** `.issuer.grpc_server`, `.registry.grpc_server`

| Field  | Type     | Description                | Example | Default | Required |
| ------ | -------- | -------------------------- | ------- | ------- | -------- |
| `addr` | `string` | GRPC server listen address | -       | `:8090` | No       |
| `tls`  | `object` | MTLS configuration         | -       | -       | No       |

### `tls`

> **Path:** `.issuer.grpc_server.tls`, `.registry.grpc_server.tls`

| Field                         | Type     | Description                                 | Example                        | Default                | Required |
| ----------------------------- | -------- | ------------------------------------------- | ------------------------------ | ---------------------- | -------- |
| `enable`                      | `bool`   | Enable                                      | -                              | `false`                | No       |
| `cert_file_path`              | `string` | Server certificate                          | -                              | `/pki/grpc_server.crt` | No       |
| `key_file_path`               | `string` | Server private key                          | -                              | `/pki/grpc_server.key` | No       |
| `client_ca_path`              | `string` | CA to verify client certificates (for mTLS) | -                              | `/pki/client_ca.crt`   | No       |
| `allowed_client_fingerprints` | `object` | SHA256 fingerprint -> friendly name         | `a1b2c3...: issuer-prod`       | -                      | No       |
| `allowed_client_dns`          | `object` | Friendly name -> Certificate Subject DN     | `apigw-prod: CN=apigw,O=SUNET` | -                      | No       |

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

| Field                    | Type       | Description                                                                                                                                                                         | Example | Default   | Required |
| ------------------------ | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- | --------- | -------- |
| `certificate_chain_path` | `string`   | Path to the PEM certificate chain TODO(pki): Consider folding into pki.KeyConfig.ChainPath to unify certificate chain loading with the standard key material configuration pattern. | -       | -         | Yes      |
| `default_validity`       | `duration` | Default credential validity (default: 365 days)                                                                                                                                     | -       | `8760h`   | No       |
| `digest_algorithm`       | `string`   | Digest algorithm: "SHA-256", "SHA-384", or "SHA-512"                                                                                                                                | -       | `SHA-256` | No       |

### `audit_log`

> **Path:** `.issuer.audit_log`

| Field                | Type       | Description                                                                                                                                                                                                                                                 | Example                                                              | Default | Required         |
| -------------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- | ------- | ---------------- |
| `enable`             | `bool`     | Audit logging                                                                                                                                                                                                                                               | -                                                                    | `false` | No               |
| `destinations`       | `[]string` | List of log destinations (console/stdout, file path, or HTTP URL)                                                                                                                                                                                           | `["stdout", "/var/log/audit.log", "https://audit.sunet.se/webhook"]` | -       | Yes (if enabled) |
| `file_sync_interval` | `duration` | Fsync behavior for file destinations. 0 = fsync after every write (strict durability, lower throughput). >0 = periodic batched fsync at the given interval (better throughput, bounded data-loss window). Has no effect on console or webhook destinations. | -                                                                    | `5s`    | No               |

### `sign_metadata_rate_limit`

> **Path:** `.issuer.sign_metadata_rate_limit`

| Field                 | Type      | Description                                                       | Example | Default | Required |
| --------------------- | --------- | ----------------------------------------------------------------- | ------- | ------- | -------- |
| `requests_per_second` | `float64` | Sustained rate limit in requests per second. Default: 2           | -       | `2`     | No       |
| `burst`               | `int`     | Maximum number of requests allowed in a single burst. Default: 20 | -       | `20`    | No       |

### `access_certificate`

> **Path:** `.issuer.access_certificate`

Under CIR (EU) 2025/848 a PID or attestation provider is a registered
wallet-relying party in its own right, so the certificate that
authenticates the issuer to a wallet is a WRPAC, governed by the same
profile the verifier uses.

The access certificate is kept separate from Issuer.KeyConfig on purpose.
The credential key is published in /jwks and signs credentials; an mdoc
document-signer certificate chains to an IACA under an entirely different
profile; and the two have independent rotation lifecycles. Conflating them
means a WRPAC rotation forces a credential-key rotation.

When KeyConfig is unset the issuer falls back to signing metadata with the
credential key, logging a warning. That keeps an existing single-key
deployment booting across an upgrade rather than failing on start.

| Field                 | Type       | Description                                                                                                                                                                                                                                                                                       | Example                                   | Default | Required |
| --------------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------- | ------- | -------- |
| `validate`            | `bool`     | Validate enforces the WRPAC certificate profile at startup: keyUsage must include nonRepudiation (contentCommitment), subjectAltName must carry contact information (URI or email), and certificatePolicies must contain a WRPAC policy OID. Startup fails when the certificate does not conform. | -                                         | -       | No       |
| `allowed_policy_oids` | `[]string` | AllowedPolicyOIDs optionally narrows which WRPAC certificate policy OIDs are accepted, for a deployment that must assert a specific assurance level. When empty, all four TS 119 411-8 WRPAC policy OIDs are accepted.                                                                            | `["0.4.0.194118.1.3","0.4.0.194118.1.4"]` | -       | No       |
| `key_config`          | `object`   | Signing key and certificate chain for the access certificate. When set, issuer metadata is signed with this key and the chain is advertised in the JWT's x5c header; credentials continue to be signed with Issuer.KeyConfig.                                                                     | -                                         | -       | No       |

## `verifier` (Top-level)

Configuration for the Verifier service that verifies credentials and acts as an OIDC Provider.

### `verifier`

> **Path:** `.verifier`

| Field                    | Type     | Description                                                                                                                                                                                                                                                                                                                                                                                                                              | Example                                                                                                          | Default        | Required                           |
| ------------------------ | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- | -------------- | ---------------------------------- |
| `api_server`             | `object` | HTTP API server configuration                                                                                                                                                                                                                                                                                                                                                                                                            | -                                                                                                                | -              | Yes                                |
| `public_url`             | `string` | Public URL of this service (must be valid HTTP/HTTPS URL)                                                                                                                                                                                                                                                                                                                                                                                | `"https://verifier.sunet.se"`                                                                                    | -              | Yes                                |
| `key_config`             | `object` | Signing key configuration                                                                                                                                                                                                                                                                                                                                                                                                                | -                                                                                                                | -              | Yes                                |
| `client_id_scheme`       | `string` | ClientIDScheme determines how the verifier identifies itself to wallets. Supported values: "x509_san_dns" (default), "x509_hash", "did". When "did", the DID field must be set and /.well-known/did.json is served. When "x509_hash" (the scheme the EUDI ARF mandates for Relying Party authentication), the client_id is the base64url SHA-256 of the signing certificate, so key_config must supply one and it is always sent in x5c. | -                                                                                                                | `x509_san_dns` | No                                 |
| `did`                    | `string` | Verifier's DID identity.                                                                                                                                                                                                                                                                                                                                                                                                                 | `"did:web:verifier.example.com"`                                                                                 | -              | Yes (if client_id_scheme is "did") |
| `access_certificate`     | `object` | AccessCertificate validates the verifier's own wallet-facing certificate as an EUDI Relying Party access certificate (WRPAC, ETSI TS 119 411-8). Off by default; deployments outside an ARF trust framework are unaffected.                                                                                                                                                                                                              | -                                                                                                                | -              | No                                 |
| `preferred_vp_formats`   | `object` | Informational VP formats and algorithms supported by wallets                                                                                                                                                                                                                                                                                                                                                                             | -                                                                                                                | -              | No                                 |
| `supported_wallets`      | `object` | Supported wallet configurations                                                                                                                                                                                                                                                                                                                                                                                                          | -                                                                                                                | -              | No                                 |
| `inbound`                | `object` | Inbound groups inbound credential verification                                                                                                                                                                                                                                                                                                                                                                                           | -                                                                                                                | -              | No                                 |
| `outbound`               | `object` | Outbound groups outbound identity assertion                                                                                                                                                                                                                                                                                                                                                                                              | -                                                                                                                | -              | No                                 |
| `digital_credentials`    | `object` | W3C Digital Credentials API configuration                                                                                                                                                                                                                                                                                                                                                                                                | -                                                                                                                | -              | No                                 |
| `authorization_page_css` | `object` | Authorization page styling configuration                                                                                                                                                                                                                                                                                                                                                                                                 | -                                                                                                                | -              | No                                 |
| `credential_display`     | `object` | Credential display settings                                                                                                                                                                                                                                                                                                                                                                                                              | -                                                                                                                | -              | No                                 |
| `trust`                  | `object` | Trust evaluation configuration                                                                                                                                                                                                                                                                                                                                                                                                           | -                                                                                                                | -              | No                                 |
| `federation`             | `object` | OpenID Federation entity configuration. When enabled, serves /.well-known/openid-federation as a self-signed JWT.                                                                                                                                                                                                                                                                                                                        | -                                                                                                                | -              | No                                 |
| `presets`                | `object` | Predefined verification request presets shown in the UI. The map key is the human-readable label; see PresetDefinition for what each entry configures.                                                                                                                                                                                                                                                                                   | `"PID":{"credentials":{"pid":null}},"PID + EHIC":{"credentials":{"pid":null,"ehic":null},"category":"Combined"}` | -              | No                                 |
| `combined_presentation`  | `object` | Combined presentation verification (ARF 3.0 §6.6.3.10). When multiple credentials are presented, this verifies they belong to the same holder.                                                                                                                                                                                                                                                                                           | -                                                                                                                | -              | No                                 |
| `revocation`             | `object` | Credential revocation checking at presentation time (ARF 3.0 §6.6.3.7). When enabled, the Verifier checks Token Status List references in presented credentials.                                                                                                                                                                                                                                                                         | -                                                                                                                | -              | No                                 |
| `zk_circuits`            | `object` | The zk-circuits catalog service used to resolve "mso_mdoc_zk" (Longfellow ZK/PPID) proof circuits for native verification. Only consulted by builds with the "zknative" Go build tag (see pkg/mdoc/zk_native_cgo.go) - ignored by the default build.                                                                                                                                                                                     | -                                                                                                                | -              | No                                 |

### `access_certificate`

> **Path:** `.verifier.access_certificate`

This validates the certificate the verifier already signs request objects
with - it does not introduce a second certificate. Deployments not
participating in an ARF trust framework can leave it disabled and are
unaffected.

| Field                 | Type       | Description                                                                                                                                                                                                                                                                                       | Example                                   | Default | Required |
| --------------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------- | ------- | -------- |
| `validate`            | `bool`     | Validate enforces the WRPAC certificate profile at startup: keyUsage must include nonRepudiation (contentCommitment), subjectAltName must carry contact information (URI or email), and certificatePolicies must contain a WRPAC policy OID. Startup fails when the certificate does not conform. | -                                         | -       | No       |
| `allowed_policy_oids` | `[]string` | AllowedPolicyOIDs optionally narrows which WRPAC certificate policy OIDs are accepted, for a deployment that must assert a specific assurance level (e.g. only the qualified policies). When empty, all four TS 119 411-8 WRPAC policy OIDs are accepted.                                         | `["0.4.0.194118.1.3","0.4.0.194118.1.4"]` | -       | No       |

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

| Field                | Type       | Description                                                                                                                                            | Example                                                               | Default | Required |
| -------------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------- | ------- | -------- |
| `proof_type_values`  | `[]string` | Non-empty array containing identifiers of proof types supported. If present, the proof type of the presented VC/VP MUST match one of the array values. | `["DataIntegrityProof", "Ed25519Signature2020"]`                      | -       | No       |
| `cryptosuite_values` | `[]string` | Non-empty array containing identifiers of crypto suites supported. Used when one of the algorithms in ProofTypeValues supports multiple crypto suites. | `["ecdsa-rdfc-2019", "ecdsa-sd-2023", "eddsa-rdfc-2022", "bbs-2023"]` | -       | No       |

### `jwt_vc_json`

> **Path:** `.verifier.preferred_vp_formats.jwt_vc_json`

| Field        | Type       | Description                                                                                                                                                              | Example | Default | Required |
| ------------ | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------- | ------- | -------- |
| `alg_values` | `[]string` | Non-empty array containing identifiers of cryptographic algorithms supported. If present, the alg JOSE header of the presented VC/VP MUST match one of the array values. | -       | -       | No       |

### `dc+sd-jwt`

> **Path:** `.verifier.preferred_vp_formats.dc+sd-jwt`

| Field               | Type       | Description                                                                                                      | Example | Default | Required |
| ------------------- | ---------- | ---------------------------------------------------------------------------------------------------------------- | ------- | ------- | -------- |
| `sd-jwt_alg_values` | `[]string` | Non-empty array containing cryptographic algorithm identifiers supported for the Issuer-signed JWT of an SD-JWT. | -       | -       | No       |
| `kb-jwt_alg_values` | `[]string` | Non-empty array containing cryptographic algorithm identifiers supported for a Key Binding JWT (KB-JWT).         | -       | -       | No       |

### `mso_mdoc`

> **Path:** `.verifier.preferred_vp_formats.mso_mdoc`

| Field                   | Type    | Description                                                                                                      | Example | Default | Required |
| ----------------------- | ------- | ---------------------------------------------------------------------------------------------------------------- | ------- | ------- | -------- |
| `issuerauth_alg_values` | `[]int` | Non-empty array containing cryptographic algorithm identifiers supported for IssuerAuth COSE signatures.         | -       | -       | No       |
| `deviceauth_alg_values` | `[]int` | Non-empty array containing cryptographic algorithm identifiers supported for DeviceAuth COSE signatures or MACs. | -       | -       | No       |

### `inbound`

> **Path:** `.verifier.inbound`

| Field       | Type     | Description                                                | Example | Default | Required |
| ----------- | -------- | ---------------------------------------------------------- | ------- | ------- | -------- |
| `openid4vp` | `object` | OpenID4VP configuration for accepting wallet presentations | -       | -       | Yes      |

### `openid4vp`

> **Path:** `.verifier.inbound.openid4vp`

| Field                       | Type     | Description                                            | Example                             | Default | Required |
| --------------------------- | -------- | ------------------------------------------------------ | ----------------------------------- | ------- | -------- |
| `presentation_timeout`      | `int`    | Presentation timeout in seconds                        | -                                   | `300`   | No       |
| `supported_credentials`     | `array`  | Supported credential configurations                    | -                                   | -       | Yes      |
| `presentation_requests_dir` | `string` | Optional directory with presentation request templates | -                                   | -       | No       |
| `token_endpoint`            | `string` | OAuth2 token endpoint URL used for VP token exchange   | `"https://verifier.sunet.se/token"` | -       | Yes      |
| `clients`                   | `object` | OAuth2 client configurations for RP interactions       | -                                   | -       | Yes      |

### `supported_credentials` entry

> **Path:** `.verifier.inbound.openid4vp.supported_credentials[]`

| Field    | Type       | Description                                      | Example            | Default | Required |
| -------- | ---------- | ------------------------------------------------ | ------------------ | ------- | -------- |
| `vct`    | `string`   | Verifiable credential type                       | `"urn:eudi:pid:1"` | -       | Yes      |
| `scopes` | `[]string` | OIDC scopes that grant access to this credential | -                  | -       | Yes      |

### `outbound`

> **Path:** `.verifier.outbound`

| Field           | Type     | Description                                                                   | Example | Default | Required |
| --------------- | -------- | ----------------------------------------------------------------------------- | ------- | ------- | -------- |
| `oidc_provider` | `object` | OIDC Provider configuration for asserting verified identity to downstream RPs | -       | -       | No       |

### `oidc_provider`

> **Path:** `.verifier.outbound.oidc_provider`

This configures how the verifier issues ID tokens and access tokens to relying parties.
Note: This is NOT related to verifiable credential issuance (see IssuerConfig for VC issuance).
The signing key is shared from the parent Verifier.KeyConfig.

| Field                    | Type     | Description                                                                                                                                                                                                                                                                                                                                                                                                                                      | Example                       | Default | Required |
| ------------------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------- | ------- | -------- |
| `issuer`                 | `string` | OIDC Provider identifier that appears in ID tokens and discovery metadata. This identifies the verifier as an OpenID Provider. Must match the 'iss' claim in all issued ID tokens.                                                                                                                                                                                                                                                               | `"https://verifier.sunet.se"` | -       | Yes      |
| `session_duration`       | `int`    | Session duration in seconds                                                                                                                                                                                                                                                                                                                                                                                                                      | -                             | `3600`  | No       |
| `code_duration`          | `int`    | Authorization code duration in seconds                                                                                                                                                                                                                                                                                                                                                                                                           | -                             | `300`   | No       |
| `access_token_duration`  | `int`    | Access token duration in seconds                                                                                                                                                                                                                                                                                                                                                                                                                 | -                             | `3600`  | No       |
| `id_token_duration`      | `int`    | ID token duration in seconds                                                                                                                                                                                                                                                                                                                                                                                                                     | -                             | `3600`  | No       |
| `refresh_token_duration` | `int`    | Refresh token duration in seconds                                                                                                                                                                                                                                                                                                                                                                                                                | -                             | `86400` | No       |
| `subject_type`           | `string` | Subject type: "public" or "pairwise"                                                                                                                                                                                                                                                                                                                                                                                                             | -                             | -       | Yes      |
| `subject_salt`           | `string` | Salt for pairwise subject generation                                                                                                                                                                                                                                                                                                                                                                                                             | -                             | -       | Yes      |
| `enable_userinfo`        | `bool`   | Whether the verifier-OP advertises a userinfo_endpoint in its discovery metadata and issues JWT access tokens (RFC 9068 at+jwt). When true (default), the OP advertises userinfo_endpoint in discovery and returns an access token alongside the ID token. The userinfo endpoint is stateless: it validates the JWT signature and returns the embedded claims. When false, only ID tokens are returned — no access_token or userinfo endpoint.   | -                             | `true`  | No       |
| `static_clients`         | `array`  | List of pre-configured OIDC clients These clients are checked in addition to dynamically registered clients                                                                                                                                                                                                                                                                                                                                      | -                             | -       | No       |

### `static_clients` entry

> **Path:** `.verifier.outbound.oidc_provider.static_clients[]`

Static clients are configured in YAML and do not require dynamic registration.
These clients are checked in addition to dynamically registered clients stored in the database.

| Field                        | Type       | Description                                                                                                                                                  | Example | Default                  | Required                                          |
| ---------------------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------- | ------------------------ | ------------------------------------------------- |
| `client_id`                  | `string`   | Unique identifier for the client                                                                                                                             | -       | -                        | Yes                                               |
| `client_secret`              | `string`   | Client secret for authentication. Can be defined in the secrets file under verifier.oidc_op.static_clients as a map of client_id to client_secret.           | -       | -                        | Yes (unless token_endpoint_auth_method is "none") |
| `redirect_uris`              | `[]string` | List of allowed redirect URIs for this client                                                                                                                | -       | -                        | Yes                                               |
| `allowed_scopes`             | `[]string` | List of scopes this client is allowed to request. If empty, defaults to standard OIDC scopes (openid, profile, email, address, phone).                       | -       | -                        | No                                                |
| `token_endpoint_auth_method` | `string`   | Authentication method for the token endpoint. Supported values: client_secret_basic, client_secret_post, none (public client) Default: "client_secret_basic" | -       | `client_secret_basic`    | No                                                |
| `grant_types`                | `[]string` | List of allowed grant types. Supported values: authorization_code, refresh_token Default: ["authorization_code"]                                             | -       | `["authorization_code"]` | No                                                |
| `response_types`             | `[]string` | List of allowed response types. Supported values: code Default: ["code"]                                                                                     | -       | `["code"]`               | No                                                |
| `client_name`                | `string`   | Optional human-readable name for the client                                                                                                                  | -       | -                        | No                                                |

### `digital_credentials`

> **Path:** `.verifier.digital_credentials`

| Field               | Type       | Description                                                                                                                                              | Example            | Default                                  | Required |
| ------------------- | ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------ | ---------------------------------------- | -------- |
| `enable`            | `bool`     | W3C Digital Credentials API support in browser                                                                                                           | -                  | `false`                                  | No       |
| `use_jar`           | `bool`     | JWT Authorization Request (JAR) for wallet communication When true, request objects are signed JWTs instead of plain JSON                                | -                  | `false`                                  | No       |
| `preferred_formats` | `[]string` | The order of preference for credential formats Supported values: "vc+sd-jwt", "dc+sd-jwt", "mso_mdoc" Default: ["vc+sd-jwt", "dc+sd-jwt", "mso_mdoc"]    | -                  | `["vc+sd-jwt", "dc+sd-jwt", "mso_mdoc"]` | No       |
| `response_mode`     | `string`   | The OpenID4VP response mode for DC API flows Supported values: "dc_api.jwt" (encrypted), "direct_post.jwt" (signed), "direct_post" Default: "dc_api.jwt" | -                  | `dc_api.jwt`                             | No       |
| `allow_qr_fallback` | `bool`     | Automatic fallback to QR code if DC API is unavailable Default: true                                                                                     | -                  | `true`                                   | No       |
| `deep_link_scheme`  | `string`   | DeepLinkScheme for mobile wallet integration                                                                                                             | `"eudi-wallet://"` | -                                        | No       |

### `authorization_page_css`

> **Path:** `.verifier.authorization_page_css`

| Field             | Type     | Description                                                                                                                           | Example     | Default | Required |
| ----------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------- | ----------- | ------- | -------- |
| `custom_css`      | `string` | Inline CSS that will be injected into the authorization page Allows deployers to override default styling without modifying templates | -           | -       | No       |
| `css_file`        | `string` | Path to an external CSS file to include If both CustomCSS and CSSFile are provided, both are included                                 | -           | -       | No       |
| `theme`           | `string` | Predefined color scheme: "light" (default), "dark", "blue", "purple"                                                                  | -           | `light` | No       |
| `primary_color`   | `string` | PrimaryColor overrides the primary brand color                                                                                        | `"#667eea"` | -       | No       |
| `secondary_color` | `string` | SecondaryColor overrides the secondary brand color                                                                                    | `"#764ba2"` | -       | No       |
| `logo_url`        | `string` | A URL to a custom logo image                                                                                                          | -           | -       | No       |
| `title`           | `string` | Title overrides the page title (default: "Wallet Authorization")                                                                      | -           | -       | No       |
| `subtitle`        | `string` | Subtitle overrides the page subtitle                                                                                                  | -           | -       | No       |

### `credential_display`

> **Path:** `.verifier.credential_display`

| Field                  | Type   | Description                                                                                                                              | Example | Default | Required |
| ---------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------- | ------- | ------- | -------- |
| `enable`               | `bool` | Users to optionally view credential details before completing authorization When enabled, a checkbox appears on the authorization page   | -       | `false` | No       |
| `require_confirmation` | `bool` | Users to review credentials before proceeding When true, the credential display step is mandatory (checkbox is pre-checked and disabled) | -       | `false` | No       |
| `show_raw_credential`  | `bool` | The raw VP token/credential in the display page Useful for debugging and technical users                                                 | -       | `false` | No       |
| `show_claims`          | `bool` | The parsed claims that will be sent to the RP Recommended for transparency and user consent                                              | -       | `true`  | No       |
| `allow_edit`           | `bool` | Users to redact certain claims before sending to RP (future feature) Currently not implemented                                           | -       | `false` | No       |

### `presets` entry

> **Path:** `.verifier.presets.<preset label>`

plus how it should be organized in the UI. The parent Presets map's key
serves as the human-readable label.

| Field         | Type     | Description                                                                                                                                                                                                                                                  | Example | Default | Required |
| ------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------- | ------- | -------- |
| `credentials` | `object` | Credential_metadata scopes to optional overrides. At least one scope is required - see VerificationPreset's own doc comment for what a nil scope value means.                                                                                                | -       | -       | Yes      |
| `category`    | `string` | Category groups this preset under a UI heading shared with every other preset carrying the same Category string. Presets with no Category fall into a generic catch-all group. Purely cosmetic - does not affect matching/verification behavior in any way.  | -       | -       | No       |
| `order`       | `int`    | This preset's position within its Category, ascending; ties (including the default 0) are broken alphabetically by label. Purely cosmetic.                                                                                                                   | -       | -       | No       |
| `featured`    | `bool`   | Featured presets are always shown; the rest are revealed progressively (grouped by Category, initially collapsed) so an operator with a large preset catalog doesn't force every wallet integrator to scan a long flat list before finding the common cases. | -       | `false` | No       |

### `credentials` entry

> **Path:** `.verifier.presets.<preset label>.credentials.<key>`

| Field            | Type    | Description                                                     | Example | Default | Required |
| ---------------- | ------- | --------------------------------------------------------------- | ------- | ------- | -------- |
| `claims`         | `array` | Specific claims to request. If empty, all VCTM claims are used. | -       | -       | No       |
| `exclude_claims` | `array` | Claims to exclude from the DCQL query.                          | -       | -       | No       |
| `validations`    | `array` | Optional rules applied server-side after claims extraction      | -       | -       | No       |

### `claims` entry

> **Path:** `.verifier.presets.<preset label>.credentials.<key>.claims[]`, `.verifier.presets.<preset label>.credentials.<key>.exclude_claims[]`

| Field  | Type       | Description         | Example                                  | Default | Required |
| ------ | ---------- | ------------------- | ---------------------------------------- | ------- | -------- |
| `path` | `[]string` | Claim path segments | `["birthdate"], ["address", "locality"]` | -       | Yes      |

### `validations` entry

> **Path:** `.verifier.presets.<preset label>.credentials.<key>.validations[]`

| Field   | Type       | Description                                     | Example         | Default | Required |
| ------- | ---------- | ----------------------------------------------- | --------------- | ------- | -------- |
| `rule`  | `string`   | Validation rule to apply, e.g., "age_over".     | `"age_over"`    | -       | Yes      |
| `path`  | `[]string` | Claim path to validate, e.g., ["birthdate"].    | `["birthdate"]` | -       | Yes      |
| `value` | `object`   | Threshold or expected value for the validation. | `18`            | -       | Yes      |

### `combined_presentation`

> **Path:** `.verifier.combined_presentation`

| Field                 | Type                               | Description                                                                                                                                                                                                                                                                 | Example | Default | Required |
| --------------------- | ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- | ------- | -------- |
| `enabled`             | `bool`                             | Enabled activates combined presentation binding verification.                                                                                                                                                                                                               | -       | -       | No       |
| `enforcement`         | `string` (enforce\|warn\|disabled) | Enforcement determines how binding verification results are handled: - "enforce": reject the presentation if binding cannot be established - "warn": log a warning but allow the presentation through (per ARF 3.0 ACP_08) - "disabled": skip binding verification entirely | -       | `warn`  | No       |
| `binding_attributes`  | `array`                            | Attribute-based binding checks.                                                                                                                                                                                                                                             | -       | -       | No       |
| `key_binding_enabled` | `bool`                             | KeyBindingEnabled activates key-based binding (cnf.jwk / device key comparison). Cross-format comparison (SD-JWT cnf.jwk vs mDoc device key) is always supported since both are converted to RFC 7638 JWK thumbprints.                                                      | -       | -       | No       |

### `binding_attributes` entry

> **Path:** `.verifier.combined_presentation.binding_attributes[]`

| Field   | Type       | Description                                                         | Example                                                    | Default | Required |
| ------- | ---------- | ------------------------------------------------------------------- | ---------------------------------------------------------- | ------- | -------- |
| `paths` | `[]string` | Claim paths that must ALL match across credentials (AND semantics). | `["family_name", "birth_date", "place_of_birth.locality"]` | -       | Yes      |

### `revocation`

> **Path:** `.verifier.revocation`

| Field         | Type       | Description                                                                                                                                                                                                                                                                                   | Example | Default | Required |
| ------------- | ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------- | ------- | -------- |
| `enabled`     | `bool`     | Enabled activates revocation status checking for presented credentials.                                                                                                                                                                                                                       | -       | -       | No       |
| `cache_ttl`   | `int`      | Duration in seconds to cache fetched status list tokens.                                                                                                                                                                                                                                      | -       | `300`   | No       |
| `fail_open`   | `bool`     | FailOpen determines behavior when the status list is unreachable or unparseable: - true: log warning and allow the credential through (fail-open) - false: reject the credential (fail-closed) Note: explicitly revoked/suspended credentials are always rejected regardless of this setting. | -       | `true`  | No       |
| `skip_scopes` | `[]string` | Credential scopes exempt from revocation checking (e.g., short-lived credentials valid < 24 hours per ARF 3.0 §6.6.3.7).                                                                                                                                                                      | -       | -       | No       |

### `zk_circuits`

> **Path:** `.verifier.zk_circuits`

(pkg/mdoc/zkcircuit) used to resolve a presented "mso_mdoc_zk" document's
zkSystemId to a downloadable circuit artifact.

| Field     | Type       | Description                                                                                                                                                                                                               | Example                           | Default                           | Required |
| --------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------- | --------------------------------- | -------- |
| `sources` | `[]string` | Zk-circuits catalog mirror base URLs, tried in order until one succeeds (see pkg/mdoc/zkcircuit.Client - these are mirrors of the SAME catalog, not distinct registries). Defaults to the live deployed service if empty. | `["https://zk-circuits.fly.dev"]` | `["https://zk-circuits.fly.dev"]` | No       |

## `registry` (Top-level)

Configuration for the Registry service that manages credential status.

### `registry`

> **Path:** `.registry`

| Field                | Type     | Description                                               | Example                       | Default | Required |
| -------------------- | -------- | --------------------------------------------------------- | ----------------------------- | ------- | -------- |
| `api_server`         | `object` | HTTP API server configuration                             | -                             | -       | Yes      |
| `public_url`         | `string` | Public URL of this service (must be valid HTTP/HTTPS URL) | `"https://registry.sunet.se"` | -       | Yes      |
| `grpc_server`        | `object` | GRPC server configuration                                 | -                             | -       | Yes      |
| `token_status_lists` | `object` | Token Status List configuration                           | -                             | -       | Yes      |
| `admin_gui`          | `object` | Admin GUI configuration                                   | -                             | -       | No       |

### `token_status_lists`

> **Path:** `.registry.token_status_lists`

| Field                            | Type     | Description                                                                                                                                | Example | Default   | Required |
| -------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------ | ------- | --------- | -------- |
| `key_config`                     | `object` | Key configuration for signing Token Status List tokens.                                                                                    | -       | -         | Yes      |
| `token_refresh_interval`         | `int64`  | How often (in seconds) new Token Status List tokens are generated. Default: 43200 (12 hours). Min: 301 (>5 minutes), Max: 86400 (24 hours) | -       | `43200`   | No       |
| `section_size`                   | `int64`  | Number of entries (decoys) per section. Default: 1000000 (1 million)                                                                       | -       | `1000000` | No       |
| `rate_limit_requests_per_minute` | `int`    | Maximum requests per minute per IP for token status list endpoints. Default: 60                                                            | -       | `60`      | No       |

### `admin_gui`

> **Path:** `.registry.admin_gui`

| Field      | Type     | Description    | Example | Default | Required         |
| ---------- | -------- | -------------- | ------- | ------- | ---------------- |
| `enable`   | `bool`   | The admin GUI  | -       | `false` | No               |
| `username` | `string` | Admin username | -       | `admin` | No               |
| `password` | `string` | Admin password | -       | -       | Yes (if enabled) |

## Secrets File Reference

The structure of the separate secrets file.

### Secrets file structure

> **Path:** `(root)`

When Common.SecretFilePath is set, ApplySecrets merges these values
into the main config: the Mongo URI is only used when the main config
has none. For each service section (apigw, registry, verifier) that
is present in the secrets file, the corresponding secret fields in
the main config are cleared and replaced by the secrets-file values.
Sections omitted from the secrets file are left untouched.

| Field      | Type     | Description | Example | Default | Required |
| ---------- | -------- | ----------- | ------- | ------- | -------- |
| `common`   | `object` | Common      | -       | -       | No       |
| `apigw`    | `object` | APIGW       | -       | -       | No       |
| `registry` | `object` | Registry    | -       | -       | No       |
| `verifier` | `object` | Verifier    | -       | -       | No       |

### `common`

> **Path:** `.common`

| Field   | Type     | Description | Example | Default | Required |
| ------- | -------- | ----------- | ------- | ------- | -------- |
| `mongo` | `object` | Mongo       | -       | -       | No       |
| `sql`   | `object` | SQL         | -       | -       | No       |

### `mongo`

> **Path:** `.common.mongo`

| Field | Type     | Description                                                             | Example | Default | Required |
| ----- | -------- | ----------------------------------------------------------------------- | ------- | ------- | -------- |
| `uri` | `string` | MongoDB connection string, which may include authentication credentials | -       | -       | No       |

### `sql`

> **Path:** `.common.sql`

| Field      | Type     | Description                  | Example | Default | Required |
| ---------- | -------- | ---------------------------- | ------- | ------- | -------- |
| `postgres` | `object` | Postgres connection password | -       | -       | No       |
| `mariadb`  | `object` | MariaDB connection password  | -       | -       | No       |

### `postgres`

> **Path:** `.common.sql.postgres`

| Field      | Type     | Description                  | Example | Default | Required |
| ---------- | -------- | ---------------------------- | ------- | ------- | -------- |
| `password` | `string` | Postgres connection password | -       | -       | No       |

### `mariadb`

> **Path:** `.common.sql.mariadb`

| Field      | Type     | Description                 | Example | Default | Required |
| ---------- | -------- | --------------------------- | ------- | ------- | -------- |
| `password` | `string` | MariaDB connection password | -       | -       | No       |

### `apigw`

> **Path:** `.apigw`

| Field            | Type     | Description    | Example | Default | Required |
| ---------------- | -------- | -------------- | ------- | ------- | -------- |
| `api_server`     | `object` | API Server     | -       | -       | No       |
| `auth_providers` | `object` | Auth Providers | -       | -       | No       |

### `api_server`

> **Path:** `.apigw.api_server`

| Field      | Type     | Description | Example | Default | Required |
| ---------- | -------- | ----------- | ------- | ------- | -------- |
| `api_auth` | `object` | API Auth    | -       | -       | No       |

### `api_auth`

> **Path:** `.apigw.api_server.api_auth`

| Field  | Type     | Description | Example | Default | Required |
| ------ | -------- | ----------- | ------- | ------- | -------- |
| `oidc` | `object` | OIDC        | -       | -       | No       |

### `oidc`

> **Path:** `.apigw.api_server.api_auth.oidc`

| Field           | Type     | Description                                | Example | Default | Required |
| --------------- | -------- | ------------------------------------------ | ------- | ------- | -------- |
| `client_secret` | `string` | OAuth2 client secret for the OIDC provider | -       | -       | No       |

### `auth_providers`

> **Path:** `.apigw.auth_providers`

| Field  | Type     | Description | Example | Default | Required |
| ------ | -------- | ----------- | ------- | ------- | -------- |
| `oidc` | `object` | OIDC        | -       | -       | No       |

### `oidc`

> **Path:** `.apigw.auth_providers.oidc`

| Field          | Type     | Description  | Example | Default | Required |
| -------------- | -------- | ------------ | ------- | ------- | -------- |
| `registration` | `object` | Registration | -       | -       | No       |

### `registration`

> **Path:** `.apigw.auth_providers.oidc.registration`

| Field           | Type     | Description   | Example | Default | Required |
| --------------- | -------- | ------------- | ------- | ------- | -------- |
| `preconfigured` | `object` | Preconfigured | -       | -       | No       |
| `dynamic`       | `object` | Dynamic       | -       | -       | No       |

### `preconfigured`

> **Path:** `.apigw.auth_providers.oidc.registration.preconfigured`

| Field           | Type     | Description                                         | Example | Default | Required |
| --------------- | -------- | --------------------------------------------------- | ------- | ------- | -------- |
| `client_secret` | `string` | Shared secret for the pre-configured OIDC RP client | -       | -       | No       |

### `dynamic`

> **Path:** `.apigw.auth_providers.oidc.registration.dynamic`

| Field                  | Type     | Description                                                     | Example | Default | Required |
| ---------------------- | -------- | --------------------------------------------------------------- | ------- | ------- | -------- |
| `initial_access_token` | `string` | Bearer token required by the OP for dynamic client registration | -       | -       | No       |

### `registry`

> **Path:** `.registry`

| Field       | Type     | Description | Example | Default | Required |
| ----------- | -------- | ----------- | ------- | ------- | -------- |
| `admin_gui` | `object` | Admin GUI   | -       | -       | No       |

### `admin_gui`

> **Path:** `.registry.admin_gui`

| Field      | Type     | Description              | Example | Default | Required |
| ---------- | -------- | ------------------------ | ------- | ------- | -------- |
| `password` | `string` | Admin GUI login password | -       | -       | No       |

### `verifier`

> **Path:** `.verifier`

| Field      | Type     | Description | Example | Default | Required |
| ---------- | -------- | ----------- | ------- | ------- | -------- |
| `outbound` | `object` | Outbound    | -       | -       | No       |

### `outbound`

> **Path:** `.verifier.outbound`

| Field           | Type     | Description   | Example | Default | Required |
| --------------- | -------- | ------------- | ------- | ------- | -------- |
| `oidc_provider` | `object` | OIDC Provider | -       | -       | No       |

### `oidc_provider`

> **Path:** `.verifier.outbound.oidc_provider`

| Field            | Type     | Description                                                                                                                                                                                                                                      | Example                          | Default | Required |
| ---------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------- | ------- | -------- |
| `subject_salt`   | `string` | Secret value used to derive pairwise subject identifiers for OIDC clients                                                                                                                                                                        | -                                | -       | No       |
| `static_clients` | `object` | Client_id to client_secret for static OIDC clients. Only clients listed here will have their secrets applied; clients not present in this map keep whatever value the main config provides (which will be empty after ApplySecrets clears them). | `<client_id>: "<client_secret>"` | -       | No       |

### Example `secrets.yaml`

> **Path:** `file referenced by .common.secret_file_path`

```yaml
common:
  mongo:
    uri: "mongodb://user:password@mongo:27017/vc"
  sql:
    postgres:
      password: "change-me-in-production"
    mariadb:
      password: "change-me-in-production"
apigw:
  api_server:
    api_auth:
      oidc:
        client_secret: "your-oidc-client-secret"
  auth_providers:
    oidc:
      registration:
        preconfigured:
          client_secret: "your-oidc-client-secret"
        dynamic:
          initial_access_token: "<secret-value>"
registry:
  admin_gui:
    password: "change-me-in-production"
verifier:
  outbound:
    oidc_provider:
      subject_salt: "random-salt-for-pairwise-subjects"
      static_clients:
        <client_id>: "<client_secret>"
```


