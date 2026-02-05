# Configuration Reference

Complete reference for all configuration parameters in the VC system.

## Table of Contents

- [Common Configuration](#common-configuration)
- [Authentication Methods](#authentication-methods)
- [Credential Constructor](#credential-constructor)
- [API Gateway (APIGW)](#api-gateway-apigw)
- [Issuer](#issuer)
- [Verifier](#verifier)
- [Registry](#registry)
- [Mock AS](#mock-as)
- [UI](#ui)

---

## Common Configuration

Shared configuration used across all services.

### Common

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|  
| `production` | `bool` | Enable production mode | `false` | No |
| `log` | `object` | Logging configuration | - | Yes |
| `mongo` | `object` | MongoDB configuration | - | No |
| `tracing` | `object` | OpenTelemetry tracing configuration | - | Yes |
| `kafka` | `object` | Kafka message broker configuration | - | No |
| `credential_offer_qr` | `object` | Credential offer QR code settings | - | No |

### Log

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `folder_path` | `string` | Path to log folder | - | No |

### Mongo

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `uri` | `string` | MongoDB connection URI | - | Yes |

**Example:**
```yaml
mongo:
  uri: "mongodb://localhost:27017/vc"
```

### OTEL

OpenTelemetry configuration for distributed tracing.

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `addr` | `string` | OTEL collector address | - | Yes |
| `timeout` | `int64` | Timeout in seconds | `10` | No |

**Example:**
```yaml
tracing:
  addr: "jaeger:4318"
  type: "otlp"
  timeout: 10
```

### Kafka

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `enabled` | `bool` | Enable Kafka integration | `false` | No |
| `brokers` | `[]string` | Kafka broker addresses | `["kafka0:9092", "kafka1:9092"]` | Yes (if enabled) |

**Example:**
```yaml
kafka:
  enabled: true
  brokers:
    - "kafka0:9092"
    - "kafka1:9092"
```

### CredentialOfferQRConfig

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `type` | `string` | Credential offer type: `credential_offer` or `credential_offer_uri` | `credential_offer` | Yes |
| `qr` | `object` | QR code configuration | - | No |

### QRCfg

QR code generation settings.

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `recovery_level` | `int` | Error correction level (0-3) | `2` | Yes |
| `size` | `int` | QR code size in pixels | `256` | Yes |

**Example:**
```yaml
credential_offer_qr:
  type: credential_offer
  qr:
    recovery_level: 2
    size: 256
```

---

## Authentication Methods

Defines authentication methods for credential issuance. Each method specifies what credentials the wallet must present.

### AuthMethod

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `vcts` | `array` | Acceptable Verifiable Credential Type URNs | - | Yes (min: 1) |
| `format` | `string` | Credential format (e.g., "dc+sd-jwt", "ldp_vc", "mso_mdoc") | - | Yes |
| `claims` | `array` | Identity claims to extract from auth credential | - | Yes (min: 1) |

**Example:**
```yaml
auth_methods:
  basic:
    vcts:
      - "urn:eudi:pid:1"
    format: "dc+sd-jwt"
    claims:
      - "given_name"
      - "family_name"
  
  pid_auth:
    vcts:
      - "urn:eudi:pid:1"
      - "urn:eudi:pid:arf-1.5:1"
    format: "dc+sd-jwt"
    claims:
      - "given_name"
      - "family_name"
      - "birth_date"
```

---

## Credential Constructor

Maps OAuth2 scopes to credential configurations. The key is the scope name used in authorization requests.

### CredentialConstructor

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `vct` | `string` | Verifiable Credential Type URN | - | Yes |
| `vctm_file_path` | `string` | Path to VCTM (Verifiable Credential Type Metadata) file | - | Yes |
| `format` | `string` | Credential format (e.g., "dc+sd-jwt") | - | Yes |
| `auth_method` | `string` | Reference to auth method (must exist in `auth_methods`) | - | Yes |
| `attributes` | `object` | Attribute mappings by authentic source | - | No |

**Example:**
```yaml
credential_constructor:
  pid:
    vct: "urn:eudi:pid:1"
    vctm_file_path: "metadata/vctm_pid.json"
    format: "dc+sd-jwt"
    auth_method: "basic"
    attributes:
      authentic_source_se:
        user_id:
          - "sub"
  
  ehic:
    vct: "urn:eudi:ehic:1"
    vctm_file_path: "metadata/vctm_ehic.json"
    format: "dc+sd-jwt"
    auth_method: "pid_auth"
```

---

## API Gateway (APIGW)

Configuration for the API Gateway service that handles credential issuance requests.

### APIGW

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|  
| `api_server` | `object` | HTTP API server configuration | - | Yes |
| `key_config` | `object` | Signing key configuration | - | Yes |
| `credential_offers` | `object` | Credential offer wallet configurations | - | No |
| `oauth_server` | `object` | OAuth2 server configuration | - | No |
| `issuer_metadata` | `object` | OpenID4VCI issuer metadata | - | No |
| `public_url` | `string` | Public URL of this service (must be valid HTTP/HTTPS URL) | - | Yes |
| `registry_public_url` | `string` | Public URL of registry service for status list URIs (must be valid HTTP/HTTPS URL) | - | Yes |
| `saml` | `object` | SAML Service Provider configuration | - | No |
| `oidcrp` | `object` | OIDC Relying Party configuration | - | No |
| `issuer_client` | `object` | gRPC client config for issuer | - | Yes |
| `registry_client` | `object` | gRPC client config for registry | - | Yes |

### APIServer

HTTP API server configuration.

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `addr` | `string` | Listen address | `:8080` | Yes |
| `tls` | `object` | TLS configuration | - | No |
| `basic_auth` | `object` | HTTP Basic authentication | - | No |
| `cors` | `object` | CORS configuration | - | No |

### TLS

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `enabled` | `bool` | Enable TLS | `false` | No |
| `cert_file_path` | `string` | Path to TLS certificate | - | Yes (if enabled) |
| `key_file_path` | `string` | Path to TLS private key | - | Yes (if enabled) |

### BasicAuth

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `enabled` | `bool` | Enable HTTP Basic authentication | `false` | No |
| `users` | `object` | Username to password mapping | - | No |

### CORS

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `allowed_origins` | `array` | Allowed CORS origins | `[]` | No |

**Example:**
```yaml
apigw:
  api_server:
    addr: ":8080"
    tls:
      enabled: true
      cert_file_path: "/pki/api_server.crt"
      key_file_path: "/pki/api_server.key"
    cors:
      allowed_origins:
        - "https://wallet.example.com"
  public_url: "https://issuer.example.com"
  registry_public_url: "https://registry.example.com"
```

### CredentialOffers

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `issuer_url` | `string` | Issuer URL for credential offers | - | Yes |
| `wallets` | `object` | Wallet redirect configurations | - | Yes |

### CredentialOfferWallets

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `label` | `string` | Display label for wallet | - | Yes |
| `redirect_uri` | `string` | Wallet redirect URI | - | Yes |

**Example:**
```yaml
credential_offers:
  issuer_url: "https://issuer.example.com"
  wallets:
    eudi_wallet:
      label: "EUDI Wallet"
      redirect_uri: "eudi-wallet://credential-offer"
    web_wallet:
      label: "Web Wallet"
      redirect_uri: "https://wallet.example.com/receive"
```

### IssuerMetadata

OpenID4VCI issuer metadata configuration.

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `authorization_servers` | `array` | Authorization server URLs | - | No |
| `deferred_credential_endpoint` | `string` | Deferred credential endpoint | - | No |
| `notification_endpoint` | `string` | Notification endpoint | - | No |
| `cryptographic_binding_methods_supported` | `array` | Supported binding methods | `["jwk"]` | No |
| `credential_signing_alg_values_supported` | `array` | Supported signing algorithms | `["ES256", "ES384", "RS256"]` | No |
| `proof_signing_alg_values_supported` | `array` | Supported proof algorithms | `["ES256", "ES384", "ES512", "RS256", "RS384", "RS512"]` | No |
| `credential_response_encryption` | `object` | Response encryption config | - | No |
| `batch_credential_issuance` | `object` | Batch issuance config | - | No |
| `display` | `array` | Display metadata | - | No |

### OAuthServer

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `token_endpoint` | `string` | OAuth2 token endpoint URL | - | Yes |
| `clients` | `object` | OAuth2 client configurations | - | Yes |

### SAMLConfig

SAML Service Provider configuration for credential issuance via SAML authentication.

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `enabled` | `bool` | Enable SAML support | `false` | No |
| `entity_id` | `string` | SAML SP entity identifier | - | Yes (if enabled) |
| `metadata_url` | `string` | Public URL where SP metadata is served | - | No |
| `mdq_server` | `string` | MDQ (Metadata Query Protocol) server base URL | - | No* |
| `static_idp_metadata` | `object` | Static IdP configuration | - | No* |
| `certificate_path` | `string` | Path to X.509 certificate for SAML signing/encryption | - | Yes (if enabled) |
| `private_key_path` | `string` | Path to private key for SAML signing/encryption | - | Yes (if enabled) |
| `acs_endpoint` | `string` | Assertion Consumer Service URL | - | Yes (if enabled) |
| `session_duration` | `int` | Session duration in seconds | `3600` | No |
| `credential_mappings` | `object` | Credential type to attribute mappings | - | Yes (if enabled) |
| `metadata_cache_ttl` | `int` | IdP metadata cache TTL in seconds | `3600` | No |

*Note: Either `mdq_server` OR `static_idp_metadata` must be configured, but not both.

### StaticIDPConfig

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `entity_id` | `string` | IdP entity identifier | - | Yes |
| `metadata_path` | `string` | File path to IdP metadata XML | - | No* |
| `metadata_url` | `string` | HTTP(S) URL to fetch IdP metadata | - | No* |

*Note: Either `metadata_path` OR `metadata_url` must be configured, but not both.

### CredentialMapping

Maps external attributes to credential claims for a specific credential type.

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `credential_config_id` | `string` | OpenID4VCI credential configuration identifier | - | Yes |
| `attributes` | `object` | Attribute OID to claim mappings | - | Yes |
| `default_idp` | `string` | Default IdP entityID for this credential type | - | No |

### AttributeConfig

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `claim` | `string` | Target claim name (supports dot-notation) | - | Yes |
| `required` | `bool` | Whether attribute must be present | `false` | No |
| `transform` | `string` | Transformation: `lowercase`, `uppercase`, or `trim` | - | No |
| `default` | `string` | Default value if attribute is missing | - | No |

**SAML Example:**
```yaml
saml:
  enabled: true
  entity_id: "https://issuer.example.com/saml/metadata"
  mdq_server: "https://md.example.org/entities/"
  certificate_path: "/pki/saml.crt"
  private_key_path: "/pki/saml.key"
  acs_endpoint: "https://issuer.example.com/saml/acs"
  session_duration: 3600
  credential_mappings:
    pid:
      credential_config_id: "urn:eudi:pid:1"
      attributes:
        "urn:oid:2.5.4.42":
          claim: "given_name"
          required: true
        "urn:oid:2.5.4.4":
          claim: "family_name"
          required: true
          transform: "uppercase"
```

### OIDCRPConfig

OIDC Relying Party configuration for credential issuance via OIDC authentication.

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `enabled` | `bool` | Enable OIDC RP support | `false` | No |
| `dynamic_registration` | `object` | RFC 7591 dynamic client registration | - | No |
| `client_id` | `string` | OIDC client identifier | - | Yes* |
| `client_secret` | `string` | OIDC client secret | - | Yes* |
| `redirect_uri` | `string` | Callback URL for authorization response | - | Yes (if enabled) |
| `issuer_url` | `string` | OIDC Provider's issuer URL | - | Yes (if enabled) |
| `scopes` | `array` | OAuth2/OIDC scopes to request (must include "openid") | `["openid", "profile", "email"]` | Yes |
| `session_duration` | `int` | Session duration in seconds | `3600` | No |
| `client_name` | `string` | Client name for display/registration | - | No |
| `client_uri` | `string` | Client homepage URI | - | No |
| `logo_uri` | `string` | Client logo URI | - | No |
| `contacts` | `array` | Contact email addresses | - | No |
| `tos_uri` | `string` | Terms of service URI | - | No |
| `policy_uri` | `string` | Privacy policy URI | - | No |
| `credential_mappings` | `object` | Credential type to claim mappings | - | Yes (if enabled) |

*Note: Required unless `dynamic_registration.enabled` is true.

### DynamicRegistrationConfig

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `enabled` | `bool` | Enable dynamic client registration | `false` | No |
| `initial_access_token` | `string` | Bearer token for registration (required by some providers) | - | No |
| `storage_path` | `string` | Path to cache registered credentials | - | No |

**OIDC RP Example:**
```yaml
oidcrp:
  enabled: true
  client_id: "issuer-client"
  client_secret: "secret123"
  redirect_uri: "https://issuer.example.com/oidcrp/callback"
  issuer_url: "https://accounts.google.com"
  scopes:
    - "openid"
    - "profile"
    - "email"
  credential_mappings:
    pid:
      credential_config_id: "urn:eudi:pid:1"
      attributes:
        "given_name":
          claim: "given_name"
          required: true
        "family_name":
          claim: "family_name"
          required: true
```

### GRPCClientTLS

mTLS configuration for gRPC client connections.

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `addr` | `string` | gRPC server address | - | Yes |
| `tls` | `bool` | Enable TLS | `false` | No |
| `cert_file_path` | `string` | Client certificate for mTLS | - | No |
| `key_file_path` | `string` | Client private key for mTLS | - | No |
| `ca_file_path` | `string` | CA certificate to verify server | - | No |
| `server_name` | `string` | Server name for TLS verification | - | No |

---

## Issuer

Configuration for the Issuer service that signs and issues verifiable credentials.

### Issuer

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `api_server` | `object` | HTTP API server configuration | - | Yes |
| `grpc_server` | `object` | gRPC server configuration | - | Yes |
| `key_config` | `object` | Signing key configuration | - | Yes |
| `jwt_attribute` | `object` | JWT attribute configuration | - | Yes |
| `issuer_url` | `string` | Issuer identifier URL | - | Yes |
| `registry_client` | `object` | Registry gRPC client config | - | No |
| `mdoc` | `object` | mDL/mdoc configuration | - | No |
| `audit_log` | `object` | Audit log configuration | - | No |

### GRPCServer

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `addr` | `string` | Listen address | `:8090` | Yes |
| `tls` | `object` | mTLS configuration | - | No |

### GRPCTLS

mTLS configuration for gRPC server.

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `enabled` | `bool` | Enable mTLS | `false` | No |
| `cert_file_path` | `string` | Server certificate path | `/pki/grpc_server.crt` | Yes (if enabled) |
| `key_file_path` | `string` | Server private key path | `/pki/grpc_server.key` | Yes (if enabled) |
| `client_ca_path` | `string` | CA to verify client certificates | `/pki/client_ca.crt` | Yes (if enabled) |
| `allowed_client_fingerprints` | `object` | SHA256 fingerprint to friendly name mapping | - | Yes (if enabled) |

**Example:**
```yaml
grpc_server:
  addr: ":8090"
  tls:
    enabled: true
    cert_file_path: "/pki/grpc_server.crt"
    key_file_path: "/pki/grpc_server.key"
    client_ca_path: "/pki/client_ca.crt"
    allowed_client_fingerprints:
      "a1b2c3d4...": "apigw-prod"
      "e5f6g7h8...": "apigw-staging"
```

### JWTAttribute

JWT credential attribute configuration.

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `issuer` | `string` | Issuer of the token (e.g., "https://issuer.sunet.se") | - | Yes |
| `static_host` | `string` | Static host for serving files like images | - | No |
| `enable_not_before` | `bool` | Enable nbf claim | `false` | No |
| `valid_duration` | `int64` | Token validity duration in seconds | `3600` | No |
| `verifiable_credential_type` | `string` | Verifiable credential type URL | - | Yes |
| `kid` | `string` | Key ID of the signing key | - | No |

### MDocConfig

mDL (ISO 18013-5) issuer configuration.

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `certificate_chain_path` | `string` | Path to PEM certificate chain | - | Yes |
| `default_validity` | `duration` | Default credential validity | `8760h` (365 days) | No |
| `digest_algorithm` | `string` | Digest algorithm: "SHA-256", "SHA-384", or "SHA-512" | `SHA-256` | No |

### AuditLog

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `enabled` | `bool` | Enable audit logging | `false` | No |
| `destinations` | `array` | Log destinations (console/stdout, file path, or HTTP URL) | - | Yes (if enabled) |

**Example:**
```yaml
audit_log:
  enabled: true
  destinations:
    - "stdout"
    - "/var/log/audit.log"
    - "https://audit.example.com/webhook"
```

### PKCS11

PKCS#11 HSM configuration for hardware security module integration.

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `module_path` | `string` | Path to PKCS#11 module | `/usr/lib/softhsm/libsofthsm2.so` | Yes |
| `slot_id` | `uint` | HSM slot ID | `0` | No |
| `pin` | `string` | PIN for HSM access | `1234` | Yes |
| `key_label` | `string` | Key label in HSM | `vc_key` | Yes |
| `key_id` | `string` | Key ID in HSM | `vc_key_id` | Yes |

---

## Verifier

Configuration for the Verifier service that verifies credentials and acts as an OIDC Provider.

### Verifier

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `api_server` | `object` | HTTP API server configuration | - | Yes |
| `grpc_server` | `object` | gRPC server configuration | - | Yes |
| `public_url` | `string` | Public URL of this service (must be valid HTTP/HTTPS URL) | - | Yes |
| `key_config` | `object` | Signing key configuration | - | Yes |
| `oauth_server` | `object` | OAuth2 server configuration | - | Yes |
| `preferred_vp_formats` | `object` | Preferred VP formats | - | No |
| `supported_wallets` | `object` | Supported wallet configurations | - | No |
| `oidc` | `object` | OIDC Provider configuration | - | No |
| `openid4vp` | `object` | OpenID4VP configuration | - | No |
| `digital_credentials` | `object` | W3C Digital Credentials API config | - | No |
| `authorization_page_css` | `object` | Authorization page styling | - | No |
| `credential_display` | `object` | Credential display settings | - | No |
| `trust` | `object` | Trust evaluation configuration | - | No |

### OIDCConfig

OIDC Provider configuration for the verifier's role as an OpenID Provider.

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `issuer` | `string` | OIDC Provider identifier | - | Yes |
| `session_duration` | `int` | Session duration in seconds | `3600` | Yes |
| `code_duration` | `int` | Authorization code duration in seconds | `300` | Yes |
| `access_token_duration` | `int` | Access token duration in seconds | `3600` | Yes |
| `id_token_duration` | `int` | ID token duration in seconds | `3600` | Yes |
| `refresh_token_duration` | `int` | Refresh token duration in seconds | `86400` | Yes |
| `subject_type` | `string` | Subject type: "public" or "pairwise" | - | Yes |
| `subject_salt` | `string` | Salt for pairwise subject generation | - | Yes |

### OpenID4VPConfig

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `presentation_timeout` | `int` | Presentation timeout in seconds | `300` | Yes |
| `supported_credentials` | `array` | Supported credential configurations | - | Yes |
| `presentation_requests_dir` | `string` | Directory with presentation request templates | - | No |

### SupportedCredentialConfig

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `vct` | `string` | Verifiable credential type | - | Yes |
| `scopes` | `array` | OIDC scopes that grant access to this credential | - | Yes |

**Example:**
```yaml
openid4vp:
  presentation_timeout: 300
  supported_credentials:
    - vct: "urn:eudi:pid:1"
      scopes:
        - "pid"
    - vct: "urn:eudi:ehic:1"
      scopes:
        - "ehic"
```

### DigitalCredentialsConfig

W3C Digital Credentials API configuration for browser-based credential presentation.

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `enabled` | `bool` | Enable Digital Credentials API | `false` | No |
| `use_jar` | `bool` | Enable JWT Authorization Request (JAR) | `false` | No |
| `preferred_formats` | `array` | Preferred credential formats | `["vc+sd-jwt", "dc+sd-jwt", "mso_mdoc"]` | No |
| `response_mode` | `string` | Response mode: "dc_api.jwt", "direct_post.jwt", or "direct_post" | `dc_api.jwt` | No |
| `allow_qr_fallback` | `bool` | Enable QR fallback if DC API unavailable | `true` | No |
| `deep_link_scheme` | `string` | Deep link scheme for mobile wallets | - | No |

### AuthorizationPageCSSConfig

Customization for the authorization page styling.

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `custom_css` | `string` | Inline CSS to inject | - | No |
| `css_file` | `string` | Path to external CSS file | - | No |
| `theme` | `string` | Predefined theme: "light", "dark", "blue", or "purple" | `light` | No |
| `primary_color` | `string` | Primary brand color (hex format) | - | No |
| `secondary_color` | `string` | Secondary brand color (hex format) | - | No |
| `logo_url` | `string` | URL to custom logo image | - | No |
| `title` | `string` | Page title | `Wallet Authorization` | No |
| `subtitle` | `string` | Page subtitle | - | No |

### CredentialDisplayConfig

Controls credential display before sending to RP.

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `enabled` | `bool` | Allow users to view credentials | `false` | No |
| `require_confirmation` | `bool` | Force credential review | `false` | No |
| `show_raw_credential` | `bool` | Display raw VP token | `false` | No |
| `show_claims` | `bool` | Display parsed claims | `true` | No |
| `allow_edit` | `bool` | Allow claim redaction (future feature) | `false` | No |

### TrustConfig

Configuration for key resolution and trust evaluation via go-trust.

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `go_trust_url` | `string` | go-trust PDP service URL | - | No |
| `local_did_methods` | `array` | DID methods resolved locally | `["did:key", "did:jwk"]` | No |
| `trust_policies` | `object` | Per-role trust policies | - | No |
| `enabled` | `bool` | Enable trust evaluation | `true` | No |

### TrustPolicyConfig

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `trust_frameworks` | `array` | Accepted trust frameworks | - | No |
| `trust_anchors` | `array` | Trusted root entities | - | No |
| `require_revocation_check` | `bool` | Enforce revocation checking | `false` | No |

**Example:**
```yaml
trust:
  enabled: true
  go_trust_url: "https://trust.example.com/pdp"
  local_did_methods:
    - "did:key"
    - "did:jwk"
  trust_policies:
    issuer:
      trust_frameworks:
        - "did:web"
        - "x509"
      trust_anchors:
        - "did:web:issuer.example.com"
      require_revocation_check: true
```

---

## Registry

Configuration for the Registry service that manages credential status.

### Registry

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `api_server` | `object` | HTTP API server configuration | - | Yes |
| `public_url` | `string` | Public URL of this service (must be valid HTTP/HTTPS URL) | - | Yes |
| `grpc_server` | `object` | gRPC server configuration | - | Yes |
| `token_status_lists` | `object` | Token Status List configuration | - | No |
| `admin_gui` | `object` | Admin GUI configuration | - | No |

### TokenStatusLists

Token Status List configuration per draft-ietf-oauth-status-list.

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `key_config` | `object` | Signing key configuration | - | Yes |
| `token_refresh_interval` | `int64` | Token refresh interval in seconds | `43200` (12 hours) | No |
| `section_size` | `int64` | Entries per section (decoys) | `1000000` (1 million) | No |
| `rate_limit_requests_per_minute` | `int` | Rate limit per IP | `60` | No |

### AdminGUI

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `enabled` | `bool` | Enable admin GUI | `true` | No |
| `username` | `string` | Admin username | `admin` | Yes (if enabled) |
| `password` | `string` | Admin password | - | Yes (if enabled) |
| `session_secret` | `string` | Secret for session cookies | - | Yes (if enabled) |

---

## Mock AS

Configuration for the Mock Authentic Source service (testing/development).

### MockAS

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `api_server` | `object` | HTTP API server configuration | - | Yes |
| `datastore_url` | `string` | Datastore service URL | - | Yes |
| `bootstrap_users` | `array` | User IDs to bootstrap on startup | `["100", "102"]` | No |

**Example:**
```yaml
mock_as:
  api_server:
    addr: ":8081"
  datastore_url: "http://datastore:8080"
  bootstrap_users:
    - "100"
    - "101"
    - "102"
```

---

## UI

Configuration for the UI service (web interface).

### UI

| Field | Type | Description | Default | Required |
|-------|------|-------------|---------|----------|
| `api_server` | `object` | HTTP API server configuration | - | Yes |
| `username` | `string` | UI login username | - | Yes |
| `password` | `string` | UI login password | - | Yes |
| `session_cookie_authentication_key` | `string` | Session cookie auth key | - | Yes |
| `session_store_encryption_key` | `string` | Session encryption key | - | Yes |
| `session_inactivity_timeout_in_seconds` | `int` | Session timeout | - | Yes |
| `services.apigw.base_url` | `string` | APIGW service URL | - | No |
| `services.mockas.base_url` | `string` | MockAS service URL | - | No |
| `services.verifier.base_url` | `string` | Verifier service URL | - | No |

---

## Minimal Configuration Example

Minimal viable configuration without SAML, OIDC RP, or PKCS11:

```yaml
common:
  tracing:
    addr: "jaeger:4318"
    type: "otlp"

auth_methods:
  basic:
    vcts:
      - "urn:eudi:pid:1"
    format: "dc+sd-jwt"
    claims:
      - "given_name"
      - "family_name"

credential_constructor:
  pid:
    vct: "urn:eudi:pid:1"
    vctm_file_path: "metadata/vctm_pid.json"
    format: "dc+sd-jwt"
    auth_method: "basic"

apigw:
  api_server:
    addr: ":8080"
  public_url: "https://issuer.example.com"
  registry_public_url: "https://registry.example.com"
  key_config:
    private_key_path: "/pki/apigw.key"
  issuer_client:
    addr: "issuer:8090"
  registry_client:
    addr: "registry:8090"

issuer:
  api_server:
    addr: ":8080"
  grpc_server:
    addr: ":8090"
  issuer_url: "https://issuer.example.com"
  key_config:
    private_key_path: "/pki/issuer.key"
  jwt_attribute:
    issuer: "https://issuer.example.com"
    verifiable_credential_type: "VerifiableCredential"

verifier:
  api_server:
    addr: ":8080"
  grpc_server:
    addr: ":8090"
  public_url: "https://verifier.example.com"
  key_config:
    private_key_path: "/pki/verifier.key"
  oauth_server:
    token_endpoint: "https://verifier.example.com/token"
    clients:
      rp_client:
        client_secret: "secret"
  oidc:
    issuer: "https://verifier.example.com"
    subject_type: "public"
    subject_salt: "random-salt"
  openid4vp:
    supported_credentials:
      - vct: "urn:eudi:pid:1"
        scopes: ["pid"]

registry:
  api_server:
    addr: ":8080"
  grpc_server:
    addr: ":8090"
  public_url: "https://registry.example.com"
```

---

## Complete Example Configuration

```yaml
common:
  production: false
  log:
    folder_path: "/var/log/vc"
  mongo:
    uri: "mongodb://localhost:27017/vc"
  tracing:
    addr: "jaeger:4318"
    type: "otlp"
    timeout: 10
  kafka:
    enabled: true
    brokers:
      - "kafka0:9092"
      - "kafka1:9092"
  credential_offer_qr:
    type: credential_offer
    qr:
      recovery_level: 2
      size: 256

auth_methods:
  basic:
    vcts:
      - "urn:eudi:pid:1"
    format: "dc+sd-jwt"
    claims:
      - "given_name"
      - "family_name"

credential_constructor:
  pid:
    vct: "urn:eudi:pid:1"
    vctm_file_path: "metadata/vctm_pid.json"
    format: "dc+sd-jwt"
    auth_method: "basic"

apigw:
  api_server:
    addr: ":8080"
    tls:
      enabled: true
      cert_file_path: "/pki/api_server.crt"
      key_file_path: "/pki/api_server.key"
  public_url: "https://issuer.example.com"
  registry_public_url: "https://registry.example.com"
  issuer_client:
    addr: "issuer:8090"
    tls: true
    cert_file_path: "/pki/apigw_client.crt"
    key_file_path: "/pki/apigw_client.key"
    ca_file_path: "/pki/ca.crt"
  registry_client:
    addr: "registry:8090"
    tls: true
    cert_file_path: "/pki/apigw_client.crt"
    key_file_path: "/pki/apigw_client.key"
    ca_file_path: "/pki/ca.crt"

issuer:
  api_server:
    addr: ":8080"
  grpc_server:
    addr: ":8090"
    tls:
      enabled: true
  issuer_url: "https://issuer.example.com"
  jwt_attribute:
    issuer: "https://issuer.example.com"
    verifiable_credential_type: "VerifiableCredential"

verifier:
  api_server:
    addr: ":8080"
  grpc_server:
    addr: ":8090"
  public_url: "https://verifier.example.com"
  oidc:
    issuer: "https://verifier.example.com"
    session_duration: 3600
    code_duration: 300
    access_token_duration: 3600
    id_token_duration: 3600
    refresh_token_duration: 86400
    subject_type: "public"
    subject_salt: "random-salt-value"
  openid4vp:
    presentation_timeout: 300
    supported_credentials:
      - vct: "urn:eudi:pid:1"
        scopes: ["pid"]

registry:
  api_server:
    addr: ":8080"
  grpc_server:
    addr: ":8090"
  public_url: "https://registry.example.com"
  admin_gui:
    enabled: true
    username: "admin"
    password: "changeme"
    session_secret: "random-secret"
```

---

## Key Configuration Types

Key configuration is used across multiple services for signing operations. It can use:
- File-based keys (PEM format)
- PKCS#11 HSM
- Remote KMS

Refer to the `pkg/pki` package documentation for detailed key configuration options.
