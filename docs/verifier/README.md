# Verifier Service

## Overview

The **Verifier** is a unified service that enables verification of EU Digital Identity Wallet credentials through two interfaces:

1. **OpenID Connect (OIDC) Provider** - Allows traditional OIDC Relying Parties (such as Keycloak, Auth0, or any OIDC-compliant IAM platform) to authenticate users via EU Digital Identity Wallets
2. **Direct OpenID4VP API** - Provides direct verification capabilities for applications that want to verify credentials without going through OIDC

This service acts as a protocol translator, presenting:
- **Standard OIDC interface** to Relying Parties (authorization endpoint, token endpoint, userinfo endpoint)
- **OpenID4VP interface** to EU Digital Identity Wallets (presentation request, direct post)
- **Direct verification API** for custom integrations

> **Note**: The OIDC provider functionality and credential verification are provided by a single unified verifier service (see ADR-06).

### Important: Terminology Clarification

The term "issuer" has different meanings in this system:

- **OIDC Issuer**: The verifier acts as an OIDC Provider that **issues ID tokens and access tokens** to relying parties. The OIDC `issuer` field identifies the verifier itself.
- **VC Issuer**: A separate service (see `cmd/issuer/`) that **issues verifiable credentials** to wallets. The verifier does NOT issue credentials; it only verifies them.

The verifier verifies credentials that were previously issued by VC issuers and stored in user wallets.

## Use Cases

- **Enable wallet authentication in existing IAM platforms** (Keycloak, Auth0, Okta, etc.)
- **Add verifiable credential support to OIDC applications** without code changes
- **Centralized wallet verification** for multiple relying parties
- **Identity federation** between traditional OIDC and wallet-based authentication
- **Direct credential verification** for custom applications

## Architecture

```
┌──────────────┐         ┌──────────────────┐         ┌──────────────┐
│              │  OIDC   │                  │ OpenID4VP│              │
│   Keycloak   │◄───────►│    Verifier      │◄────────►│  EUDI Wallet │
│     (RP)     │         │ (OIDC Provider   │         │  (Has VCs)   │
└──────────────┘         │  + VP Verifier)  │         └──────────────┘
                         └──────────────────┘
                                   │
                                   ▼
                             ┌──────────┐
                             │ MongoDB  │
                             └──────────┘
```

## Features

### OIDC Provider Capabilities
✅ Authorization Code Flow with PKCE  
✅ Client authentication (client_secret_post, client_secret_basic, private_key_jwt)  
✅ ID Token generation with verifiable credential claims  
✅ UserInfo endpoint  
✅ Discovery (.well-known/openid-configuration)  
✅ JWKS endpoint  
✅ Refresh tokens  
✅ Pairwise/public subject identifiers  
✅ Dynamic Client Registration (RFC 7591)

### OpenID4VP Capabilities
✅ Presentation request generation  
✅ Request object (signed JWT)  
✅ Direct post response mode  
✅ Digital Credentials API support (W3C)
✅ Credential verification (signature, status)  
✅ Claim extraction and mapping  
✅ QR code generation  
✅ Deep link support  
✅ DCQL (Digital Credentials Query Language) support

### Security Features
✅ PKCE enforcement for public clients  
✅ State parameter validation  
✅ Nonce validation  
✅ Authorization code single-use  
✅ Token expiration  
✅ Session timeout  
✅ Pairwise pseudonymous identifiers  
✅ Rate limiting on sensitive endpoints

## Quick Start

### Prerequisites

- Go 1.25+
- MongoDB 4.4+
- Docker (optional)

### Build

```bash
# Build all services
make build

# Build verifier only
make build-verifier

# Build Docker image
make docker-build-verifier
```

### Configuration

Create or update `config.yaml`:

```yaml
verifier:
  api_server:
    addr: :8080
    tls:
      enabled: false
  external_url: "http://localhost:8080"

  # OIDC and OpenID4VP settings (nested under verifier)
  
  oidc:
    # OIDC Provider identifier - identifies this verifier service
    # This is NOT related to verifiable credential issuance
    # Must match the 'iss' claim in ID tokens issued to relying parties
    issuer: "http://localhost:8080"
    signing_key_path: "/path/to/oidc_signing_key.pem"
    signing_alg: "RS256"
    session_duration: 900        # 15 minutes
    code_duration: 300           # 5 minutes
    access_token_duration: 3600  # 1 hour
    id_token_duration: 3600      # 1 hour
    refresh_token_duration: 2592000  # 30 days
    subject_type: "pairwise"     # or "public"
    subject_salt: "change-this-to-random-value"
  
  openid4vp:
    presentation_timeout: 300    # 5 minutes
    supported_credentials:
      - vct: "urn:eudi:pid:1"
        scopes: ["openid", "profile", "email"]
      - vct: "urn:eudi:ehic:1"
        scopes: ["ehic"]
      - vct: "urn:eudi:diploma:1"
        scopes: ["diploma"]
    presentation_requests_dir: "/presentation_requests"

  digital_credentials:
    enabled: true
    use_jar: true
    preferred_formats: ["vc+sd-jwt", "dc+sd-jwt", "mso_mdoc"]
    response_mode: "dc_api.jwt"
    allow_qr_fallback: true

common:
  mongo:
    uri: mongodb://localhost:27017
  production: false
  tracing:
    addr: jaeger:4318
    type: jaeger
```

### Run

```bash
# Set config path
export VC_CONFIG_YAML=config.yaml

# Run service
./bin/vc_verifier

# Or with Docker
docker-compose up verifier
```

## API Endpoints

### OIDC Endpoints (for Relying Parties)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/openid-configuration` | GET | OpenID Provider discovery metadata |
| `/jwks` | GET | JSON Web Key Set for token verification |
| `/authorize` | GET | Authorization endpoint - initiates authentication |
| `/token` | POST | Token endpoint - exchanges code for tokens |
| `/userinfo` | GET | UserInfo endpoint - returns user claims |
| `/register` | POST | Dynamic client registration |
| `/register/{client_id}` | GET/PUT/DELETE | Client configuration management |

### OpenID4VP Endpoints (for Wallets)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/verification/request-object/{session_id}` | GET | Signed request object for wallet |
| `/verification/direct_post` | POST | Receives VP from wallet |
| `/verification/callback` | GET | Redirect with authorization code |
| `/qrcode/{session_id}` | GET | QR code for session |
| `/poll/{session_id}` | GET | Poll session status |

### Session Management Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/session/preference` | PUT | Update session display preferences |
| `/verification/display/{session_id}` | GET | Credential display data |
| `/verification/display/{session_id}/confirm` | POST | Confirm credential display |

## Integration with Keycloak

### 1. Add Verifier as Identity Provider

1. Go to Keycloak Admin Console
2. Select your realm
3. Navigate to **Identity Providers** → **Add provider** → **OpenID Connect v1.0**
4. Configure:
   - **Alias**: `wallet`
   - **Display Name**: `EU Digital Identity Wallet`
   - **Discovery Endpoint**: `http://localhost:8080/.well-known/openid-configuration`
   - **Client ID**: `keycloak-dev`
   - **Client Secret**: `your-secret`
   - **Client Authentication**: `Client secret sent as post`
   - **Validate Signatures**: `ON`
   - **Use PKCE**: `ON`

### 2. Configure Claim Mappings

Add mappers in Keycloak to map wallet claims to user attributes:

- **Username**: `sub`
- **First Name**: `given_name`
- **Last Name**: `family_name`
- **Email**: `email`
- **Birth Date**: `birthdate`
- **Nationality**: `nationality`

## Scope to Credential Mapping

| Scope | Credential Type | Claims |
|-------|----------------|--------|
| `openid` | PID | `sub` |
| `profile` | PID | `given_name`, `family_name`, `birthdate`, `nationality` |
| `email` | PID | `email` |
| `address` | PID | `address` |
| `ehic` | EHIC | All EHIC fields |
| `diploma` | Diploma | All diploma fields |

## Security Considerations

### Subject Identifier Generation

The `sub` claim can be generated in two modes:

**Pairwise** (recommended for privacy):
```
sub = BASE64URL(SHA256(wallet_id + client_id + salt))
```
Different `sub` for each client prevents cross-RP correlation.

**Public**:
```
sub = BASE64URL(SHA256(wallet_id + salt))
```
Same `sub` across all clients.

### Token Security

- Authorization codes are single-use and expire after 5 minutes
- PKCE is enforced for public clients and recommended for all
- Access tokens are bearer tokens, protect in transit and storage
- Refresh tokens can be rotated on each use
- All tokens should use HTTPS in production

### VP Validation

The verifier validates:
1. VP token signature (wallet's signature)
2. Credential signature (issuer's signature)
3. Credential status (not revoked)
4. Presentation submission matches presentation definition
5. Nonce prevents replay attacks

## Development

### Project Structure

```
cmd/verifier/                 # Main entry point
  main.go
internal/verifier/            # Internal implementation
  apiv1/                      # API handlers
    client.go                 # API client setup
    handlers.go               # Health check
    handler_oidc.go           # OIDC endpoints (authorize, token)
    handler_openid4vp.go      # OpenID4VP handling
    handler_api.go            # Discovery, JWKS, QR code, etc.
    handler_client_registration.go  # Dynamic client registration
    handler_session_preference.go   # Session display preferences
    testing.go                # Test helpers
  db/                         # Database layer
    service.go                # MongoDB connection
    session.go                # Session CRUD
    client.go                 # Client CRUD
  httpserver/                 # HTTP server
    service.go                # Server setup, routing
    endpoints_*.go            # Route handlers
  static/                     # Static files (HTML templates)
```

### Testing

```bash
# Run tests
go test ./internal/verifier/...

# With coverage
go test -cover ./internal/verifier/...
```



## Troubleshooting

### Common Issues

**Client not found**
- Ensure client is registered in MongoDB `clients` collection
- Verify `client_id` matches

**Invalid redirect URI**
- Check `redirect_uris` array in client document
- URI must match exactly (including trailing slashes)

**PKCE validation failed**
- Ensure `code_verifier` is sent in token request
- Verify `code_challenge` calculation: `BASE64URL(SHA256(code_verifier))`

**VP validation failed**
- Check credential signature and issuer trust
- Verify credential hasn't been revoked
- Ensure wallet DID is resolvable

## Production Deployment

### Required Changes for Production

1. **Enable TLS**:
```yaml
api_server:
  tls:
    enabled: true
    cert_path: "/path/to/cert.pem"
    key_path: "/path/to/key.pem"
```

2. **Use strong subject salt**:
```bash
openssl rand -base64 32
```

3. **Configure proper MongoDB**:
   - Use authentication
   - Enable TLS
   - Set up replication

4. **Set up monitoring**:
   - Configure tracing endpoint
   - Set up log aggregation
   - Monitor session expiration

5. **Secure secrets**:
   - Use environment variables or secret management
   - Hash client secrets with bcrypt
   - Rotate keys regularly

## License

Same as the parent VC project.

## Support

For issues and questions, see the main VC project documentation.
