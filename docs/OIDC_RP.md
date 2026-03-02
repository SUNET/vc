# OIDC Relying Party (RP) Integration

## Overview

The OIDC RP feature enables the APIGW service to act as an OpenID Connect Relying Party, allowing users to authenticate with external OIDC Providers (Google, Azure AD, Keycloak, etc.) and receive verifiable credentials based on the claims returned by those providers.

This is an **optional feature** that must be enabled at compile time using the `oidcrp` build tag.

## Architecture

### Authentication Flow

```
┌─────────┐                 ┌─────────┐                 ┌──────────────┐
│ Wallet  │                 │  APIGW  │                 │ OIDC Provider│
│         │                 │ (OIDC RP)│                │ (Google/etc.)│
└────┬────┘                 └────┬────┘                 └──────┬───────┘
     │                           │                             │
     │ 1. Initiate Auth          │                             │
     │ POST /oidcrp/initiate     │                             │
     │ {credential_type: "pid"}  │                             │
     ├──────────────────────────►│                             │
     │                           │                             │
     │                           │ 2. Generate PKCE challenge  │
     │                           │    Create session           │
     │                           │                             │
     │ 3. Authorization URL      │                             │
     │ {authorization_url, state}│                             │
     │◄──────────────────────────┤                             │
     │                           │                             │
     │ 4. Redirect to OIDC Provider                            │
     ├─────────────────────────────────────────────────────────►
     │                           │                             │
     │                           │         5. User Login       │
     │                           │         & Consent           │
     │                           │                             │
     │ 6. Callback with code     │                             │
     │ GET /oidcrp/callback?code=...&state=...                 │
     │◄─────────────────────────────────────────────────────────
     │                           │                             │
     │                           │ 7. Exchange code for tokens │
     │                           │    (with PKCE verifier)     │
     │                           ├────────────────────────────►│
     │                           │                             │
     │                           │ 8. ID Token + Access Token  │
     │                           │◄────────────────────────────┤
     │                           │                             │
     │                           │ 9. Verify ID Token          │
     │                           │    (signature, nonce, etc.) │
     │                           │                             │
     │                           │ 10. Fetch UserInfo (optional)
     │                           ├────────────────────────────►│
     │                           │                             │
     │                           │ 11. UserInfo claims         │
     │                           │◄────────────────────────────┤
     │                           │                             │
     │                           │ 12. Transform claims to     │
     │                           │     credential format       │
     │                           │                             │
     │                           │ 13. Issue credential        │
     │                           │     via Issuer gRPC         │
     │                           │                             │
     │ 14. Credential + Offer    │                             │
     │◄──────────────────────────┤                             │
     │                           │                             │
```

### Key Components

1. **Session Store** (`pkg/oidcrp/session.go`)
   - In-memory session storage with automatic expiration
   - Stores OAuth2 state, PKCE code_verifier, nonce, credential_type
   - Thread-safe with mutex protection
   - Automatic cleanup every 5 minutes

2. **OIDC Service** (`pkg/oidcrp/service.go`)
   - OIDC Provider discovery via `.well-known/openid-configuration`
   - OAuth2 authorization code flow with PKCE (S256)
   - ID Token verification (signature, nonce, expiration)
   - UserInfo endpoint support for extended claims

3. **Claim Transformer** (`pkg/oidcrp/transformer.go`)
   - Protocol-agnostic claim transformation
   - Supports dot-notation for nested structures
   - Optional transformations: lowercase, uppercase, trim
   - Required/optional claim validation
   - Default values for missing claims

4. **HTTP Endpoints** (`internal/apigw/httpserver/endpoints_oidcrp.go`)
   - `POST /oidcrp/initiate` - Start authentication
   - `GET /oidcrp/callback` - Handle provider callback

## Building with OIDC RP Support

### Compile with OIDC RP enabled:
```bash
go build -tags=oidcrp ./cmd/apigw/
```

### Compile without OIDC RP (smaller binary):
```bash
go build ./cmd/apigw/
```

When built without the `oidcrp` tag, stub implementations are used and the feature is completely disabled.

## Configuration

### Basic Configuration

Add the `oidcrp` section to your `config.yaml` under `apigw`:

```yaml
apigw:
  oidcrp:
    enabled: true
    client_id: "your-client-id"
    client_secret: "your-client-secret"
    redirect_uri: "https://issuer.example.com/oidcrp/callback"
    issuer_url: "https://accounts.google.com"
    scopes:
      - "openid"
      - "profile"
      - "email"
    session_duration: 300
    credential_mappings:
      pid:
        credential_config_id: "urn:eudi:pid:1"
        attributes:
          given_name:
            claim: "identity.given_name"
            required: true
          family_name:
            claim: "identity.family_name"
            required: true
          email:
            claim: "identity.email"
            required: true
```

### Provider-Specific Examples

#### Google

```yaml
oidcrp:
  enabled: true
  client_id: "123456789-abcdefg.apps.googleusercontent.com"
  client_secret: "GOCSPX-xxxxxxxxxxxxxxxxxxxx"
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
        given_name:
          claim: "identity.given_name"
          required: true
        family_name:
          claim: "identity.family_name"
          required: true
        email:
          claim: "identity.email"
          required: true
        email_verified:
          claim: "identity.email_verified"
          required: false
        sub:
          claim: "identity.subject_id"
          required: true
        picture:
          claim: "identity.picture_url"
          required: false
```

#### Azure AD

```yaml
oidcrp:
  enabled: true
  client_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  client_secret: "your-azure-client-secret"
  redirect_uri: "https://issuer.example.com/oidcrp/callback"
  # Replace {tenant-id} with your Azure AD tenant ID
  issuer_url: "https://login.microsoftonline.com/{tenant-id}/v2.0"
  scopes:
    - "openid"
    - "profile"
    - "email"
  credential_mappings:
    pid:
      credential_config_id: "urn:eudi:pid:1"
      attributes:
        given_name:
          claim: "identity.given_name"
          required: true
        family_name:
          claim: "identity.family_name"
          required: true
        email:
          claim: "identity.email"
          required: true
        upn:
          claim: "identity.upn"
          required: false
        oid:
          claim: "identity.azure_oid"
          required: true
```

#### Keycloak

```yaml
oidcrp:
  enabled: true
  client_id: "issuer-service"
  client_secret: "keycloak-client-secret"
  redirect_uri: "https://issuer.example.com/oidcrp/callback"
  # Replace {realm-name} with your Keycloak realm
  issuer_url: "https://keycloak.example.com/realms/{realm-name}"
  scopes:
    - "openid"
    - "profile"
    - "email"
  credential_mappings:
    pid:
      credential_config_id: "urn:eudi:pid:1"
      attributes:
        given_name:
          claim: "identity.given_name"
          required: true
        family_name:
          claim: "identity.family_name"
          required: true
        email:
          claim: "identity.email"
          required: true
        preferred_username:
          claim: "identity.username"
          required: true
        # Custom Keycloak attributes
        organization:
          claim: "identity.organization"
          required: false
          default: "Unknown"
```

### Dynamic Client Registration (RFC 7591)

Instead of manually pre-registering your OIDC RP with each provider, you can enable **dynamic client registration** to automatically register at runtime. This is especially useful for:

- Development/testing environments
- Multi-tenant scenarios
- Providers that support dynamic registration (Google, Keycloak, etc.)

#### How It Works

1. When `dynamic_registration.enabled: true`, the service attempts to register with the OIDC Provider on startup
2. The provider's `registration_endpoint` is discovered via `.well-known/openid-configuration`
3. Registration request is sent with client metadata (name, redirect_uri, scopes, etc.)
4. Provider returns `client_id` and `client_secret`
5. Credentials are cached to `storage_path` (if configured) to avoid re-registration on restart
6. Cached credentials are reused until they expire (if `client_secret_expires_at` is set)

#### Configuration Example

```yaml
oidcrp:
  enabled: true
  # Static credentials are optional when using dynamic registration
  # client_id: "optional-fallback-id"
  # client_secret: "optional-fallback-secret"
  
  redirect_uri: "https://issuer.example.com/oidcrp/callback"
  issuer_url: "https://accounts.google.com"
  scopes:
    - "openid"
    - "profile"
    - "email"
  
  # Client metadata for registration
  client_name: "My Credential Issuer"
  client_uri: "https://issuer.example.com"
  logo_uri: "https://issuer.example.com/logo.png"
  contacts:
    - "admin@example.com"
  tos_uri: "https://issuer.example.com/terms"
  policy_uri: "https://issuer.example.com/privacy"
  
  # Enable dynamic registration
  dynamic_registration:
    enabled: true
    # Some providers (e.g., Keycloak) require an initial access token
    initial_access_token: "optional-bearer-token"
    # Cache credentials to avoid re-registration
    storage_path: "/var/lib/vc/oidcrp_credentials.json"
  
  credential_mappings:
    pid:
      credential_config_id: "urn:eudi:pid:1"
      attributes:
        given_name:
          claim: "identity.given_name"
          required: true
        family_name:
          claim: "identity.family_name"
          required: true
        email:
          claim: "identity.email"
          required: true
```

#### Provider-Specific Notes

**Google**
- Supports dynamic registration without initial access token
- Registration endpoint: `https://accounts.google.com/o/oauth2/register`
- No special configuration needed

**Azure AD**
- Does NOT support RFC 7591 dynamic registration
- Must use Azure Portal to pre-register clients
- Use static `client_id` and `client_secret`

**Keycloak**
- Supports dynamic registration with initial access tokens
- Generate initial access token in Keycloak admin console:
  - Go to Realm Settings → Client Registration → Initial Access Tokens
  - Create new token and copy it to `initial_access_token` field
- Registration endpoint: `https://keycloak.example.com/realms/{realm}/clients-registrations/openid-connect`

**Example: Keycloak with Dynamic Registration**

```yaml
oidcrp:
  enabled: true
  redirect_uri: "https://issuer.example.com/oidcrp/callback"
  issuer_url: "https://keycloak.example.com/realms/master"
  scopes:
    - "openid"
    - "profile"
    - "email"
  
  client_name: "Issuer Service (Auto-Registered)"
  client_uri: "https://issuer.example.com"
  
  dynamic_registration:
    enabled: true
    # Get this from Keycloak admin console
    initial_access_token: "eyJhbGciOiJIUzI1NiIsInR5cCI..."
    storage_path: "/var/lib/vc/keycloak_credentials.json"
  
  credential_mappings:
    pid:
      credential_config_id: "urn:eudi:pid:1"
      attributes:
        given_name:
          claim: "identity.given_name"
          required: true
        family_name:
          claim: "identity.family_name"
          required: true
```

#### Cached Credentials Format

When `storage_path` is configured, registered credentials are cached in JSON format:

```json
{
  "client_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "client_secret": "super-secret-string",
  "registration_access_token": "optional-token-for-updates",
  "registration_client_uri": "https://provider.com/clients/a1b2c3d4...",
  "client_secret_expires_at": 1735689600,
  "registered_at": "2024-01-15T10:30:00Z"
}
```

**Security Notes:**
- Cached credential files should have `0600` permissions (owner read/write only)
- The `storage_path` directory should be protected
- Consider using volume mounts for Docker deployments
- Rotate credentials periodically if provider supports it

#### Fallback to Static Credentials

You can configure both dynamic registration AND static credentials for failover:

```yaml
oidcrp:
  enabled: true
  # Static credentials as fallback
  client_id: "fallback-client-id"
  client_secret: "fallback-client-secret"
  
  redirect_uri: "https://issuer.example.com/oidcrp/callback"
  issuer_url: "https://provider.example.com"
  scopes:
    - "openid"
    - "profile"
  
  # Try dynamic registration first
  dynamic_registration:
    enabled: true
    storage_path: "/var/lib/vc/credentials.json"
  
  credential_mappings:
    # ...
```

If dynamic registration fails, the service will use the static credentials.

### Credential Mappings

Credential mappings define how OIDC claims are transformed into credential claims.

#### Attribute Mapping Fields

- **claim**: Target claim path in the credential (supports dot-notation)
  - Example: `"given_name"` for flat structure
  - Example: `"identity.given_name"` for nested structure

- **required**: Whether this claim must be present (boolean)
  - If `true` and claim is missing, authentication fails
  - If `false` and claim is missing, it's omitted (unless default is set)

- **transform**: Optional transformation to apply (string)
  - `"lowercase"` - Convert string to lowercase
  - `"uppercase"` - Convert string to uppercase
  - `"trim"` - Remove leading/trailing whitespace

- **default**: Default value if claim is missing (string)
  - Only used if `required: false`

#### Example: Complete Mapping

```yaml
credential_mappings:
  diploma:
    credential_config_id: "urn:eudi:diploma:1"
    attributes:
      # Required claim with no transformation
      email:
        claim: "student.email"
        required: true
      
      # Required claim with lowercase transformation
      username:
        claim: "student.username"
        required: true
        transform: "lowercase"
      
      # Optional claim with default value
      university:
        claim: "diploma.university"
        required: false
        default: "Unknown University"
      
      # Nested structure example
      given_name:
        claim: "student.personal_info.given_name"
        required: true
        transform: "trim"
      
      # Complex nested example
      degree_title:
        claim: "diploma.degree.title"
        required: true
      
      graduation_year:
        claim: "diploma.graduation.year"
        required: true
```

This would transform OIDC claims like:
```json
{
  "email": "student@example.com",
  "username": "STUDENT123",
  "given_name": "  John  ",
  "degree_title": "Bachelor of Science",
  "graduation_year": "2024"
}
```

Into a credential document:
```json
{
  "student": {
    "email": "student@example.com",
    "username": "student123",
    "personal_info": {
      "given_name": "John"
    }
  },
  "diploma": {
    "university": "Unknown University",
    "degree": {
      "title": "Bachelor of Science"
    },
    "graduation": {
      "year": "2024"
    }
  }
}
```

## API Usage

### 1. Initiate Authentication

**Endpoint**: `POST /oidcrp/initiate`

**Request**:
```json
{
  "credential_type": "pid"
}
```

**Response**:
```json
{
  "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth?client_id=...&redirect_uri=...&response_type=code&scope=openid+profile+email&state=abc123&code_challenge=xyz&code_challenge_method=S256&nonce=def456",
  "state": "abc123"
}
```

**Usage**:
1. Client calls this endpoint with desired credential type
2. Server generates OAuth2 authorization URL with PKCE challenge
3. Client redirects user to the `authorization_url`
4. User authenticates with OIDC Provider

### 2. Handle Callback

**Endpoint**: `GET /oidcrp/callback?code=AUTH_CODE&state=STATE`

This endpoint is called by the OIDC Provider after successful authentication.

**Response**:
```json
{
  "status": "success",
  "credential_type": "pid",
  "credential": "eyJhbGc...",
  "credential_offer": {
    "credential_issuer": "https://issuer.example.com",
    "credential_configuration_ids": ["urn:eudi:pid:1"],
    "grants": {
      "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
        "pre-authorized_code": "oidcrp_1234567890"
      }
    }
  },
  "message": "OIDC authentication and credential issuance successful"
}
```

## Security Considerations

### PKCE (Proof Key for Code Exchange)

OIDC RP implementation mandates PKCE using the S256 method:
- Protects against authorization code interception attacks
- Required for public clients and recommended for all clients
- `code_verifier`: 43-128 character random string
- `code_challenge`: Base64URL(SHA256(code_verifier))

### State Parameter

- Cryptographically random 32-character string
- Protects against CSRF attacks
- Validated on callback to ensure request authenticity

### Nonce

- Included in ID Token to prevent replay attacks
- Verified against session nonce on token reception

### ID Token Verification

The service automatically verifies:
1. **Signature**: Using OIDC Provider's public keys (JWKS)
2. **Issuer**: Matches configured issuer URL
3. **Audience**: Matches client ID
4. **Expiration**: Token is not expired
5. **Nonce**: Matches session nonce

### Session Management

- In-memory storage (sessions not persisted)
- Automatic expiration (default: 1 hour)
- Cleanup of expired sessions every 5 minutes
- Sessions deleted after successful credential issuance

## Troubleshooting

### OIDC RP not available

**Error**: `OIDC RP is not enabled`

**Solution**: Rebuild with the `oidcrp` build tag:
```bash
go build -tags=oidcrp ./cmd/apigw/
```

### Provider discovery fails

**Error**: `failed to discover OIDC provider`

**Causes**:
- Invalid `issuer_url`
- Network connectivity issues
- Provider doesn't support OpenID Connect Discovery

**Solution**: Verify issuer URL and ensure `.well-known/openid-configuration` is accessible

### Token exchange fails

**Error**: `failed to exchange code for tokens`

**Causes**:
- Invalid `client_id` or `client_secret`
- Incorrect `redirect_uri` (must match registered URI exactly)
- PKCE verification failure
- Expired authorization code

**Solution**: Verify OAuth2 client configuration with provider

### Missing required claims

**Error**: `missing required claim: email`

**Solution**: 
- Ensure requested scopes include necessary claims
- Check provider's claim mapping
- Mark claim as `required: false` if it's optional

### Claim transformation errors

**Error**: `failed to set claim identity.given_name`

**Causes**:
- Conflicting claim paths (e.g., "identity" used as both object and value)
- Invalid dot-notation syntax

**Solution**: Review credential mapping paths for conflicts

## Differences from SAML Integration

| Feature | OIDC RP | SAML |
|---------|---------|------|
| Protocol | OAuth2 + OIDC | SAML 2.0 |
| Token Format | JWT (ID Token) | XML (Assertion) |
| Discovery | `.well-known/openid-configuration` | Metadata XML |
| Security | PKCE, nonce, state | XML Signatures |
| Claim Format | JSON | XML Attributes |
| Session | OAuth2 state + PKCE | SAML Request ID |
| Provider Setup | OAuth2 client registration | SP metadata exchange |

## Dependencies

- `github.com/coreos/go-oidc/v3/oidc` - OIDC client library
- `golang.org/x/oauth2` - OAuth2 client library

These dependencies are vendored and only included when building with `-tags=oidcrp`.

## Testing

### Manual Testing with Google

1. Create OAuth2 credentials at https://console.cloud.google.com/apis/credentials
2. Configure authorized redirect URI: `https://your-issuer.com/oidcrp/callback`
3. Update `config.yaml` with client ID and secret
4. Build with OIDC RP support
5. Call initiate endpoint
6. Follow authorization URL in browser
7. Authenticate with Google account
8. Observe callback with credential

### Integration Tests

Integration tests with mock OIDC provider are located in:
```
internal/apigw/integration/oidcrp_test.go
```

Run tests with:
```bash
go test -tags=oidcrp ./internal/apigw/integration/
```

## Future Enhancements

- [ ] Support for additional OIDC features (e.g., refresh tokens)
- [ ] Persistent session storage (Redis, database)
- [ ] Multi-provider support (multiple OIDC providers simultaneously)
- [ ] Advanced claim transformation (JSONPath, custom functions)
- [ ] Logout flow implementation
- [ ] Support for OpenID Connect Federation

## Related Documentation

- [SAML Integration](./SAML.md) - Similar authentication pattern using SAML
- [OpenID4VCI](../standards/api_specification.md) - Credential issuance protocol
- [Configuration Guide](../README.md#configuration) - General configuration
