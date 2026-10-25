# OIDC Relying Party (RP) Integration

## Overview

The OIDC RP feature enables the APIGW service to act as an OpenID Connect Relying Party, allowing users to authenticate with external OIDC Providers (Google, Azure AD, Keycloak, etc.) and receive verifiable credentials based on the claims returned by those providers.

`apigw.auth_providers.oidc.enable: true` turns the feature on. A credential scope authenticates through it when its data source sets `auth_provider: oidc`.

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
     │                           │ 12. Map claims, apply       │
     │                           │     derivations and policy  │
     │                           │                             │
     │                           │ 13. Store document under a  │
     │                           │     pre-authorized code     │
     │                           │                             │
     │ 14. Credential offer      │                             │
     │◄──────────────────────────┤                             │
     │                           │                             │
```

The wallet redeems the offer at the token and credential endpoints, and the issuer signs the credential then.

A wallet can also reach the OIDC Provider through the OpenID4VCI authorization flow. The consent page starts the OIDC flow for a scope whose data source sets `auth_provider: oidc`. The callback stores the document in the OpenID4VCI session and redirects the browser to `/authorization/consent/#/credentials`.

### Key Components

1. **Session Store** (`internal/apigw/auth_providers/oidcrp/session.go`)
   - Sessions live in the apigw cache `apigw_oidcrp_sessions`: in memory, or in MongoDB when `common.ha.enable` is set
   - Stores OAuth2 state, PKCE code_verifier, nonce, credential type and client ID
   - Expires after `session_duration`

2. **OIDC Service** (`internal/apigw/auth_providers/oidcrp/service.go`)
   - OIDC Provider discovery via `.well-known/openid-configuration`
   - OAuth2 authorization code flow with PKCE (S256)
   - ID Token verification (signature, nonce, expiration)
   - UserInfo endpoint support for extended claims
   - RFC 7591 dynamic client registration (`dynamic_registration.go`)

3. **Attribute Mapper** (`pkg/credential/attribute_mapping.go`)
   - Renames OIDC claims to claim paths, with dot-notation for nested structures
   - Required/optional claim validation
   - Default values for missing claims

4. **HTTP Endpoints** (`internal/apigw/httpserver/endpoints_oidcrp.go`)
   - `POST /oidcrp/initiate` - Start authentication
   - `GET /oidcrp/callback` - Handle provider callback

## Configuration

OIDC RP configuration has two parts:

1. `apigw.auth_providers.oidc` configures the Relying Party.
2. Each credential scope that authenticates with OIDC sets `auth_provider: oidc` under `apigw.data_sources`.

[CONFIGURATION.md](./CONFIGURATION.md) lists every field.

### Basic Configuration

```yaml
apigw:
  auth_providers:
    oidc:
      enable: true
      issuer_url: "https://accounts.google.com"
      redirect_uri: "https://issuer.example.com/oidcrp/callback"
      scopes:
        - "openid"
        - "profile"
        - "email"
      session_duration: 300
      registration:
        preconfigured:
          enable: true
          client_id: "your-client-id"
          client_secret: "your-client-secret"
  data_sources:
    assertion:
      scopes:
        pid:
          auth_provider: oidc
```

- `redirect_uri` is the apigw's `/oidcrp/callback` endpoint. Register it with the provider.
- `scopes` must include `openid`. The default is `["openid", "profile", "email"]`.
- `session_duration` is how long, in seconds, an authorization flow may take. The default is 300.
- `registration` holds exactly one of `preconfigured` and `dynamic`.
- `client_secret` can move to the secrets file, under the same path (see `secrets.example.yaml`).

### Provider-Specific Settings

Providers differ in `issuer_url` and in how the client is registered:

| Provider | `issuer_url` | Registration |
|----------|--------------|--------------|
| Google | `https://accounts.google.com` | `preconfigured`, with OAuth2 credentials from the Google Cloud console |
| Azure AD | `https://login.microsoftonline.com/{tenant-id}/v2.0` | `preconfigured`, with a client registered in the Azure Portal |
| Keycloak | `https://keycloak.example.com/realms/{realm-name}` | `preconfigured`, or `dynamic` with an initial access token |

### Data Sources

The data source of a scope decides what the OIDC claims are used for:

| Data source | Use of the OIDC claims |
|-------------|------------------------|
| `assertion` | The claims are the credential's data. `defaults` and `expiry_duration` supply credential fields such as `issuing_authority` and `date_of_expiry`. |
| `datastore` | The claims identify the user. `auth_claims` names the claims matched against the identities of documents pre-loaded under `authentic_source`. |
| `external_api` | The claims identify the user. The `remote` API supplies the credential's data. |

```yaml
apigw:
  data_sources:
    assertion:
      scopes:
        pid:
          auth_provider: oidc
          expiry_duration: "8760h"
          defaults:
            issuing_authority: "Example Issuer"
            issuing_country: "SE"
    datastore:
      scopes:
        ehic:
          auth_provider: oidc
          authentic_source: "SUNET"
          auth_claims: ["given_name", "family_name", "birth_date"]
    external_api:
      scopes:
        diploma:
          auth_provider: oidc
          remote: ladok
  remotes:
    ladok:
      type: eduapi
      base_url: "https://api.ladok.se/eduapi"
      token_url: "https://api.ladok.se/oauth2/token"
      client_id: "vc-ladok"
      client_secret: "ladok-client-secret"
```

`auth_claims` names identity fields: `given_name`, `family_name`, `birth_date`, `birth_place`, `authentic_source_person_id` and `personal_administrative_number`. Where the provider names a claim differently, `attribute_mapping` renames it.

Each scope also accepts `oidc_request_params`, `issuance_policy` and `derivations`.

### Dynamic Client Registration (RFC 7591)

With `registration.dynamic`, the service registers itself with the OIDC Provider at startup.

#### How It Works

1. The provider's `registration_endpoint` is discovered via `.well-known/openid-configuration`
2. The registration request carries `redirect_uri`, `scopes`, the client metadata fields and `initial_access_token`
3. Provider returns `client_id` and `client_secret`
4. The registration is stored in the apigw database and reused on restart
5. Before `client_secret_expires_at`, the next flow registers a new client. Flows in progress finish on the client they started with.

#### Configuration Example

```yaml
apigw:
  auth_providers:
    oidc:
      enable: true
      issuer_url: "https://keycloak.example.com/realms/master"
      redirect_uri: "https://issuer.example.com/oidcrp/callback"
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

      registration:
        dynamic:
          enable: true
          # Keycloak: Realm Settings → Client Registration → Initial Access Tokens
          initial_access_token: "eyJhbGciOiJIUzI1NiIsInR5cCI..."
```

`initial_access_token` is required with `dynamic`. It can move to the secrets file, under the same path.

### Attribute Mapping

`attribute_mapping` renames OIDC claims before the data source uses them. It applies to every OIDC scope.

Each key is an OIDC claim name. Its fields:

- **claim**: Target claim path (supports dot-notation)
  - Example: `"given_name"` for flat structure
  - Example: `"place_of_birth.locality"` for nested structure

- **required**: Whether the OIDC claim must be present (boolean)
  - If `true` and the claim is missing, the callback fails

- **default**: Value used when the OIDC claim is missing (string)

- **as_array**: Wraps a string value in a single-element array (boolean)

Without `attribute_mapping`, the claims keep their OIDC names. An `assertion` credential then receives the claims its VCTM or MDDL declares.

With `attribute_mapping`, the claim set holds only the mapped claims, and an `assertion` credential receives all of them. Map every claim the scopes need, including claims whose name stays the same.

Value transformations, such as case folding or date formats, are `derivations` on the scope. See [Derivation Primitives](./CONFIGURATION.md#derivation-primitives).

#### Example

```yaml
apigw:
  auth_providers:
    oidc:
      enable: true
      issuer_url: "https://idp.example.com"
      redirect_uri: "https://issuer.example.com/oidcrp/callback"
      scopes:
        - "openid"
        - "profile"
        - "email"
      registration:
        preconfigured:
          enable: true
          client_id: "issuer-service"
          client_secret: "client-secret"
      attribute_mapping:
        first_name:
          claim: "given_name"
          required: true
        last_name:
          claim: "family_name"
          required: true
        date_of_birth:
          claim: "birthdate"
          required: true
        birth_city:
          claim: "place_of_birth.locality"
        email:
          claim: "email"
        country:
          claim: "nationalities"
          as_array: true
          default: "SE"
```

This would transform OIDC claims like:
```json
{
  "sub": "248289761001",
  "first_name": "Jane",
  "last_name": "Doe",
  "date_of_birth": "1990-01-01",
  "birth_city": "Uppsala"
}
```

Into the claim set:
```json
{
  "given_name": "Jane",
  "family_name": "Doe",
  "birthdate": "1990-01-01",
  "place_of_birth": {
    "locality": "Uppsala"
  },
  "nationalities": ["SE"]
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
  "credential_offer": {
    "credential_issuer": "https://issuer.example.com",
    "credential_configuration_ids": ["pid"],
    "grants": {
      "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
        "pre-authorized_code": "Wn3x4Qe0k5LrS8vT1yZbJ2cH6dF9gA7m"
      }
    }
  },
  "message": "OIDC authentication successful, credential offer created"
}
```

In the OpenID4VCI authorization flow, the callback redirects the browser to the consent page.

## Security Considerations

### PKCE (Proof Key for Code Exchange)

OIDC RP implementation mandates PKCE using the S256 method:
- Protects against authorization code interception attacks
- Required for public clients and recommended for all clients
- `code_verifier`: 32 random bytes, base64url-encoded (43 characters)
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

- Stored in memory, or in MongoDB when `common.ha.enable` is set
- Expire after `session_duration` (default: 300 seconds)
- Sessions deleted after the callback

## Troubleshooting

### OIDC RP not available

**Error**: `OIDC RP is not enabled`

**Solution**: Set `apigw.auth_providers.oidc.enable: true`

### Provider discovery fails

**Error**: `failed to discover OIDC provider at <issuer_url>`

**Causes**:
- Invalid `issuer_url`
- Network connectivity issues
- Provider doesn't support OpenID Connect Discovery

**Solution**: Verify issuer URL and ensure `.well-known/openid-configuration` is accessible

### Token exchange fails

**Error**: `failed to exchange authorization code`

**Causes**:
- Invalid `client_id` or `client_secret`
- Incorrect `redirect_uri` (must match registered URI exactly)
- PKCE verification failure
- Expired authorization code

**Solution**: Verify OAuth2 client configuration with provider

### Missing required claims

**Error**: `missing required attribute: email (claim: email)`

**Solution**:
- Ensure requested scopes include necessary claims
- Check provider's claim mapping
- Remove `required: true` from the `attribute_mapping` entry if the claim is optional

### Claim path conflicts

**Error**: `failed to set claim identity.given_name: path conflict: identity is not a map`

**Cause**: One `attribute_mapping` entry uses a path as a value, and another uses it as an object

**Solution**: Review the `claim` paths in `attribute_mapping`

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

## Testing

### Manual Testing with Google

1. Create OAuth2 credentials at https://console.cloud.google.com/apis/credentials
2. Configure authorized redirect URI: `https://your-issuer.com/oidcrp/callback`
3. Update `config.yaml` with client ID and secret
4. Call initiate endpoint
5. Follow authorization URL in browser
6. Authenticate with Google account
7. Observe callback with credential offer

### Integration Tests

Integration tests with mock OIDC provider are located in:
```
internal/apigw/integration/oidc_integration_test.go
```

Run tests with:
```bash
go test -tags=integration ./internal/apigw/integration/
```

## Future Enhancements

- [ ] Support for additional OIDC features (e.g., refresh tokens)
- [ ] Multi-provider support (multiple OIDC providers simultaneously)
- [ ] Advanced claim transformation (JSONPath, custom functions)
- [ ] Logout flow implementation
- [ ] Support for OpenID Connect Federation

## Related Documentation

- [Configuration Reference](./CONFIGURATION.md) - `apigw.auth_providers` and `apigw.data_sources`
- [OpenID4VCI](../standards/api_specification.md) - Credential issuance protocol
- [Configuration Guide](../README.md#configuration) - General configuration
