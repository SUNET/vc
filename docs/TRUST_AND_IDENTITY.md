# Trust & Identity Configuration

This document covers how the SIROS ID services (APIGW/Issuer and Verifier) identify themselves and authenticate counterparties.

## Verifier Client ID Scheme (PR #515)

The verifier identifies itself to wallets in OID4VP requests via `client_id`. The scheme is configurable:

### X.509 SAN DNS (Default)

No configuration needed — the verifier derives `x509_san_dns:{hostname}` from `public_url`:

```yaml
verifier:
  public_url: "https://verifier.example.com"
  # Result: client_id = "x509_san_dns:verifier.example.com"
```

### DID-Based Identity

```yaml
verifier:
  public_url: "https://verifier.example.com"
  client_id_scheme: "did"
  did: "did:web:verifier.example.com"
```

When enabled:
- `client_id` in OID4VP requests = the configured DID
- `/.well-known/did.json` serves a DID Document derived from `key_config`
- Wallets resolve the DID Document to verify JAR signatures

## OpenID Federation (PR #514)

Both APIGW and Verifier can serve an OpenID Federation entity configuration, enabling discovery through federation trust chains.

### Configuration

```yaml
federation:
  enabled: true
  entity_id: "https://issuer.example.com"  # defaults to public_url
  authority_hints:
    - "https://federation.sunet.se"
  organization_name: "Example University"
  logo_uri: "https://issuer.example.com/logo.png"
  trust_marks:
    - id: "https://tm.example.com/certified"
      jwt: "eyJ..."
  ttl: 86400
```

### Endpoint

```
GET /.well-known/openid-federation
Content-Type: application/entity-statement+jwt
```

Returns a self-signed JWT (entity configuration) containing `iss`, `sub`, `jwks`, `authority_hints`, `metadata`, and `trust_marks`.

When `federation.enabled` is `false` (default), the endpoint returns 404.

## Wallet Attestation (PR #516)

Wallets can authenticate to the issuer (APIGW) using a provider-signed attestation JWT, eliminating the need for static client registration.

### Configuration

```yaml
apigw:
  trust:
    pdp_url: "https://trust.siros.se/pdp"   # Required
    wallet_attestation:
      enabled: true                          # Enable attestation
      policy:                                # Optional SPOCP tier gating
        rules:
          - "(wallet (attestation_source ios_app_attest)(scope pid)(issuer *))"
  delivery:
    openid4vci:
      clients:                               # Static map still works as fallback
        legacy-wallet:
          redirect_uri: "..."
          scopes: [openid, pid]
```

### How It Works

1. Wallet sends `OAuth-Client-Attestation` (WIA JWT) and `OAuth-Client-Attestation-PoP` (PoP JWT) as HTTP headers in the PAR request per [draft-ietf-oauth-attestation-based-client-auth-04 §3.1](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-04.html#section-3.1)
2. APIGW looks up `client_id` in static client map → not found
3. APIGW validates the PoP JWT signature against the WIA's `cnf.jwk` and checks `aud` matches this AS
4. APIGW sends the WIA to go-trust PDP with `role=wallet-provider`
5. PDP validates wallet provider's signature against trust lists/federation
6. If trusted: wallet accepted as public client (PKCE mandatory)

> **Legacy fallback:** Form-body `client_assertion` (without PoP) is accepted for backward compatibility but is deprecated. New integrations MUST use the HTTP header mechanism.

### Security

- **PKCE** binds the authorization code to the wallet (code_verifier)
- **DPoP** sender-constrains the access token
- **PAR** locks the redirect_uri at authorization time
- **No redirect URI allowlist needed** — PKCE is the primary binding

### Requirements

- `trust.pdp_url` must be configured (PDP performs the trust decision)
- Wallet provider must be discoverable by the PDP (via OIDF, trust lists, or JWKS registry)
- Attestation JWT must contain `iss` (provider) and `sub` (wallet instance = `client_id`)
