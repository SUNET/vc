# Security Hardening TODOs

## SSRF Protection for Outbound HTTP Requests

**Priority**: High  
**Scope**: Cross-cutting (all services)

The codebase makes outbound HTTP requests driven by untrusted input (credential claims, metadata URIs, JWKS discovery). Currently only URI scheme validation (`http`/`https`) is enforced. A shared safe HTTP transport should be implemented to block requests to private/loopback/link-local IP ranges after DNS resolution.

**Affected callers**:
- `pkg/revocation/status_list.go` — fetches status list tokens from credential-supplied URIs
- `pkg/trust/jwks_resolver.go` — JWKS discovery from credential `iss` claims
- `pkg/mdoc/status.go` — status list fetching (mdoc path)
- `internal/apigw/data_sources/eduapi/` — external API calls
- OIDC/SAML metadata fetching

**Recommended implementation**:
- Create `pkg/httphelpers/safe_transport.go` with a `NewSafeTransport()` that wraps `http.Transport`
- Use a custom `DialContext` that resolves DNS first, then rejects connections to:
  - `127.0.0.0/8`, `::1` (loopback)
  - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (RFC 1918 private)
  - `169.254.0.0/16`, `fe80::/10` (link-local)
  - `100.64.0.0/10` (carrier-grade NAT)
  - `fd00::/8` (unique local)
- Disable HTTP redirects to prevent redirect-based bypass (`CheckRedirect` returning error)
- Optionally support an allowlist of permitted domains/CIDRs via configuration
- Use this transport for all outbound HTTP clients created in the project

---

## Issuer Allowlist for Status List Token Verification

**Priority**: Medium  
**Scope**: `pkg/revocation/`, verifier configuration

Status list JWT signature verification resolves signing keys using the token's `iss` claim, which can trigger JWKS discovery to attacker-chosen endpoints. The trust layer (PDP/trust policies) provides some protection, but an explicit allowlist would add defense-in-depth.

**Recommended implementation**:
- Add `AllowedIssuers []string` to `RevocationConfig` in `pkg/model/config.go`
- In `parseJWTStatusList` / `parseCWTStatusList`, validate `iss` against the allowlist before calling `keyResolver.ResolveKey()`
- When empty, fall back to current behavior (any issuer accepted, trust layer decides)
- Consider constraining to the credential's own issuer (the status list issuer should match the credential issuer in most deployments)
