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
4. **APIGW itself verifies the WIA's own JWT signature** (`WalletAttestationEvaluator` → the shared `JWTTrustVerifier`, the same verifier used for issuer/verifier trust) before any PDP call. Key material is resolved from the WIA's `x5c` header (TS03/EUDI format), an embedded `jwk` header, or, for `iss`-based WIAs that carry a `kid` header but no embedded key, by discovering the wallet provider's JWKS from `iss` via a multi-step chain: `.well-known/jwt-vc-issuer` → `.well-known/openid-credential-issuer` → `.well-known/openid-configuration` → `.well-known/oauth-authorization-server` (first one that resolves wins). An `iss`-based WIA with none of `x5c`, `jwk`, or `kid` cannot be resolved and is rejected.
5. Only once the signature is verified does APIGW send the **resolved key material** (never the raw token) to go-trust PDP with `role=wallet-provider`
6. PDP performs a pure trust/registry-membership decision on that key (whitelist, OIDF federation, DID registry, ...) — **the PDP never parses or verifies a JWT signature itself**; that would let an unverified token reach registry code expecting a resolved JWK
7. If trusted: wallet accepted as public client (PKCE mandatory)

> **Legacy fallback:** Form-body `client_assertion` (without PoP) is accepted for backward compatibility but is deprecated. New integrations MUST use the HTTP header mechanism.

### Security

- **PKCE** binds the authorization code to the wallet (code_verifier)
- **DPoP** sender-constrains the access token
- **PAR** locks the redirect_uri at authorization time
- **No redirect URI allowlist needed** — PKCE is the primary binding
- **Signature verification happens in APIGW, not the PDP** — the PDP is a pure trust-decision service over already-resolved key material; it must never be handed a raw, unverified token. (Fixed in PR #556 — an earlier version skipped local verification and forwarded the WIA string directly, which for `iss`-based/no-x5c attestations meant the PDP's registry code received a JWT string where it expected a JWK, and treated it as untyped `crypto.PublicKey` input.)

### Requirements

- `trust.pdp_url` must be configured (the PDP performs only the trust/registry decision, not signature verification)
- The wallet provider's signing key must be resolvable by APIGW's own JWKS discovery chain (above) — for `iss`-based WIAs this means the wallet provider needs a real `iss` value pointing at one of the well-known discovery documents (or a bare `.well-known/jwks.json`, if you add that as an additional fallback — see go-wallet-backend's WIA docs for what it publishes)
- The resolved key/provider identity must additionally be discoverable by the PDP itself (via OIDF, trust lists, or a whitelist registry) — this is a *separate* lookup from the JWKS discovery above
- Attestation JWT must contain `iss` (provider) and `sub` (wallet instance's `client_id` — see the note below on what value this must actually be)

:::note `sub` must equal the OAuth `client_id`, not the credential issuer
Per the draft, the WIA's `sub` claim must be the client_id value the wallet uses in the *same* OAuth transaction — i.e. whatever APIGW resolves as `req.ClientID` for an unregistered client (its `redirect_uri`, OID4VCI §7.1 convention). A wallet that puts a different value there (e.g. the credential issuer's own URL) gets a clear `wallet attestation subject does not match client_id` rejection at PAR — this was a real bug hit while integrating wallet-frontend's WIA support.
:::

## Issuer Access Certificate (PR #617)

Under CIR (EU) 2025/848 a PID or attestation provider is a registered wallet-relying party **in its own right**. The certificate that authenticates an issuer to a wallet is therefore an access certificate (WRPAC, ETSI TS 119 411-8) — the same document, under the same profile, the verifier uses.

### Why the issuer signs metadata with it

Credential Issuer Metadata was signed with the issuer's credential key, whose only claim to authority is that it appears in the issuer's own `/jwks`. That is self-asserted: **a wallet cannot establish from it who the issuer is.** Signing with the access certificate and advertising its chain in the JWT's `x5c` header is what makes the signature mean something.

### Configuration

```yaml
issuer:
  key_config:                          # unchanged — still signs credentials
    private_key_path: /etc/vc/credential.key
  access_certificate:
    validate: true                     # enforce the WRPAC profile at startup
    key_config:                        # signs issuer metadata
      private_key_path: /etc/vc/wrpac.key
      chain_path: /etc/vc/wrpac.pem
```

The profile rules and `allowed_policy_oids` are exactly the verifier's — one implementation, so an issuer and a verifier cannot reach different verdicts on the same certificate.

### The two keys are deliberately separate

The equivalent split was correctly *declined* on the verifier side, because the WRPAC profile requires `contentCommitment` to be present rather than exclusive, so one certificate can serve both roles there. That argument does not carry to the issuer:

- the credential key is published in `/jwks`;
- an mdoc document-signer certificate chains to an IACA under an entirely different profile;
- the two rotate on independent schedules — conflating them means a WRPAC rotation forces a credential-key rotation.

### Upgrading an existing deployment

This is the one breaking change in the certificate work, so it is opt-in and **an existing single-key deployment keeps booting**: with no `access_certificate.key_config`, metadata is signed with the credential key exactly as before and a warning is logged.

Two guards make partial configurations fail loudly rather than quietly:

- `validate: true` **without** a separate key still validates the certificate actually being presented — so opting in is never vacuous.
- A `key_config` that loads a key but **no certificate** is refused at startup. It would otherwise sign metadata with no `x5c` header at all, leaving a wallet no way to verify or chain the signature — the entire purpose of configuring one. With `validate` unset nothing else would have caught it.

### What is not enforced yet

- **`issuer_info`.** The issuer does not yet convey its registration certificate (WRPRC) in metadata, so wallets cannot see what attestation types it is registered to provide.
- **Revocation.** As on the verifier side, nothing fetches the CRL or status list yet.
- **Wallet-side verification.** No wallet checks issuer metadata against an access certificate today, so this is currently carried and unread.
