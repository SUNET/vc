# Security Hardening Plan

Status: proposed
Date: 2026-06-12

This plan is the outcome of a three-track security audit of the codebase
(crypto/token handling, HTTP/API attack surface, data/secrets/supply chain),
extended with a compliance audit track covering protocol/spec conformance
(OpenID4VCI, OpenID4VP, SD-JWT VC, mdoc, Token Status List) and
regulatory/operational compliance (GDPR, eIDAS/ARF, supply chain).
The codebase has a sound security foundation — algorithm allowlists with
`none` rejection, `crypto/rand` for all tokens/nonces, parameterized MongoDB
queries, CSRF protection, `HttpOnly`/`Secure` cookies — but the audit
identified four critical gaps and a series of hardening items, fixed here in
priority order. Phases 4 and 5 record the compliance gaps.

## Phase 1 — Critical: data exposure & authentication gaps ✅ DONE

### 1. Stop logging credentials/PII

- `internal/verifier/apiv1/handlers_verification.go:106` —
  `c.log.Debug("directPost", "vpResponse", vpResponse)` logs the entire
  decrypted VP response, including credential tokens with personal attributes.
- `handlers_verification.go:29` logs the full verification request object.
- `handlers_verification.go:53` logs the signed JWT.

Actions:

- Remove or redact these debug statements; log only non-sensitive identifiers
  (state, kid, scope, counts, formats).
- Sweep all services for similar `Debug` calls dumping tokens, documents, or
  identity data; prefer redaction helpers over deleting debug lines to
  preserve troubleshooting value.

### 2. Implement client_assertion signature verification (RFC 7523)

`internal/apigw/apiv1/handlers_oauth.go:187-215` —
`oauth2.ExtractClientIDFromAssertion` only decodes the JWT payload; the
signature is **not** verified. Acceptance is currently gated behind the
`allow_unverified_client_assertion` config flag.

Actions:

- Verify the assertion signature against the registered client's JWKS.
- Validate `aud` (token endpoint), `exp`, `iss == sub`, and `jti` replay
  protection.
- Reuse the patterns in `pkg/trust/jwt_verifier.go` (algorithm allowlist,
  signing-method validation, `none` rejection).
- Keep `allow_unverified_client_assertion` as an explicit conformance-testing
  escape hatch with a loud startup warning; verification becomes the default
  path.

### 3. Kafka authentication/TLS

`pkg/messagebroker/kafka/consumer.go:60` and `producer.go:59` hardcode
`saramaConfig.Net.SASL.Enable = false` (with TODOs).

Actions:

- Replace hardcoded values with config-driven SASL and TLS settings in the
  `pkg/model` config structs.
- Document the new settings (regenerate `docs/CONFIGURATION.md`).

### 4. Enforce SAML metadata signature verification

`internal/apigw/auth_providers/samlsp/mdq.go` (~330-375) and
`service.go` (~86-97) — metadata signatures are only verified when
`metadata_signing_cert_path` is configured; MDQ/URL metadata is otherwise
accepted unsigned (MITM → fake IdP endpoints/certs).

Actions:

- Fail startup when MDQ or URL metadata sources are used without
  `metadata_signing_cert_path`, unless an explicit
  `allow_unsigned_metadata` opt-out is set.
- Local metadata files: allow unsigned but log a warning.

## Phase 2 — High: hardening ✅ DONE

These steps are independent and can be done in parallel.

1. **Logger directory permissions** — `pkg/logger/logger.go:37` uses
   `os.MkdirAll(logPath, fs.ModeDir)`, which has zero permission bits.
   Use `0o700`.
2. **Secrets file permissions** — `LoadSecrets` in
   `pkg/configuration/config.go:77` should stat the secrets file and
   warn/fail if it is group- or world-readable (expected `0600`).
3. **Request size limits** — add request body size limit middleware and
   `MaxHeaderBytes` to the shared HTTP server setup in `pkg/httphelpers`.
4. **APIGW rate limiting** — port the verifier's
   `internal/verifier/middleware/rate_limit.go` to APIGW token, credential,
   and datastore endpoints (per-IP and per-client).
5. **Security headers** — add middleware in `pkg/httphelpers` setting
   `X-Content-Type-Options: nosniff`, `X-Frame-Options`, HSTS (when TLS is
   enabled), and a CSP for the admin UI.
6. **Container user** — add a non-root `USER` directive to the dockerfiles.
7. **gRPC TLS hardening** — `pkg/grpchelpers/{server,client}.go`: prefer
   TLS 1.3, restrict TLS 1.2 cipher suites to a secure set.

## Phase 3 — Medium: defense in depth

1. **CORS tightening** — `internal/apigw/httpserver/service.go`:
   `AllowOriginWithContextFunc` currently returns `true` for *any* origin on
   `/samlsp/` and `/oidcrp/` paths while `AllowCredentials: true`. Scope it
   to configured IdP origins.
2. **Session cookies** — switch APIGW sessions from `SameSite=Lax` to
   `SameSite=Strict` (registry already uses Strict).
3. **Pagination** — add limits/pagination to datastore `List()` in
   `internal/apigw/db/methods_datastore.go` (currently unbounded).
4. **Fail-closed mTLS** — `pkg/grpchelpers/server.go`: error at startup if a
   client CA is configured but the fingerprint/DN allowlist is empty.
5. **JWKS URL scheme** — reject `http://` JWKS URLs at runtime (docs already
   say MUST be https).
6. **Dev environment** — enable MongoDB authentication in
   `docker-compose.yaml`; bump dev PKI script (`create_pki.sh`) to RSA 4096.

## Phase 4 — Compliance gaps: protocol conformance

Findings from the compliance audit of the OpenID4VCI/VP, SD-JWT VC, mdoc,
and Token Status List implementations against their specifications.

### 1. Revocation status not enforced at verification time (critical)

Status list *issuance* is functional (`pkg/tokenstatuslist`, JWT and CWT),
but no verification path actually checks revocation:

- `pkg/openid4vp/validator.go:207-213` — `checkRevocation()` is a
  placeholder that returns `nil`; the `CheckRevocation` flag exists but is
  a no-op.
- `pkg/mdoc/status.go:116` — `// TODO(masv): wire into the verifier so
  status checking is actually performed at presentation time.`
- `pkg/mdoc/issuer.go:510` — `return fmt.Errorf("revocation not
  implemented - integrate with token status list")`.

Revoked credentials are currently accepted as valid.

Actions:

- Implement status list resolution in the verifier: fetch the referenced
  status list token, verify its signature, and check the credential's bit
  index (with caching + TTL, reusing the JWKS cache patterns).
- Wire the same check into the mdoc verification path.
- Make revocation checking the default; keep an explicit opt-out for
  conformance testing.

### 2. Wallet attestation signature not verified

`pkg/openid4vci/proof_attestation.go:193` — `// TODO: Implement signature
verification against trusted attestation issuers`. Attestation claims
(device security level etc.) are decoded but never cryptographically
verified, so a fake wallet can claim arbitrary capabilities.

Actions:

- Verify the attestation JWT signature against a configured set of trusted
  attestation issuers (reuse `pkg/trust/jwt_verifier.go` patterns).
- Validate `exp`/`iat` and issuer trust before honoring any claims.

### 3. Data Integrity proof verification not implemented

`pkg/openid4vci/proof_divp.go:149` — `// TODO: Implement actual
cryptographic verification of the Data Integrity Proof`. Only structural
parsing is done; W3C VC 2.0 holders using Data Integrity proofs are
accepted without proof verification.

Actions:

- Implement cryptosuite verification (signature, `verificationMethod`
  resolution) or reject the proof type until implemented — do not accept
  unverified proofs.

### 4. DCQL validation is a placeholder

`pkg/openid4vp/validator.go:216` — `validateAgainstDCQL()` returns `nil`
without checking that the presented credentials actually satisfy the DCQL
query (format, required claims, constraints).

Actions:

- Implement credential-to-query matching: format, `vct`/doctype, requested
  claim presence.

### 5. Interop notes (lower priority, document or implement as needed)

- **`presentation_definition` unsupported** —
  `pkg/openid4vp/request_object.go:43` has the field commented out; the
  verifier is DCQL-only. Wallets that only speak Presentation Exchange
  cannot interoperate. Decision recorded below.
- **Batch credential endpoint** — declared in issuer metadata
  (`pkg/openid4vci/metadata_loader.go:22`) but no endpoint implementation;
  either implement or remove from metadata (metadata must not advertise
  unsupported capabilities).
- **RSA key binding unsupported** — `pkg/sdjwtvc/verification.go:761`
  ("RSA key - not implemented yet"); only ECDSA holder keys work.
- **base58-btc multibase unsupported** — `pkg/trust/helpers.go:207`;
  limits did:key interop.
- **RFC 7523 client_assertion** — covered by Phase 1 item 2.

## Phase 5 — Compliance gaps: regulatory & operational (GDPR/eIDAS/NIS2)

### 1. Audit logging is effectively non-functional (critical)

- The only `AddAuditLog` call site is commented out:
  `internal/issuer/apiv1/handlers.go:89` —
  `//c.auditLog.AddAuditLog(ctx, "create_credential", ...)`.
- `audit_log.enable` defaults to `false` (see `docs/CONFIGURATION.md`).
- Admin UI session creation/destruction and document deletions are not
  audited; no tamper evidence (signing/sequencing) on audit records.

Without an audit trail of who issued/verified/revoked/deleted what and
when, accountability obligations (GDPR Art. 5(2), NIS2 logging) cannot be
met.

Actions:

- Re-enable and extend audit logging to cover credential issuance,
  verification, revocation, document deletion, and admin sessions.
- Audit events must contain actor, action, subject identifier (not the
  credential payload), and timestamp — no PII payloads in audit records.
- Make audit logging mandatory for production configurations (startup
  warning or failure when disabled outside dev mode).

### 2. No data retention / TTL policy (GDPR storage limitation)

No `expireAfterSeconds` (TTL) indexes on MongoDB collections in
`internal/apigw/db` or `internal/verifier/db`; documents and verification
records are stored indefinitely.

Actions:

- Add configurable TTL indexes per collection (documents, sessions,
  verification records) and document the retention defaults.
- Ensure document deletion endpoints emit audit events (ties to item 1).

### 3. Anonymous admin access fallback

`internal/apigw/httpserver/endpoints_admin.go:34-44` — when no OIDC
provider is configured, an admin session is granted without
authentication.

Actions:

- Gate the fallback behind an explicit `dev_mode`/`allow_anonymous_admin`
  flag with a loud startup warning; fail closed otherwise.

### 4. Supply chain

- `.github/workflows/test.yaml` runs tests only; no `gosec`/`govulncheck`
  job in any workflow (ties to Verification item 2).
- No SBOM generation target in the Makefile; release workflows produce
  unsigned binaries.
- No `SECURITY.md`/`security.txt`; no security contact in
  `publiccode.yml`.

Actions:

- Add CI jobs for `gosec` and `govulncheck`; add an SBOM Makefile target
  (e.g. `syft`) wired into the release workflows; sign release artifacts
  (e.g. `cosign`).
- Add `SECURITY.md` with a disclosure process and a security contact in
  `publiccode.yml`.

### 5. Key management

HSM/PKCS#11 support exists but is optional; there is no key rotation
mechanism or per-credential key-version tracking (needed to scope
revocation after a key compromise).

Actions:

- Document a key rotation procedure (overlapping `kid`s in JWKS, grace
  period) and record the signing `kid` with each issued credential.

### 6. eIDAS / ARF (forward-looking, monitor only)

PID/ARF rulebook metadata is present (`metadata/vctm_pid.json`) but not
enforced; wallet attestation enforcement (Phase 4 item 2) is a
prerequisite for ARF alignment; there is no qualified-credential marking.
No action now — track ARF releases and revisit.

## Verification

1. `go test ./...` after each phase; new tests for client_assertion
   verification (valid / forged signature / expired / wrong aud / replayed
   jti) and SAML unsigned-metadata rejection.
2. `gosec ./...` and `govulncheck ./...` clean runs; add Makefile targets
   (and optionally CI jobs).
3. Manual checks against a running stack: security headers present
   (`curl -sD-`), oversized body rejected (413), rate limit triggers (429).
4. Grep audit: no `log.Debug` call logs `vpResponse`, raw JWTs, or document
   payloads.
5. Compliance (Phase 4/5): test that a revoked credential is rejected at
   presentation time (SD-JWT VC and mdoc); audit-log emission tests for
   issue/verify/delete operations; CI runs `gosec` and `govulncheck`; TTL
   indexes exist on the configured collections.

## Decisions

- `allow_unverified_client_assertion` is retained for conformance testing,
  but signature verification is the default path.
- Logging fixes favor redaction helpers over removing debug lines.
- SAML metadata verification is mandatory for MDQ/URL sources; local files
  may remain unsigned with a warning (avoids breaking existing installs).
- Revocation checking (`CheckRevocation`) becomes the default once
  implemented; opt-out retained for conformance testing.
- Audit logging becomes mandatory for production deployments.
- The verifier remains DCQL-only unless a concrete interop requirement for
  `presentation_definition` (Presentation Exchange) emerges; the gap is
  documented rather than implemented.
- Out of scope: HSM integration changes, formal threat model document,
  penetration testing, OpenID Federation, eIDAS qualified-credential status.

## Audit notes — good practices already in place (do not regress)

- JWT algorithm allowlist with unconditional `none` stripping
  (`pkg/trust/jwt_verifier.go`).
- All randomness via `crypto/rand` (`pkg/crypto/nonce.go`).
- MongoDB queries parameterized via `bson.M`; operator injection blocked by
  validator tags at the HTTP binding layer.
- Cookies `HttpOnly`, `Secure` when TLS enabled; CSRF middleware on admin UI.
- `filepath.Clean` applied to file paths; no `InsecureSkipVerify` outside
  test code.
- JWKS caching with TTL, exponential backoff, and stale fallback.
