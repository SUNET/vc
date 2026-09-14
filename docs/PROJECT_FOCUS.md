# Near-Term Project Focus

**Date**: 2026-08-28
**Scope**: Strategic direction for `SUNET/vc` — Issuer, Verifier, Registry, APIGW.

This document proposes what to prioritize next, how to make the work externally
visible ("show our work"), and the concrete use cases the platform is
positioned to serve.

It is written against the current repo state as reflected in
[ROADMAP.md](../ROADMAP.md), [todo.md](../todo.md),
[HAIP_CONFORMANCE_TODO.md](../HAIP_CONFORMANCE_TODO.md),
[docs/ARF_3_0_GAP_ANALYSIS.md](ARF_3_0_GAP_ANALYSIS.md),
[docs/SECURITY_HARDENING_TODO.md](SECURITY_HARDENING_TODO.md), and
[pain_points.md](../pain_points.md).

## Where the project stands

Feature breadth is already high:

- OpenID4VCI 1.0 and OpenID4VP 1.0 (final, 9 July 2025) — see
  [pkg/openid4vp/readme.md](../pkg/openid4vp/readme.md)
- SD-JWT VC, ISO/IEC 18013-5 mdoc, and W3C VC 2.0 with ECDSA-SD-2023
  (Priority 12, Phase 2 complete)
- W3C Digital Credentials API in the verifier (Priority 10, merged)
- OIDC RP for PID issuance (Priority 11, merged)
- Token Status List (JWT + CWT), WIA / Key Attestation, DPoP, DCQL,
  embedded disclosure policies, refresh-token re-issuance
- PKCS#11 / HSM support, gRPC mTLS, Kafka, MongoDB, OpenTelemetry

The bottleneck is no longer "which spec next". It is **provable
interoperability and production-readiness**.

## Recommended focus

Ordered by return-on-effort for the next release cycle.

### 1. Close HAIP conformance on `vc-interop-3.sunet.se`

Everything in [HAIP_CONFORMANCE_TODO.md](../HAIP_CONFORMANCE_TODO.md) is
small in scope and unlocks a public OpenID Foundation certification badge —
the single most credible external artefact in this space.

- ES256 credential-signing key with `x5c` chain (SUNET Infrastructure CA)
- `attest_jwt_client_auth` at PAR and Token endpoints
- Key attestation acceptance at the Credential endpoint
- Redirect URI + IP allowlist for the OIDF conformance suite
- `DPoP-Nonce` on token / nonce / credential endpoints
- Status List Token signed with `x5c` chain
- Signed metadata `x5c` cleanup

### 2. Finish W3C VC 2.0 + ECDSA-SD-2023 through Phase 4

Priority 12 in [ROADMAP.md](../ROADMAP.md). RDFC-1.0 is done. What remains:

- Base and derived proof creation, derived proof verification
- VC-API endpoints (`/credentials/issue`, `/credentials/verify`,
  `/presentations/verify`)
- Registration in [`w3c/vc-test-suite-implementations`](https://github.com/w3c/vc-test-suite-implementations)

This produces a second independent conformance signal.

### 3. HA and state hardening

From [todo.md](../todo.md), the "reduce state in memory" block:

- `ha` as an object in config (`enable` bool, extensible)
- Mongo-backed cache backend when HA is enabled
- `dynamic_secrets`: persist salts and session secrets at first-write
  with a Mongo mutex; generate at startup, one writer wins
- Verified 3-replica behavior per service
- gRPC mTLS re-used for Mongo where possible

This is what turns "reference implementation" into "deployable service".

### 4. Security hardening

From [docs/SECURITY_HARDENING_TODO.md](SECURITY_HARDENING_TODO.md):

- `pkg/httphelpers/safe_transport.go` — SSRF-safe outbound `http.Transport`
  used by `pkg/revocation`, `pkg/trust/jwks_resolver`, `pkg/mdoc/status`,
  eduAPI, and OIDC/SAML metadata fetching
- Optional issuer allowlist for Status List Token verification
  (defense-in-depth on top of the trust layer)

Small, self-contained, high signal.

### 5. Age-verification SP/OP and DC-API browser demo

Both are already noted in [todo.md](../todo.md). Together they produce the
two most browser-visible demos we can point at:

- A verifier profile that requests only `age_over_18` from PID or mDL via
  DCQL + selective disclosure
- A public web page using `navigator.credentials.get()` against the
  Verifier's DC-API endpoint, driven by the existing
  `authorize_enhanced.html` and `credential_display.html`

### 6. Trim remaining pain points

In this order:

- Move SAML SP from `internal/apigw/httpserver` into `apigw/apiv1`
- Secret backend abstraction (memory / file / mongo)
- Multiple `auth_providers` (accept several OP/IdP, per-credential-scope
  VCTM handling for differing claim shapes)
- Load testing and performance benchmarks (Priority 6)

### Explicitly deferred

- GNAP
- "Batch issuance" as a separate endpoint — the current `/credential`
  endpoint already handles batch via `proofs[]` per the ARF gap analysis
- Cosmetic refactors flagged as "monstrosity" in [todo.md](../todo.md)

None of these unblock external validation right now.

## Showing our work

Ranked by external credibility.

### Certifications and test suites

- **OpenID Foundation Conformance Suite** — run the OpenID4VCI + HAIP
  profile against `vc-interop-3.sunet.se`, publish the certification page,
  embed the badge in [README.md](../README.md).
- **W3C VC 2.0 Test Suite** — after Priority 12 Phase 4, submit a PR to
  `w3c/vc-test-suite-implementations`; the suite auto-publishes a public
  report.
- **SIROS `wallet-e2e-tests`** — [todo.md](../todo.md) already calls out
  adding vc-issuer and vc-verifier to
  `sirosfoundation/wallet-e2e-tests`. This produces a third-party interop
  matrix maintained by someone other than us.

### Interop events

- DC4EU deliverables and interop calls
- OpenID DCP WG plugfests
- JFF Plugfest
- EUDI Wallet Consortium interop events

Even attending as issuer + verifier and publishing a one-page interop
report per event is worth more than any internal doc.

### Public reference deployment

- A hosted Keycloak wired to the Verifier as OIDC OP so anyone can try
  "login with a wallet".
- A public Issuer that any EUDI / SIROS / Sphereon wallet can hit, with
  QR codes and deep links.
- A "Try it" section in [README.md](../README.md) linking to both plus a
  browser page exercising `navigator.credentials.get()`.

### Publications and talks

- TNC, GÉANT, SUNET-Dagarna, IIW, and DC4EU dissemination
- Short recorded flow videos for SD-JWT VC issuance, mdoc presentation,
  and the DC-API browser flow
- One page each in [docs/](.) per artefact so they are citable

### Publish trust material

- Issuer JWKS and signed metadata
- Sample Status List tokens
- Trust anchor(s) for third-party integrators

Third parties can only integrate with what they can fetch.

## Use cases

Grouped by the credential types the codebase already builds — see
[bootstrapping/](../bootstrapping/) and [metadata/](../metadata/).

### Higher education and research identity (natural fit for SUNET)

- eduID as a portable digital ID
- ELM (European Learning Model), diploma, and micro-credentials as
  issuable and verifiable credentials
- Cross-border student mobility using PID + ELM (Erasmus, Nordic
  university networks)

### EUDI Wallet ecosystem

- PID issuer using the SAML / OIDC IdP authentication path
- EHIC, PDA1, and mDL as attribute attestations issued after the wallet
  presents its PID — the two-path model already implemented in
  [README.md](../README.md)

### Login-with-wallet for existing services

The Verifier as an OIDC OP in front of Keycloak lets any Keycloak-integrated
application (SPs behind SWAMID, GÉANT eduTEAMS, generic SaaS) accept
wallet-based login without application changes.

### Age verification

A dedicated verifier profile using DCQL + selective disclosure of
`age_over_18` from mDL or PID. Concrete, publishable, browser-visible.

### Healthcare and cross-border care

- EHIC issuance and verification at care providers
- PDA1 for occupational health across borders

### Employer and registrar credential checks

Diploma or micro-credential verification via the Digital Credentials API in
a browser — the shortest path from "spec" to "user-visible demo".

### Public-sector service delivery

Any Swedish or EU authority issuing an attribute (student status,
professional licence, tax residency) can plug into the Issuer with a VCTM
schema and a claim mapping — the generic issuance path is already built.

### Trust-anchor / Status List operator

The Registry is separable and can be run as a Token Status List service for
third-party issuers, independent of the rest of the stack.

## Suggested single next step

Close [HAIP_CONFORMANCE_TODO.md](../HAIP_CONFORMANCE_TODO.md) and obtain
OpenID Foundation certification on `vc-interop-3.sunet.se`. It is the
highest-ratio work in the repo today — small, well-scoped, and produces an
artefact that every subsequent activity (talks, deployments, EUDI
conversations, funding proposals) can point at.
