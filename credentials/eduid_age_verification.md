---
vct: urn:credential:eduid_age_verification:1
background_color: "#ffffff"
text_color: "#222222"
---

# EduID Age Verification Credential

A planned age-attestation credential derived from an eduID SD-JWT credential
presented via OpenID4VP during OpenID4VCI.

## Status

**Scaffold only.** The VCTM and the `common.credential_metadata` entry (in
`fly/dev/config.yaml`, `fly/demo/config.yaml`) advertise the credential type,
but the issuance path is not yet implemented. A request for this scope will
not currently produce a credential. The full design and remaining work are
in [`docs/EDUID_AGE_ZK_VEGA_PLAN.md`](../docs/EDUID_AGE_ZK_VEGA_PLAN.md).

Concretely, the following are **not yet in code** and are tracked as
Phase 2 work:

- Wallet scope allowlist entry under `apigw.delivery.openid4vci.clients`.
- Data-source / auth-provider wiring so `auth_providers.Select` can resolve
  the scope.
- Derivation of the `age_over_*` booleans from the presented eduID's
  `birthdate` (helper existed briefly; deleted for now — the derivation
  will land beside its caller in the `VCICredential` path).
- Filtering the presented eduID's claim map against this credential's VCTM
  before issuance, so no PII (name, birthdate, etc.) leaks into the age
  credential body.
- Enforcement of a per-scope `min_assurance_level` (default `AL2`, returning
  `HTTP 403 insufficient_assurance` otherwise). This is not yet a field on
  `model.CredentialMetadata` and no code reads it.

## Claims

- `age_over_13` (boolean, mandatory): Indicates if the person is 13 years old or older. [sd=always]
- `age_over_15` (boolean, mandatory): Indicates if the person is 15 years old or older. [sd=always]
- `age_over_18` (boolean, mandatory): Indicates if the person is 18 years old or older. [sd=always]
- `age_over_21` (boolean, mandatory): Indicates if the person is 21 years old or older. [sd=always]
- `age_over_65` (boolean, mandatory): Indicates if the person is 65 years old or older. [sd=always]
- `date_of_issuance` (date, mandatory): Start date of this credential's validity. [sd=always]
- `date_of_expiry` (date, mandatory): End date of this credential's validity. [sd=never]

## Intended Issuance (Phase 2)

The credential is to be issued through an **OpenID4VP-during-OpenID4VCI**
flow. When the wallet requests scope `eduid_age_verification`, the issuer
responds with a presentation request for the wallet's eduID credential. The
wallet returns the presentation, the issuer verifies the signature and trust
chain, checks that the presented eduID's `assurance_level` claim is at least
the configured minimum, and mints this credential from the presented
`birthdate`.

## Formats

- `dc+sd-jwt` — SD-JWT VC (SD-JWT variant of Phase 2).
- `zk+vega` — zero-knowledge variant using the Vega circuit. Reserved for
  the follow-up in [`docs/EDUID_AGE_ZK_VEGA_PLAN.md`](../docs/EDUID_AGE_ZK_VEGA_PLAN.md).
