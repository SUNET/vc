---
vct: urn:credential:eduid_age_verification:1
background_color: "#ffffff"
text_color: "#222222"
---

# EduID Age Verification Credential

A minimal age-attestation credential derived from an eduID SD-JWT credential
presented via OpenID4VP during OpenID4VCI. The issuer verifies the presented
credential, refuses if its assurance level is below the configured minimum
(`AL2` by default), and derives age-threshold booleans from the presented
`birthdate`.

The credential itself carries only the age thresholds and validity dates —
no name, no birthdate, no address, no assurance level, no issuing metadata.
Assurance level is enforced at issuance time and is not echoed onto the
credential.

## Claims

- `age_over_13` (boolean, mandatory): Indicates if the person is 13 years old or older. [sd=always]
- `age_over_15` (boolean, mandatory): Indicates if the person is 15 years old or older. [sd=always]
- `age_over_18` (boolean, mandatory): Indicates if the person is 18 years old or older. [sd=always]
- `age_over_21` (boolean, mandatory): Indicates if the person is 21 years old or older. [sd=always]
- `age_over_65` (boolean, mandatory): Indicates if the person is 65 years old or older. [sd=always]
- `date_of_issuance` (date, mandatory): Start date of this credential's validity. [sd=always]
- `date_of_expiry` (date, mandatory): End date of this credential's validity. [sd=never]

## Issuance

The credential is issued through an **OpenID4VP-during-OpenID4VCI** flow. When
the wallet requests scope `eduid_age_verification`, the issuer responds with a
presentation request for the wallet's eduID credential. The wallet returns the
presentation, the issuer verifies the signature and trust chain, checks
`assurance_level >= min_assurance_level`, and mints this credential from the
presented `birthdate`.

## Assurance Level Enforcement

Assurance level is a configuration concern, not a credential claim. The
`credential_metadata.eduid_age_verification.min_assurance_level` config value
(default: `AL2`) determines the minimum canonical assurance level (`AL1` /
`AL2` / `AL3`) the presented eduID must attest. If the presented credential's
`assurance_level` claim is absent or below the configured minimum, the issuer
returns `HTTP 403 insufficient_assurance` and no credential is issued.

## Formats

- `dc+sd-jwt` — traditional SD-JWT VC (implemented).
- `zk+vega` — zero-knowledge variant using the Vega circuit. Reserved; design
  in [`docs/EDUID_AGE_ZK_VEGA_PLAN.md`](../docs/EDUID_AGE_ZK_VEGA_PLAN.md); no
  issuance path exists yet.
