---
vct: urn:credential:eduid_age_verification:1
background_color: "#ffffff"
text_color: "#222222"
---

# EduID Age Verification Credential

An age-attestation credential derived from an eduID SD-JWT credential
presented via OpenID4VP during OpenID4VCI. Issued from
`data_sources.presentation.eduid_age_verification`.

## Status

Wired end-to-end: the wallet presents an eduID, the issuer verifies the
presentation, checks `assurance_level` against the configured URI
allow-list, derives `age_over_*` booleans from `birthdate`, filters the
document against this credential's VCTM, and mints the credential. The
handler test lives with the `internal/apigw/apiv1` package; end-to-end
verification with a real wallet remains pending.

## Claims

- `age_over_13` (boolean, mandatory): Indicates if the person is 13 years old or older. [sd=always]
- `age_over_15` (boolean, mandatory): Indicates if the person is 15 years old or older. [sd=always]
- `age_over_18` (boolean, mandatory): Indicates if the person is 18 years old or older. [sd=always]
- `age_over_21` (boolean, mandatory): Indicates if the person is 21 years old or older. [sd=always]
- `age_over_65` (boolean, mandatory): Indicates if the person is 65 years old or older. [sd=always]
- `date_of_issuance` (date, mandatory): Start date of this credential's validity. [sd=always]
- `date_of_expiry` (date, mandatory): End date of this credential's validity. [sd=never]

## Issuance

Issued through an **OpenID4VP-during-OpenID4VCI** flow. When the wallet
requests scope `eduid_age_verification`, the issuer responds with a
presentation request for the wallet's eduID credential. The wallet returns
the presentation, the issuer verifies the signature and trust chain, checks
that the presented eduID's `assurance_level` URI is in the scope's
configured allow-list (e.g. `http://www.swamid.se/policy/assurance/al2` or
`.../al3`), derives the age booleans from the presented `birthdate`,
filters the resulting document against `metadata/vctm_eduid_age_verification.json`,
and mints the credential.

## Formats

- `dc+sd-jwt` — SD-JWT VC (SD-JWT variant of Phase 2).
- `zk+vega` — zero-knowledge variant using the Vega circuit. Reserved for
  the follow-up in [`docs/EDUID_AGE_ZK_VEGA_PLAN.md`](../docs/EDUID_AGE_ZK_VEGA_PLAN.md).
