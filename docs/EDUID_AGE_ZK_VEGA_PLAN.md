# EduID Age Verification — ZK (Vega) Variant Design

Status: **Design / reserved constants only.** No issuance path is wired.
The traditional SD-JWT variant of `urn:credential:eduid_age_verification:1`
is implemented; this document sketches the second (zero-knowledge) format
of the same credential type.

## Goal

Issue an eduid-derived age credential where the verifier learns *only* which
age thresholds hold (`age_over_13/15/18/21/65`) — with no linkage back to the
source eduid credential, no birthdate, no assurance level (that gate is
applied at issuance time only), and no correlatable holder identifier.

The verifier side already accepts Vega proofs for `mso_mdoc_zk` presentations
(see [pkg/mdoc/zk_verifier.go](../pkg/mdoc/zk_verifier.go),
[pkg/mdoc/zknative_vega/verifier.go](../pkg/mdoc/zknative_vega/verifier.go),
and [ZK_VEGA_DIGESTID_WIRE_EXTENSION.md](ZK_VEGA_DIGESTID_WIRE_EXTENSION.md)).
This document is about the *issuance* side.

## Identifiers

- Credential type: `urn:credential:eduid_age_verification:1` — same URN for
  both the SD-JWT and ZK variants; the format string disambiguates.
- Format `dc+sd-jwt` — the traditional SD-JWT VC path, implemented today.
- Format `zk+vega` (proposed) — reserved for this design; no code path uses
  it yet.

## Envelope choice

Two options, both viable:

| Option                       | Pros                                                                                                      | Cons                                                                    |
|------------------------------|-----------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------|
| Reuse `mso_mdoc_zk`          | Verifier already supports it; wallets that speak `mso_mdoc_zk` will interop; existing DCQL machinery.     | Requires an mdoc doctype for the age credential, plus MDDL definition.  |
| New `zk+vega` SD-JWT envelope| Fits the SD-JWT VC ecosystem; no doctype needed; VCTM already exists.                                     | New wire format; no verifier support yet; wallets must learn about it. |

**Recommendation:** start with `mso_mdoc_zk` for the interop win, and add a
`vctm_eduid_age_verification.mdoc.json` MDDL schema alongside the SD-JWT
`vctm_eduid_age_verification.json`. Fall back to `zk+vega` only if the mdoc
route turns out to be too constrained (e.g. representing the five boolean +
date claims cleanly).

## Vega claim-slot mapping

Vega's r12 circuit exposes `MAX_CLAIMS_V1` fixed disclosure slots (see
[ZK_VEGA_DIGESTID_WIRE_EXTENSION.md](ZK_VEGA_DIGESTID_WIRE_EXTENSION.md)).
Map the age credential's exposable claims to those slots as follows:

| Slot | Element identifier          | Value type | Notes                                         |
|------|-----------------------------|------------|-----------------------------------------------|
| 0    | `age_over_13`               | boolean    |                                               |
| 1    | `age_over_15`               | boolean    |                                               |
| 2    | `age_over_18`               | boolean    |                                               |
| 3    | `age_over_21`               | boolean    |                                               |
| 4    | `age_over_65`               | boolean    |                                               |
| 5    | `date_of_issuance`          | string     | ISO YYYY-MM-DD.                               |

Remaining slots stay `None`. The credential's `date_of_expiry` is a header
field (validity window), not a claim slot, matching the existing Vega
verifier's `checkVegaValidityWindow` treatment.

Assurance level is enforced at issuance time only and is not carried on the
credential in any format.

## Issuance workflow (sketch)

Reuses the same OpenID4VP-during-OpenID4VCI trigger as the SD-JWT variant:

1. Wallet requests scope `eduid_age_verification` with format `zk+vega`.
2. Apigw responds with a presentation request for the wallet's eduid SD-JWT.
3. Wallet returns the presentation. Apigw verifies it, enforces the
   configured `min_assurance_level` against the presented eduid's
   `assurance_level` claim, and derives the five age booleans.
4. Wallet then supplies a Vega **issuance commitment** (blinding factors +
   claim commitments) in the follow-up VCI credential request. The wallet
   binds this to its own holder key so the resulting credential is
   unlinkable to the source eduid.
5. Apigw forwards the derived-claim vector plus the commitment to the issuer
   over a new gRPC method (proposed `MakeZKVega`), analogous to
   `MakeSDJWT`/`MakeMDoc`.
6. The issuer runs the Vega prover with the same key material used elsewhere
   in the deployment, produces the ZK credential envelope, and returns it.
7. Apigw hands the envelope back to the wallet as the VCI credential
   response.

## Trust and key material

The Vega prover requires a Vega **prover key** matching a `zkSystemId` the
verifier catalog will accept — see the existing verifier catalog config
`zk_circuits` in [docs/CONFIGURATION.md](CONFIGURATION.md) and the resolver
in [pkg/mdoc/zk_verifier.go](../pkg/mdoc/zk_verifier.go). The issuer side
needs to load a matching prover key at startup; propose a new
`issuer.zk_vega` config block with `prover_key_path` and `system_id`.

## Phase 2 issuance requirements (SD-JWT variant, prerequisites for ZK)

Before either variant of `urn:credential:eduid_age_verification:1` can be
issued, the SD-JWT path must land the following pieces. This section is a
checklist so nothing is silently deferred.

1. **Data-source / auth-provider wiring.** `auth_providers.Select` resolves
   scopes through `data_sources`. The scope currently has only a
   `common.credential_metadata` entry — the data-source entry (recommended:
   `data_sources.assertion` with a new `openid4vp` auth provider variant)
   plus the corresponding wallet allowlist under
   `apigw.delivery.openid4vci.clients.<wallet>.scopes` are required.
2. **`age_over_*` derivation from `birthdate`.** Bring back the previously
   drafted helper (`deriveAgeThresholds(birthdate string, now time.Time,
   thresholds []int) (map[string]bool, error)`) beside its `VCICredential`
   caller. Thresholds: `[13, 15, 18, 21, 65]`; keys `age_over_NN`.
3. **Claim filtering against the credential's VCTM.** The existing SAML
   VCI path stores the full transformed assertion map and does not apply
   `filterClaimsByCredentialType`; `sdjwtvc.ValidateDocument` only checks
   mandatory claims, it does not reject extras. Once the presentation path
   forwards a document, it must be filtered against
   `metadata/vctm_eduid_age_verification.json`'s claim set so `given_name`,
   `birthdate`, address, etc. never reach the issued age credential.
4. **Allowed `assurance_level` URIs per-scope.** Add a
   `required_claims map[string][]string` field on the new
   `PresentationScope` under `data_sources.presentation`. Each key must be
   present on the verified presentation; a populated list is an allow-list
   compared verbatim (empty list = presence-only). For
   `eduid_age_verification`, set
   `assurance_level: [http://www.swamid.se/policy/assurance/al2, .../al3]`
   in `fly/{dev,demo}/config.yaml`. `VCICredential` returns
   `HTTP 403 forbidden_claim_value` on mismatch.
5. **`presentation_requests/eduid_age_verification.yaml`.** The eduID
   claims the age issuer requests from the wallet: `birthdate`,
   `assurance_level`, plus any binding claims.
6. **`PresentationDuringIssuanceSession`.** Populate the
   currently-empty response field in `handlers_verifier.go`
   `VerificationDirectPost` with `authCtx.SessionID` so the wallet can
   resume issuance.

## Open questions

1. **Revocation.** A ZK credential can carry a status list reference, but
   the wallet must be able to prove non-revocation without leaking the
   entry index. Investigate `mso_mdoc_zk`'s treatment. Fall back: rely on
   short validity (default 1 year → shorten to weeks) rather than a live
   revocation channel.
2. **Holder binding.** The presented eduid is bound to holder key K_eduid.
   The new age credential should be bound to a fresh holder key K_age so
   presentations are unlinkable to the eduid. Wallet SDK must generate
   K_age and prove ownership without disclosing K_eduid.
3. **Wallet SDK availability.** Vega prover support in wallets is not
   universal today. Recommend piloting with the SUNET wallet before
   promising interop.
4. **Circuit revision pinning.** The r12 revision is current at time of
   writing (see [ZK_VEGA_DIGESTID_WIRE_EXTENSION.md](ZK_VEGA_DIGESTID_WIRE_EXTENSION.md));
   pin both prover and verifier to the same revision at deploy time.
5. **Batch issuance.** OID4VCI Appendix F.4 batch issuance would want one
   ZK credential per wallet key. Vega proof generation is expensive;
   consider capping batch size below the SD-JWT default.

## Out of scope for this document

- Wallet-side implementation.
- Vega circuit changes.
- Verifier-side changes (the verifier already accepts `mso_mdoc_zk`
  presentations).
- Actual apigw / issuer code.

## References

- [ZK_PPID_VERIFICATION_PLAN.md](ZK_PPID_VERIFICATION_PLAN.md) — verifier-side
  ZK/PPID plan for Longfellow.
- [ZK_VEGA_DIGESTID_WIRE_EXTENSION.md](ZK_VEGA_DIGESTID_WIRE_EXTENSION.md) —
  Vega wire-format extension (r12 revision).
- [pkg/mdoc/zk_verifier.go](../pkg/mdoc/zk_verifier.go) — verifier-side
  `mso_mdoc_zk` plumbing.
- [pkg/mdoc/zknative_vega/verifier.go](../pkg/mdoc/zknative_vega/verifier.go)
  — Vega cgo binding.
- [cmd/zkvegaverifyworker/main.go](../cmd/zkvegaverifyworker/main.go) — the
  isolated Vega verifier subprocess.
