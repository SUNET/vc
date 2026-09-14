# ARF 3.0 Gap Analysis

**Date**: 2026-07-30  
**ARF version**: [v3.0.0](https://eudi.dev/latest/main/) (released July 2026)  
**Project**: SUNET/vc  
**Scope**: This project implements Credential Issuer, Verifier (Relying Party), and Registry roles — it is **not** a Wallet.

## Overview

This document compares the requirements and capabilities described in the EUDI Architecture and Reference Framework (ARF) 3.0 against the current implementation state of this project, focusing on Issuer, Verifier, and Registry responsibilities.

## Already Well-Covered

| ARF 3.0 Requirement | Project Status | Location |
|---|---|---|
| SD-JWT VC format + HAIP profile | ✅ Full | `pkg/sdjwtvc` |
| ISO/IEC 18013-5 mdoc format | ✅ Full | `pkg/mdoc` |
| W3C VCDM 2.0 (Data Integrity) | ✅ In progress | `pkg/vc20` |
| OpenID4VCI 1.0 issuance | ✅ Full | `pkg/openid4vci` |
| OpenID4VP 1.0 verification | ✅ Full | `pkg/openid4vp` |
| W3C Digital Credentials API | ✅ Implemented | Verifier service |
| PKI X.509 trust chains | ✅ Full | `pkg/pki` |
| Token Status List (revocation) | ✅ Full | `pkg/tokenstatuslist` |
| Wallet Instance Attestation (WIA) validation | ✅ Full | `pkg/trust/wallet_attestation.go` |
| Key Attestation (KA) validation | ✅ Full | OpenID4VCI Appendix D.1 |
| Registration Certificates (WRPRC) | ✅ Full | ETSI TS 119 475 via go-trust |
| Access Certificates (WRPAC) | ✅ Full | ETSI TS 119 411-8 |
| Trusted Lists / LoTE lookup | ✅ Full | AKI matching, DCQL trusted_authorities |
| Device binding (key binding) verification | ✅ Full | SD-JWT KB-JWT + mDoc device auth |
| Selective disclosure | ✅ All formats | SD-JWT, mDoc, VC 2.0 ECDSA-SD-2023 |
| Relying Party authentication (X.509) | ✅ Full | VP request signing with chain |
| DPoP token binding | ✅ Full | OpenID4VCI |
| DCQL (Digital Credentials Query Language) | ✅ Full | `pkg/openid4vp/dcql.go` |
| Pairwise pseudonyms | ✅ Basic | Verifier service |
| Credential Issuer metadata signing | ✅ Full | `pkg/openid4vci` signed_metadata |

## Gaps — Not Yet Implemented

### High Priority (Core Issuer/Verifier Mechanisms)

#### 1. ~~Batch Issuance Endpoint~~ ✅ Done

**ARF ref**: §6.6.2.9, §6.6.6.2.2  
**Status**: ✅ Already implemented — the `/credential` endpoint handles batch via `proofs` (plural) per OID4VCI ID1.  
**Role**: Issuer  

The credential endpoint accepts multiple proofs, enforces `batch_credential_issuance.batch_size`, issues one credential per JWK, and returns a `credentials[]` array. No separate endpoint needed.

#### 2. ~~Re-issuance Flows (Credential Renewal)~~ ✅ Done

**ARF ref**: §6.6.6.2 (all sub-sections)  
**Status**: ✅ Implemented — `refresh_token` grant type with DPoP-bound, one-time-use rotation.  
**Role**: Issuer  

Implemented:
- `refresh_token` grant type in token endpoint with device-bound (DPoP) sender-constraining
- Atomic token rotation via `RotateRefreshToken` (compare-and-swap) preventing concurrent replay
- OAuth2 metadata advertises `grant_types_supported` including `refresh_token`
- Configurable via `grant_types` and `refresh_token_duration` in `apigw.delivery.openid4vci`
- Wallet calls `/credential` with new access token to obtain fresh credentials (existing flow)

#### 3. ~~Embedded Disclosure Policies (ETSI TS 119 472-3)~~ ✅ Done

**ARF ref**: §6.6.2.8  
**Status**: ✅ Implemented — per-credential `disclosure_policy` in Credential Issuer metadata.  
**Role**: Issuer  

Implemented:
- `EmbeddedDisclosurePolicy` struct with three policy types: `none`, `authorized_relying_parties`, `specific_root_of_trust`
- Published in `credential_configurations_supported` via `disclosure_policy` field
- Always explicitly declarative (defaults to `{"policy_type":"none"}` when not configured)
- Validation: RP list required for `authorized_relying_parties`, SHA-256 hex fingerprints required for `specific_root_of_trust`
- Configurable per-scope via `disclosure_policy:` in YAML under `credential_metadata`

#### 4. ~~ISO/IEC 18013-7 Remote Verification~~ ✅ Covered

**ARF ref**: §5.7.3  
**Status**: ✅ Effectively covered — mdoc remote presentation works via OpenID4VP + DC API.  
**Role**: Verifier  

The Verifier receives mdoc DeviceResponse via OpenID4VP (all formats including `mso_mdoc`), validates issuer signatures, certificate chains (IACA), MSO digests, and extracts claims. The W3C Digital Credentials API (`dc_api.jwt` response mode) provides the browser-native invocation mechanism required by ISO 18013-7 Annex C. The `mdoc://` custom URI scheme (Annex A) is optional per ARF 3.0 §4.4.3.1. Device binding for remote flows is handled at the OpenID4VP protocol level, not the mdoc session transcript level.

#### 5. ~~Transactional Data in Presentation Requests~~ ✅ Implemented

**ARF ref**: §5.7.5  
**Status**: ✅ Implemented  
**Role**: Verifier, Wallet  

The Verifier can include `transaction_data` in OpenID4VP authorization requests. Each entry contains a `type` (an ecosystem-defined, collision-resistant identifier — e.g. `urn:eudi:transaction:payment`, `urn:eudi:transaction:document_signing`) and `credential_ids` referencing DCQL credential queries. The Wallet hashes each base64url-encoded transaction data entry and includes `transaction_data_hashes` and `transaction_data_hashes_alg` claims in the KB-JWT. The Verifier re-computes the hashes and validates them against the KB-JWT, returning `invalid_transaction_data` on mismatch. The mechanism is fully backward-compatible: when no transaction data is present, the flow is unchanged.

### Medium Priority (Ecosystem Features)

#### 6. ~~Combined Presentation Verification~~ ✅ Implemented

**ARF ref**: §6.6.3.10, Discussion Topic K  
**Status**: ✅ Implemented  
**Role**: Verifier  
**Importance**: Privacy-preserving proof that multiple attestations belong to same user

Implemented three complementary binding verification methods per ARF 3.0 Discussion Topic K §3.2:
- **Session-based binding** (low confidence): implicit trust that all credentials in a single VP response belong to the same user
- **Key-based binding** (high confidence): compares RFC 7638 JWK thumbprints of holder keys (`cnf.jwk` for SD-JWT, device key for mDoc) across all presented credentials
- **Attribute-based binding** (medium confidence): configurable shared identifier matching (e.g., `sub`, `given_name`+`family_name`+`birth_date`) across credentials

Enforcement is configurable per ARF 3.0 ACP_08 ("SHOULD NOT refuse solely because proof is absent"):
- `enforce`: reject presentation if binding cannot be established
- `warn`: log warning but allow through
- `disabled`: skip binding verification

Cryptographic binding via WSCA/WSCD proof (ZKP) is out of scope — ARF 3.0 §4.2 explicitly removes ACP_03–09 as immature.

#### 7. Attestation Revocation Verification by Verifier

**ARF ref**: §6.6.3.7  
**Status**: Partial (Token Status List exists, but full verification flow may be incomplete)  
**Role**: Verifier  
**Importance**: Recommended for all attestations valid > 24 hours

The Verifier should check the revocation status of received PIDs/attestations using the Token Status List URL and index included in the attestation.

#### 8. WIA/KA Revocation Monitoring (Issuer-side)

**ARF ref**: §6.6.2.5, §6.5.3.4  
**Status**: Not implemented  
**Role**: Issuer (PID Provider)  
**Importance**: Mandatory for PID Providers per CIR 2024/2977

PID Providers must regularly verify (during entire PID lifetime) whether the Wallet Unit was revoked by checking WIA/KA revocation status. If revoked, the PID Provider must revoke the PID. This requires:
- Storing WIA/KA revocation references at issuance time
- Periodic background checking (go routine) of Wallet Provider status lists
- Auto-revoking PIDs when Wallet Unit revocation is detected

#### 9. Registration Certificate in Credential Issuer Metadata

**ARF ref**: §6.3.2.3, §6.6.2.2  
**Status**: Partial  
**Role**: Issuer  
**Importance**: Mandatory for Wallet Units to verify Provider entitlements

The Issuer must include both its access certificate and registration certificate in the Credential Issuer metadata, so that Wallet Units can verify the Issuer's registered entitlements and attestation types.

#### 10. Intermediary Support (Verifier)

**ARF ref**: §6.6.5  
**Status**: Not implemented  
**Role**: Verifier  
**Importance**: Required for intermediary/proxy RP patterns

When acting as an intermediary for other Relying Parties, the Verifier must:
- Use access certificates containing the `usesIntermediary` association
- Include the intermediated RP's registration certificate in requests
- Delete obtained attributes immediately after forwarding to the intermediated RP

### Lower Priority (Future / Governance)

#### 11. Zero Knowledge Proofs

**ARF ref**: Technical Specifications TS4, TS13, TS14  
**Status**: Not implemented  
**Role**: Issuer + Verifier  
**Importance**: Future requirement, specifications still being defined

TS4 covers general ZKP framework, TS13 covers zkSNARKs, TS14 covers ZKPs from multi-message signatures. All are new Technical Specifications in ARF 3.0.

#### 12. Catalogue of Attestation Schemes

**ARF ref**: §5.6.3, Technical Specification 11  
**Status**: Not implemented  
**Role**: Issuer  
**Importance**: Ecosystem interoperability (Commission-managed registry)

Machine-readable attestation scheme registry enabling discovery of attestation types, their attributes, and encoding rules. Issuers may register their attestation schemes.

#### 13. Data Deletion Endpoint (RP obligation)

**ARF ref**: §6.6.3.13, Technical Specification 7  
**Status**: Not implemented  
**Role**: Verifier/RP  
**Importance**: GDPR Article 17 compliance

As a Relying Party, the Verifier must provide a mechanism for users to request deletion of personal data obtained via credential presentation. The RP's registration certificate must include contact information (web form URL, email, phone) for such requests.

## New Concepts in ARF 3.0

These are newly emphasized or first-specified in version 3.0:

| Concept | ARF Section | Relevance to This Project |
|---|---|---|
| Logical vs Technical attestations | §5.3 | Issuer issues many short-lived technical copies of one logical credential |
| Registration Certificates distinct from Access Certificates | §6.3.2.3, §6.4.2 | Both Issuer and Verifier need separate RCs and ACs |
| WIA/KA revocation maintenance period | §6.5.3.4, §6.5.3.5 | PID Provider must monitor WIA/KA revocation throughout PID lifetime |
| Synchronous re-issuance | §6.6.6.2.4 | Issuer issues fresh credential at presentation time |
| Intermediary handling | §6.6.5 | Verifier may act as intermediary with `usesIntermediary` in RC |
| Credential Issuer metadata signing | §6.6.2.2 | Issuer signs metadata with access certificate |
| Device-signed (self-issued) attributes | §6.6.3.6 | Verifier validates transactional data signed by device |
| Once-only attestations | §7.4.3.5 | Issuer issues single-use technical attestations for unlinkability |
| Embedded disclosure policies | §6.6.2.8 | Issuer publishes policies in Credential Issuer metadata |

## Relevant Technical Specifications (New in 3.0)

| TS | Title | Relevance |
|---|---|---|
| TS2 | Notification & Publication of Provider Info | Issuer/Verifier registration lifecycle |
| TS3 | Wallet Unit Attestations (WUA) | Issuer validates WIA + KA during issuance |
| TS4 | Zero-Knowledge Proof (ZKP) | Future: Issuer + Verifier support |
| TS5 | RP Registration Information (formats & API) | Verifier registration, `usesIntermediary` |
| TS6 | Common Set of RP Information | What to register as Verifier/RP |
| TS7 | Data Deletion Requests | RP must support incoming deletion requests |
| TS11 | Catalogue of Attributes & Attestation Schemes | Issuer registers attestation types |
| TS12 | SCA for Payments | Verifier: transactional data in VP requests |
| TS13 | zkSNARKs | Future ZKP mechanism |
| TS14 | ZKPs from Multi-Message Signatures | Future ZKP mechanism |

## Recommendations

### Short-term (next release cycle)
1. **Batch issuance endpoint** — metadata is ready, implement the HTTP handler
2. **Re-issuance via refresh tokens** — implement device-bound refresh token flow in OpenID4VCI
3. **Embedded disclosure policies for SD-JWT** — extend policy engine beyond mDoc

### Medium-term
4. **ISO 18013-7 remote verification** — add alongside OpenID4VP for mdoc
5. **Transactional data in VP requests** — extend VP request/response with signed device data
6. **WIA/KA revocation monitoring** — background checker for PID Provider obligation
7. **Intermediary support** — implement `usesIntermediary` access certificate handling
8. **Data deletion endpoint** — RP obligation per TS7

### Long-term / Monitor
9. **ZKP support** — await stable TS4/TS13/TS14 specifications
10. **Cryptographic binding verification** — await standardized WSCA/WSCD combined presentation mechanism (ZKP-based)
11. **Catalogue integration** — await Commission's TS11 deployment

---

*Based on: [EUDI Architecture and Reference Framework v3.0.0](https://eudi.dev/latest/main/)*
