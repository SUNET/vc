# PR #790 merge review remarks

Reviewed on 2026-10-15: https://github.com/SUNET/vc/pull/790

Reviewed head: `7de2afc453b9f4d05e2c95be3f5778d47f689efd`.

## Recommendation

Merge this targeted security improvement. No new merge-blocking defect was
identified in the source review. At review time, all eight CI checks passed,
GitHub reported no merge conflicts, and all review threads were resolved.

The fix verifies the holder signature, presentation hash, token type and
timestamp. Regression tests cover wrong signing keys, symmetric-key rejection,
multiple key and hash algorithms, and the DCQL holder-binding requirement.

## Before deployment: real-wallet smoke test

The stricter validation intentionally rejects credentials without `cnf.jwk`
and proofs without valid `sd_hash` or `iat`. The default freshness policy
accepts proofs up to ten minutes old plus thirty seconds of clock skew, and
no more than thirty seconds into the future.

Confirm that the deployed wallet can complete presentation-based issuance and
the verifier flow with a legitimate holder-bound credential.

## Urgent follow-up: SD-JWT verification on OIDC direct-post

This is a preexisting gap, not introduced or fixed by #790.

[`ProcessDirectPost`](../internal/verifier/apiv1/handler_oidc.go#L839) invokes
the W3C verification gate and then extracts and maps claims. For SD-JWT-only
responses to SD-JWT requests,
[`verifyVC20ForOIDC`](../internal/verifier/apiv1/oidc_vc20_verification.go#L52)
returns without cryptographic verification. This path does not invoke the
strengthened `VPTokenValidator` or issuer-signature verification before storing
claims and proceeding toward authorization-code issuance.

Prioritize verification of SD-JWT issuer signature/trust and holder binding,
including the session nonce and audience, before accepting claims on this path.
Merging #790 must not be treated as securing every presentation entry point.

## Follow-up: issuer credential validity period

This is also preexisting, not introduced or fixed by #790.

[`JWTTrustVerifier`](../pkg/trust/jwt_verifier.go#L102) disables JWT claims
validation. The reviewed SD-JWT callers in
[`handlers_verification.go`](../internal/verifier/apiv1/handlers_verification.go#L299)
and [`handlers_verifier.go`](../internal/apigw/apiv1/handlers_verifier.go#L293)
do not compensate by checking issuer credential `exp` and `nbf`.

A holder can create a fresh, correctly signed key-binding proof for an expired
credential. The new KB-JWT `iat` checks do not establish that the issuer
credential is currently valid. Enforce the credential validity period separately
and add regression tests for expired and not-yet-valid credentials.

## Review limitations

This was a source and CI review, not a complete security audit. Tests were not
rerun locally, and no real-wallet interoperability test was performed. The PR
diff and tests were inspected at the head above; surrounding integration paths
were inspected on local `main` at
`dd70582b4edf729bab3e911826d281f1f9ff7a01`.