# ADR-17: Verifier Signature and Trust Validation Architecture

## Status

**Implemented** (March 2026)

## Context

The verifier's `VerificationDirectPost` endpoint receives VP tokens from wallets containing credentials in multiple formats (SD-JWT and mDOC). Each credential must undergo two distinct validation steps before it can be accepted:

1. **Signature verification** — Cryptographic proof that the credential was issued by the entity controlling the signing key.
2. **Trust evaluation** — Policy-based decision that the signing entity is an authorized issuer for the given credential type.

These two concerns are logically separate but tightly coupled: the key used for signature verification is the same key whose trustworthiness is evaluated. Prior to this work, signature verification and trust evaluation were handled through different code paths and interfaces depending on the credential format, making the verification flow difficult to reason about.

Additionally, for SD-JWT credentials, the JWT header carries the key material needed for verification (in the `x5c`, `jwk`, or `kid` header fields). The standard library function `ParseUnverified` was previously used to extract this key material before verification, but this creates a two-step flow where the JWT is parsed twice: once to extract the key, and once to verify the signature. This is both unnecessary and problematic for static analysis tools.

## Decision

### Single-pass JWT signature verification

For SD-JWT credentials, signature verification is performed in a single `jwt.Parse` call. The library's keyfunc callback receives the fully parsed (but not yet verified) token, including headers and claims. This allows key extraction and signature verification to happen in one atomic operation:

```
jwt.Parse(issuerJWT, func(token *jwt.Token) (any, error) {
    // 1. Enforce algorithm allowlist
    // 2. Extract key material from header (x5c, jwk, or resolve DID)
    // 3. Validate signing method matches key type
    // 4. Return public key → library verifies signature
})
```

This is implemented in `evaluateIssuerTrust()` in `internal/verifier/apiv1/handlers_verification.go`.

### Unified TrustEvaluator interface

Both credential formats use the same `trust.TrustEvaluator` interface (defined in `pkg/trust/trust.go`) for trust evaluation:

```go
type TrustEvaluator interface {
    Evaluate(ctx context.Context, req *EvaluationRequest) (*TrustDecision, error)
    SupportsKeyType(kt KeyType) bool
}
```

The `EvaluationRequest` carries the issuer identity, key type (`KeyTypeX5C` or `KeyTypeJWK`), key material, role, and credential/document type. The `TrustDecision` response indicates whether the issuer is trusted and through which trust framework.

### Format-specific verification paths

The `VerificationDirectPost` handler detects the credential format via `detectCredentialFormat()` and dispatches to the appropriate path:

#### SD-JWT path

```
VerificationDirectPost
  └─ for each scope:
       ├─ VPTokenValidator.Validate()         # Format validation (nonce, client_id)
       │    (ValidateFormat: false)           # Signature NOT checked here
       │
       └─ evaluateIssuerTrust()               # Signature + trust in one flow
            ├─ jwt.Parse(keyfunc)             # Single-pass signature verification
            │    ├─ buildAllowedAlgorithmSet  #   Enforce algorithm allowlist
            │    ├─ extractJWTClaimsInfo       #   Extract iss, vct from claims
            │    ├─ extractJWTKeyMaterial      #   Extract key from header:
            │    │    ├─ x5c → cert chain     #     Parse x5c certificate chain
            │    │    ├─ jwk → public key      #     Parse embedded JWK
            │    │    └─ did: → resolve key    #     Resolve via KeyResolver
            │    └─ validateSigningMethodForKey #   Match method to key type
            │                                  #   → library verifies signature
            │
            └─ trustEvaluator.Evaluate()      # AuthZEN PDP trust decision
                 SubjectID:      issuerID
                 KeyType:        x5c | jwk
                 Key:            certChain | publicKey
                 Role:           credential-issuer
                 CredentialType: vct claim value
```

Key material extraction supports three sources, tried in order:

1. **x5c header** — The leaf certificate's public key is used for verification; the full chain is sent to the trust evaluator. If the `iss` claim is empty, the leaf certificate's CN is used as issuer ID.
2. **jwk header** — The embedded JWK is parsed to a public key. The JWK map is sent to the trust evaluator.
3. **DID issuer** — If the `iss` claim starts with `did:`, the key is resolved via `trust.KeyResolver.ResolveKey()`. The resolved key is used for both signature verification and trust evaluation.

#### mDOC path

```
VerificationDirectPost
  └─ for each scope:
       └─ MDocHandler.VerifyAndExtract()      # Combined sig + trust
            ├─ CBOR decode DeviceResponse
            ├─ COSE_Sign1 signature verify    # Signature verification
            └─ trustEvaluator.Evaluate()      # Same TrustEvaluator interface
                 SubjectID:      issuer from DS cert
                 KeyType:        x5c
                 Key:            IACA certificate chain
                 Role:           credential-issuer
                 DocType:        e.g. org.iso.18013.5.1.mDL
```

The `MDocHandler` (in `pkg/openid4vp/mdoc_handler.go`) receives the same `TrustEvaluator` instance via `WithMDocTrustEvaluator()`. It handles COSE signature verification internally and delegates trust evaluation to the shared interface.

### Algorithm security

The SD-JWT path enforces a strict algorithm allowlist via `buildAllowedAlgorithmSet()`:

- **Allowed by default**: ES256, ES384, ES512, RS256, RS384, RS512, PS256, PS384, PS512, EdDSA
- **Configurable**: The list can be overridden via `cfg.Verifier.Trust.AllowedSignatureAlgorithms`
- **Hardened**: The `none` algorithm (all case variants) is unconditionally stripped from the allowlist

The `validateSigningMethodForKey()` function provides a second layer of defence by verifying that the JWT signing method is compatible with the extracted key type (e.g., ECDSA method requires `*ecdsa.PublicKey`).

## Consequences

### Positive

- **Single parse**: The JWT is parsed exactly once. Key extraction and signature verification happen atomically in `jwt.Parse`'s keyfunc callback. No `ParseUnverified` call exists in the codebase.
- **Unified trust**: Both SD-JWT and mDOC paths use the same `TrustEvaluator` interface, making it straightforward to swap or compose trust strategies (remote AuthZEN, local certificate pool, composite).
- **Signature before trust**: The signature is always verified before the trust evaluator is called. An invalid signature never reaches the PDP.
- **Defence in depth**: Algorithm allowlist + signing method/key type validation + signature verification are layered checks that each independently prevent algorithm confusion attacks.

### Negative

- **Keyfunc complexity**: The `jwt.Parse` keyfunc closure performs key extraction, DID resolution, and validation. This concentrates logic in a callback, though the actual work is delegated to extracted helper functions (`extractJWTClaimsInfo`, `extractJWTKeyMaterial`, `validateSigningMethodForKey`).
- **Format detection heuristic**: `detectCredentialFormat()` uses structural heuristics (presence of `~` and `.` characters, base64 decodability) rather than a declared format field. Edge cases with non-standard encoding could misclassify.

### Neutral

- **VPTokenValidator still used**: For SD-JWT, the `VPTokenValidator` handles format-level validation (nonce, client_id, SD-JWT structure) with `ValidateFormat: false`. Signature verification is exclusively the responsibility of `evaluateIssuerTrust`.

## Related ADRs

- **ADR-15**: Unified Trust Management Across Credential Formats — defines the `TrustEvaluator` interface and its implementations
- **ADR-14**: W3C VC DataIntegrity / OpenID4VC Integration — context for multi-format credential support
