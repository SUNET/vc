# Configurable Credential Types for SAML Issuer

## Problem Statement

The current implementation hardcodes credential types in multiple places:
1. `internal/issuer/apiv1/handlers.go` - Switch statement with hardcoded types
2. `internal/issuer/httpserver/endpoints_saml.go` - Hardcoded PID/diploma/EHIC transformations
3. Package-specific document types (`pid.Document`, `education.DiplomaDocument`, etc.)

This makes adding new credential types require code changes, rebuilds, and redeployment. The goal is to make credential types fully configurable via YAML configuration.

## Current Architecture

### Credential Constructor Config
```yaml
credential_constructor:
  "pid":
    vct: "urn:eudi:pid:1"
    vctm_file_path: "/metadata/vctm_pid.json"
    auth_method: basic
```

- **Key**: Short credential type identifier (e.g., "pid", "diploma")
- **vct**: Verifiable Credential Type URN
- **vctm_file_path**: Path to VCTM (VC Type Metadata) JSON file
- **auth_method**: Authentication method required

### VCTM Structure
VCTM files define the credential schema, claims, and display properties. They're already loaded and validated.

### Current Flow
```
SAML Assertion
  → claimsToPIDDocument() [HARDCODED]
  → pid.Document struct [HARDCODED TYPE]
  → json.Marshal()
  → CreateCredentialRequest
  → switch on DocumentType [HARDCODED]
  → pidClient.sdjwt() [HARDCODED CLIENT]
  → SD-JWT token
```

## Proposed Solution

### Phase 1: Generic Document Transformation (SAML-specific)

**Goal**: Remove hardcoded credential type logic from SAML endpoints.

#### 1.1 Enhanced SAML Configuration

```yaml
issuer:
  saml:
    enabled: true
    entity_id: "https://issuer.sunet.se/saml/sp"
    mdq_server: "https://mds.swamid.se/md"
    
    # Map SAML credential requests to credential_constructor keys
    credential_mappings:
      - saml_type: "pid"  # What user requests via SAML
        credential_type: "pid"  # Maps to credential_constructor["pid"]
        credential_config_id: "urn:eudi:pid:1"  # For OpenID4VCI offers
        
        # Attribute mapping (rename-only)
        # Maps SAML attributes → generic claim names → VCTM claim paths.
        # Value transformation belongs in the target scope's derivations.
        attributes:
          # Direct mappings
          "urn:oid:2.5.4.42":  # SAML givenName
            claim: "given_name"
            required: true
          
          "urn:oid:2.5.4.4":   # SAML surname
            claim: "family_name"
            required: true
          
          "urn:oid:1.2.752.29.4.13":  # Swedish personnummer
            claim: "personal_administrative_number"
            required: false
          
          # Nested mappings for complex structures
          "urn:oid:2.5.4.10":  # organizationName
            claim: "identity.organization"
            required: false
          
          # Conditional/computed fields
          "urn:oid:0.9.2342.19200300.100.1.3":  # mail
            claim: "email_address"
            required: false
            # Value transformations (e.g. lowercase) live on the target scope's
            # derivations block — see docs/CONFIGURATION.md § Derivation Primitives.
      
      - saml_type: "diploma"
        credential_type: "diploma"
        credential_config_id: "urn:eudi:diploma:1"
        attributes:
          "urn:oid:2.5.4.42":
            claim: "credential_subject.given_name"
            required: true
          "urn:oid:2.5.4.4":
            claim: "credential_subject.family_name"
            required: true
          "urn:oid:1.3.6.1.4.1.5923.1.1.1.1":  # eduPersonAffiliation
            claim: "affiliation"
            required: true
```

#### 1.2 Generic Claim Transformer (removed)

The original design proposed a `pkg/saml/transformer.go` package exposing a
`ClaimTransformer` type with a `TransformClaims(samlType, attributes)`
entry point and a per-attribute `Transform` field (`"lowercase"`,
`"uppercase"`, `"trim"`). That package no longer exists: value
transformations are now expressed in each scope's `derivations:` block
(see docs/CONFIGURATION.md § Derivation Primitives) and attribute mappings
have been reduced to pure rename, matching the YAML above. The
pseudocode and example wiring that lived in sections 1.2 and 1.3 of this
document described APIs (`ClaimTransformer`, `TransformClaims`,
`AttributeConfig.Transform`) that no longer exist and have been removed
to avoid directing operators toward dead code.

### Phase 2: Generic Credential Issuance (gRPC issuer changes)

**Goal**: Remove hardcoded switch statement in `apiv1/handlers.go`.

**IMPORTANT**: These changes should be in a **separate commit/PR** for clean review.

#### 2.1 New Generic Credential Client

Create `internal/issuer/apiv1/credential_generic.go`:

```go
type genericCredentialClient struct {
    cfg    *model.Cfg
    log    *logger.Log
    tracer *trace.Tracer
    jose   *jose.Client
}

// sdjwt creates a credential using VCTM configuration
func (c *genericCredentialClient) sdjwt(
    ctx context.Context,
    credentialType string,  // Key from credential_constructor
    claims map[string]any,
    jwk *apiv1_issuer.Jwk,
    salt *string,
) (string, error) {
    // Get credential constructor config
    constructor := c.cfg.CredentialConstructor[credentialType]
    if constructor == nil {
        return "", fmt.Errorf("unknown credential type: %s", credentialType)
    }
    
    // Use VCTM to build credential
    vctm := constructor.VCTM
    if vctm == nil {
        return "", fmt.Errorf("VCTM not loaded for: %s", credentialType)
    }
    
    // Build credential using VCTM schema
    credential := map[string]any{
        "vct": constructor.VCT,
    }
    
    // Merge claims into credential structure
    // VCTM defines which claims are selective disclosure vs. always visible
    for claimName, value := range claims {
        if vctm.IsValidClaim(claimName) {
            credential[claimName] = value
        }
    }
    
    // Sign using SD-JWT
    token, err := c.jose.CreateSDJWT(ctx, credential, vctm, jwk, salt)
    if err != nil {
        return "", err
    }
    
    return token, nil
}
```

#### 2.2 Update MakeSDJWT Handler

Replace switch statement in `handlers.go`:

```go
func (c *Client) MakeSDJWT(ctx context.Context, req *CreateCredentialRequest) (*CreateCredentialReply, error) {
    ctx, span := c.tracer.Start(ctx, "apiv1:CreateCredential")
    defer span.End()

    // Parse document data as generic map
    var claims map[string]any
    if err := json.Unmarshal(req.DocumentData, &claims); err != nil {
        return nil, fmt.Errorf("invalid document data: %w", err)
    }
    
    // Find credential type in credential_constructor config
    var credentialType string
    for key, constructor := range c.cfg.CredentialConstructor {
        if constructor.VCT == req.DocumentType {
            credentialType = key
            break
        }
    }
    
    if credentialType == "" {
        return nil, fmt.Errorf("unknown credential type: %s", req.DocumentType)
    }
    
    // Use generic credential client
    token, err := c.genericClient.sdjwt(ctx, credentialType, claims, req.JWK, nil)
    if err != nil {
        return nil, err
    }
    
    reply := &CreateCredentialReply{
        Data: []*apiv1_issuer.Credential{
            {Credential: token},
        },
    }
    
    return reply, nil
}
```

#### 2.3 Backward Compatibility

Keep existing credential clients for backward compatibility but mark as deprecated:

```go
// Legacy support - use genericClient for new credentials
if credentialType == "pid" {
    // Old path for backward compatibility
    doc := &pid.Document{}
    if err := json.Unmarshal(req.DocumentData, &doc); err == nil {
        return c.pidClient.sdjwt(ctx, doc, req.JWK, nil)
    }
}

// New generic path
return c.genericClient.sdjwt(ctx, credentialType, claims, req.JWK, nil)
```

## Implementation Plan

### Commit 1: Generic SAML Transformer (feat/saml-issuer branch)
- [ ] Create `pkg/saml/transformer.go`
- [ ] Add `credential_mappings` to SAML config schema
- [ ] Update `endpoints_saml.go` to use transformer
- [ ] Remove hardcoded `claimsToPIDDocument()`, etc.
- [ ] Add unit tests for transformer
- [ ] Update `config.saml.example.yaml`

### Commit 2: Generic Credential Client (separate PR to main)
- [ ] Create `internal/issuer/apiv1/credential_generic.go`
- [ ] Update `handlers.go` MakeSDJWT to use generic client
- [ ] Add backward compatibility fallback
- [ ] Update VCTM loader to validate schemas
- [ ] Add integration tests
- [ ] Document migration path for existing credentials

## Benefits

1. **No Code Changes**: New credential types via YAML config only
2. **VCTM-Driven**: Credential structure defined by VCTM metadata
3. **Flexible Mappings**: Support nested claims, transformations, defaults
4. **Clean Separation**: SAML changes isolated from core issuer changes
5. **Backward Compatible**: Existing credentials continue to work

## Configuration Example

```yaml
credential_constructor:
  "custom_employee_id":
    vct: "urn:company:employee:1"
    vctm_file_path: "/metadata/vctm_employee.json"
    auth_method: basic

issuer:
  saml:
    credential_mappings:
      - saml_type: "employee"
        credential_type: "custom_employee_id"
        credential_config_id: "urn:company:employee:1"
        attributes:
          "urn:oid:2.16.840.1.113730.3.1.3":  # employeeNumber
            claim: "employee_number"
            required: true
          "urn:oid:2.5.4.10":  # organizationName
            claim: "employer"
            required: true
```

No code changes required - just add config and VCTM file!

## Migration Path

### Existing Deployments
1. Keep current credential clients
2. Add generic client alongside
3. Gradually migrate credentials to VCTM-based approach
4. Eventually deprecate hardcoded clients

### New Deployments
1. Use only generic client
2. Define all credentials via VCTM
3. Configure SAML mappings in YAML
4. No Go code changes for new credential types

---

## Implementation Status

### Phase 1: Generic SAML Transformer — superseded by derivations

The transformer approach described above (`pkg/saml/transformer.go`,
`ClaimTransformer`, `TransformClaims`, `AttributeConfig.Transform`) was
implemented and then replaced. Attribute mappings are now rename-only:
pure OID→claim-name renames with no transform step. All value
transformations now live in a scope's `derivations:` block, which runs
after mapping and whose primitives are documented in
docs/CONFIGURATION.md § Derivation Primitives. The removed files include
`pkg/saml/transformer.go` and `pkg/saml/transformer_test.go`; the
`SAMLAttributeMapping` struct has no `Transform` field.

The historical pseudocode and "lines changed" metrics for the removed
transformer are intentionally left out of this document — refer to the
git history on this file if the earlier design is needed.

### Phase 2: Generic Credential Client 🔜 PENDING (Separate PR)

**Planned for main branch:**
- Create `internal/issuer/apiv1/credential_generic.go`
- Implement `createVCFromVCTM()` function
- Remove hardcoded switch statement in `MakeSDJWT()`
- Load VCTM files from credential_constructor config
- Maintain backward compatibility

**Reason for Separation:**
Keeping Phase 2 separate allows clean PRs for SAML-specific changes (feat/saml-issuer branch) vs core gRPC issuer refactoring (main branch).

---

## Testing Summary

The transformer-era test suite was removed together with
`pkg/saml/transformer.go`. The behaviour it covered (dot-notation claim
paths, required/optional attributes, defaults, and value
transformations) is now covered by:

- `pkg/credential/attribute_mapping_test.go` — rename-only attribute
  mappings and nested claim paths.
- `pkg/credential/derivations_test.go` and
  `pkg/credential/primitives/*_test.go` — the derivation primitives
  that replaced the transformer's `"lowercase"` / `"uppercase"` /
  `"trim"` steps.

---

## Benefits Summary

### For Operators
- **No Rebuilds**: Add credential types via YAML configuration
- **Faster Deployment**: No code changes required
- **Easier Testing**: Test configurations without recompilation

### For Developers
- **Less Code**: Generic mapping + derivations replace N hardcoded functions
- **Better Separation**: SAML logic independent from credential schemas
- **Extensibility**: Easy to add new derivation primitives or claim types

### For the System
- **Flexibility**: Support any credential schema via VCTM
- **Consistency**: Same mapping/derivation pipeline for all credential types
- **Maintainability**: Single source of truth in configuration

