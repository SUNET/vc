# PKI Integration for VC20 Cryptosuites

This document describes the integration of `pkg/pki` key management into `pkg/vc20` Data Integrity cryptosuites, enabling HSM support for Verifiable Credential signing.

## Overview

The `pkg/pki` package provides a sophisticated key management abstraction supporting:
- Software-based keys (file PEM)
- HSM-based keys via PKCS#11
- Lazy loading and fallback strategies
- Certificate chain management

The `pkg/vc20` crypto suites currently accept raw Go crypto keys (`*ecdsa.PrivateKey`, `ed25519.PrivateKey`). This integration adds support for the `pki.Signer` abstraction.

## Architecture

### Key Challenge

The `pki.Signer.Sign()` method **hashes data internally**, but VC20 suites require signing **pre-hashed data** (concatenation of `proofHash + docHash`). We solve this via a new `RawSigner` interface.

### New Interfaces

```
pkg/pki/signer.go
├── Signer (existing)          - Sign(data) hashes internally
└── RawSigner (new)            - SignDigest(digest) signs pre-hashed

pkg/vc20/crypto/signer.go
└── VCSigner                   - Unified interface for VC signing
    ├── ECDSAKeyWrapper        - Wraps *ecdsa.PrivateKey
    ├── EdDSAKeyWrapper        - Wraps ed25519.PrivateKey
    └── PKISignerWrapper       - Wraps pki.RawSigner
```

## Implementation Phases

### Phase 1: Extend pkg/pki with RawSigner

**Files:**
- `pkg/pki/signer.go` - Add RawSigner interface
- `pkg/pki/software.go` - Implement SignDigest
- `pkg/pki/pkcs11.go` - Implement SignDigest using CKM_ECDSA
- `pkg/pki/keymaterial_signer.go` - Add SignDigest
- `pkg/pki/signer_config.go` - Add RawSigner() method

### Phase 2: Create VCSigner Abstraction

**New file:** `pkg/vc20/crypto/signer.go`

Defines the unified signing interface for VC operations with adapters for both raw keys and pki.RawSigner.

### Phase 3: Refactor Cryptosuites

Update each suite with new `SignWithSigner` methods:
- `pkg/vc20/crypto/ecdsa/suite.go` - ecdsa-rdfc-2019
- `pkg/vc20/crypto/ecdsa/sd_suite.go` - ecdsa-sd-2023
- `pkg/vc20/crypto/eddsa/suite.go` - eddsa-rdfc-2022
- `pkg/vc20/crypto/jcs/suite.go` - eddsa-jcs-2022

### Phase 4: Testing

- Unit tests for RawSigner implementations
- Integration tests with SoftHSM2
- Backward compatibility verification

## Usage Examples

### Current (Raw Key)
```go
suite := ecdsa.NewSuite()
signedCred, err := suite.Sign(cred, ecdsaPrivateKey, opts)
```

### New (With PKI/HSM)
```go
signerConfig := pki.NewSignerConfig(&pki.KeyConfig{
    PKCS11: &pki.PKCS11Config{
        ModulePath: "/usr/lib/softhsm/libsofthsm2.so",
        SlotID:     0,
        PIN:        "1234",
        KeyLabel:   "vc-issuer-key",
    },
})

rawSigner, err := signerConfig.RawSigner()
vcSigner := crypto.NewPKISignerWrapper(rawSigner)

suite := ecdsa.NewSuite()
signedCred, err := suite.SignWithSigner(cred, vcSigner, opts)
```

## Backward Compatibility

All existing `Sign(cred, key, opts)` methods remain unchanged. New `SignWithSigner(cred, signer, opts)` methods are added alongside.

## Special Considerations

### ECDSA-SD-2023
This suite requires multiple signing operations:
1. Ephemeral key signatures (must remain software-based)
2. Base proof signature (can use HSM)

Only the final base proof benefits from HSM signing.

### Ed25519 HSM Support
Some HSMs may not support Ed25519 (`CKM_EDDSA`). In such cases, software signing is the fallback.

## Task Checklist

- [ ] Add RawSigner interface to pkg/pki/signer.go
- [ ] Implement SignDigest on SoftwareSigner
- [ ] Implement SignDigest on KeyMaterialSigner
- [ ] Implement SignDigest on PKCS11Signer
- [ ] Add RawSigner() method to SignerConfig
- [ ] Create pkg/vc20/crypto/signer.go with VCSigner
- [ ] Update ecdsa suite with SignWithSigner
- [ ] Update ecdsa-sd suite with SignWithSigner
- [ ] Update eddsa suite with SignWithSigner
- [ ] Update jcs suite with SignWithSigner
- [ ] Add tests
- [ ] Update README documentation
