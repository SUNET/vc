# PKI Package - Centralized Key Management & Signing

This package provides unified key management, certificate handling, and cryptographic signing operations for the VC project.

## Overview

The PKI package consolidates:
- **SignerConfig**: High-level configuration object for signing and encryption operations
- **KeyLoader**: Centralized key and certificate loading with multiple format support
- **Signer Interface**: Abstraction for signing operations (software and HSM)
- **Algorithm Detection**: Optimized JWT signing method selection
- **Legacy Functions**: Backward-compatible utilities (marked deprecated where applicable)

## Features

- **Multiple Key Format Support**: PKCS#8, PKCS#1 (RSA), SEC1 (EC)
- **Certificate Chain Loading**: Automatic parsing and base64 encoding for x5c
- **Type Validation**: Ensure keys match expected types (RSA, ECDSA)
- **Optimized Algorithm Detection**: O(1) map-based lookups for signing method selection
- **Thread-Safe**: All KeyLoader methods safe for concurrent use
- **HSM Support**: PKCS#11 hardware security modules (with build tag `pkcs11`)
- **Centralized Error Handling**: Consistent error messages across the codebase
- **Lazy Loading**: Keys loaded on first use with thread-safe initialization

## Performance Optimizations

- **Map-based Algorithm Selection**: Replaced switch statements with hash maps for O(1) lookups
- **Unified Hash Functions**: Single `algorithmHashMap` for all hash selections
- **Curve Normalization**: Direct elliptic.Curve comparison instead of string parsing
- **Reduced Allocations**: Streamlined signing path with pre-computed hashes
- **Lazy Initialization**: SignerConfig loads keys only when needed

## Usage

### SignerConfig Approach (Recommended for Services)

The `SignerConfig` provides the highest-level abstraction. Services create a config and call methods directly:

```go
import "vc/pkg/pki"

// File-based keys
signerConfig := pki.NewSignerConfig(&pki.KeyConfig{
    PrivateKeyPath:  "/path/to/key.pem",
    ChainPath: "/path/to/chain.pem",
})

// Sign arbitrary data
signature, err := signerConfig.Sign([]byte("data to sign"))

// Sign JWT with claims
token, err := signerConfig.SignJWT(jwt.MapClaims{
    "sub": "user123",
    "exp": time.Now().Add(time.Hour).Unix(),
})

// Get public key as JWK
jwk, err := signerConfig.GetJWK()

// Get certificate
cert, err := signerConfig.GetCertificate()
```

### SignerConfig with HSM

```go
// HSM-based keys
signerConfig := pki.NewSignerConfig(&pki.KeyConfig{
    PrivateKeyPath: "my-signing-key", // HSM label
    PKCS11: &pki.PKCS11Config{
        ModulePath: "/usr/lib/softhsm/libsofthsm2.so",
        SlotID:     0,
        PIN:        "1234",
        KeyLabel:   "signing-key",
    },
})

// Same interface works for HSM!
token, err := signerConfig.SignJWT(claims)
```

### SignerConfig with Fallback

```go
// Try HSM first, fall back to file
signerConfig := pki.NewSignerConfig(&pki.KeyConfig{
    PrivateKeyPath:  "/backup/key.pem",
    ChainPath: "/backup/chain.pem",
    PKCS11: &pki.PKCS11Config{
        ModulePath: "/usr/lib/softhsm/libsofthsm2.so",
        SlotID:     0,
        PIN:        "1234",
        KeyLabel:   "signing-key",
    },
    Priority:   []pki.KeySource{pki.KeySourceHSM, pki.KeySourceFile},
    EnableHSM:  true,
    EnableFile: true,
})

// Automatically uses HSM if available, falls back to file
signature, err := signerConfig.Sign(data)
```

### Example: Service Integration

```go
type TokenService struct {
    signer *pki.SignerConfig
}

func NewTokenService(keyPath, chainPath string) *TokenService {
    return &TokenService{
        signer: pki.NewSignerConfig(&pki.KeyConfig{
            PrivateKeyPath:  keyPath,
            ChainPath: chainPath,
        }),
    }
}

func (ts *TokenService) GenerateAccessToken(userID string) (string, error) {
    claims := jwt.MapClaims{
        "sub": userID,
        "iss": "my-service",
        "iat": time.Now().Unix(),
        "exp": time.Now().Add(time.Hour).Unix(),
    }
    
    // SignerConfig handles all the complexity
    return ts.signer.SignJWT(claims)
}

func (ts *TokenService) GetPublicKey() (*jose.JSONWebKey, error) {
    return ts.signer.GetJWK()
}
```

### KeyConfig Approach (Lower-level)

Use `KeyConfig` directly with `KeyLoader` when you need more control:

```go
import "vc/pkg/pki"

keyLoader := pki.NewKeyLoader()

// File-based keys
config := &pki.KeyConfig{
    PrivateKeyPath:  "/path/to/key.pem",
    ChainPath: "/path/to/chain.pem",
}
km, err := keyLoader.LoadKeyMaterial(config)

// HSM-based keys
config := &pki.KeyConfig{
    PrivateKeyPath: "my-signing-key", // HSM label
    HSM: &pki.PKCS11Config{
        ModulePath: "/usr/lib/softhsm/libsofthsm2.so",
        SlotID:     0,
        PIN:        "1234",
        KeyID:      "hsm-key-1",
    },
}
km, err := keyLoader.LoadKeyMaterial(config)

// Fallback: try HSM first, then file
config := &pki.KeyConfig{
    PrivateKeyPath:  "/backup/key.pem",
    ChainPath: "/backup/chain.pem",
    HSM: &pki.PKCS11Config{...},
    Priority: []pki.KeySource{pki.KeySourceHSM, pki.KeySourceFile},
}
km, err := keyLoader.LoadKeyMaterial(config)

// Explicit control with enable flags
config := &pki.KeyConfig{
    PrivateKeyPath:   "/path/to/key.pem",
    HSM:        &pki.PKCS11Config{...},
    EnableFile: true,  // Use file
    EnableHSM:  false, // Don't use HSM even though configured
}
km, err := keyLoader.LoadKeyMaterial(config)
```

**Key insight**: All key source configuration is in `KeyConfig`, making it easy to:
- Switch between file and HSM by changing config
- Support fallback scenarios with `Priority`
- Enable/disable sources with flags
- Store configuration in YAML/JSON

### Basic Key Loading (Low-level)

For more explicit control when needed:

```go
import "vc/pkg/pki"

keyLoader := pki.NewKeyLoader()

// Load just a private key
key, err := keyLoader.LoadPrivateKey("/path/to/key.pem")
if err != nil {
    return err
}

// Explicitly load from file (even if PKCS11Config is set)
km, err := keyLoader.LoadKeyMaterialFromFile("/path/to/key.pem", "/path/to/chain.pem")
if err != nil {
    return err
}

// Access the loaded materials
privateKey := km.PrivateKey
cert := km.Cert             // First certificate in chain
chain := km.Chain           // Base64-encoded DER certificates for x5c
signingMethod := km.SigningMethod  // jwt.SigningMethod for JWT operations
```

### Advanced: Explicit Source Control

```go
// Override automatic detection
keyLoader := pki.NewKeyLoaderWithPKCS11(&pki.PKCS11Config{...})
keyLoader.DefaultSource = pki.KeySourceFile  // Force file loading

// Now LoadKeyMaterial uses files even though PKCS11Config is set
km, err := keyLoader.LoadKeyMaterial("/path/to/key.pem", "")

// Or explicitly specify source per call
km, err := keyLoader.LoadKeyMaterialFromFile("/path/to/key.pem", "")  // Always file
km, err := keyLoader.LoadKeyMaterialFromHSM("key-label")                // Always HSM (deprecated)
```

### Example: Source-Agnostic Component

### Example: Source-Agnostic Component

```go
// Component that doesn't care about key source
type Signer struct {
    keyLoader *pki.KeyLoader
    keyID     string
    chainID   string
}

func (s *Signer) Sign(data []byte) ([]byte, error) {
    // Same code works for both file and HSM keys!
    km, err := s.keyLoader.LoadKeyMaterial(s.keyID, s.chainID)
    if err != nil {
        return nil, err
    }
    
    // Sign using standard crypto.Signer interface
    signer := km.PrivateKey.(crypto.Signer)
    hash := crypto.SHA256.New()
    hash.Write(data)
    
    return signer.Sign(rand.Reader, hash.Sum(nil), crypto.SHA256)
}

// Usage with files
fileSigner := &Signer{
    keyLoader: pki.NewKeyLoader(),
    keyID:     "/etc/keys/signing.pem",
    chainID:   "/etc/keys/chain.pem",
}

// Usage with HSM (same component code!)
hsmSigner := &Signer{
    keyLoader: pki.NewKeyLoaderWithPKCS11(&pki.PKCS11Config{...}),
    keyID:     "hsm-signing-key",  // HSM label
    chainID:   "",                   // Chain from HSM or empty
}
```

### Loading Keys from HSM (Legacy Example)

For backward compatibility, explicit HSM methods still exist:

```go
// Build with: go build -tags=pkcs11

// Create KeyLoader with HSM configuration
keyLoader := pki.NewKeyLoaderWithPKCS11(&pki.PKCS11Config{
    ModulePath: "/usr/lib/softhsm/libsofthsm2.so",
    SlotID:     0,
    PIN:        "1234",
    KeyID:      "hsm-key-1",
})

// Deprecated: Explicit HSM loading (use LoadKeyMaterial instead)
km, err := keyLoader.LoadKeyMaterialFromHSM("my-signing-key")
if err != nil {
    return err
}

// Load certificate from HSM (optional)
cert, err := keyLoader.LoadCertificateFromHSM("my-cert")

// Use the HSM key with standard crypto interfaces
// km.PrivateKey implements crypto.Signer
signature, err := km.PrivateKey.(crypto.Signer).Sign(rand.Reader, digest, crypto.SHA256)
```

### Signing Operations

```go
import "vc/pkg/pki"

// Create a software signer
key, _ := keyLoader.LoadPrivateKey("/path/to/key.pem")
signer, err := pki.NewSoftwareSigner(key, "my-key-id")
if err != nil {
    return err
}

// Sign data
signature, err := signer.Sign(context.Background(), dataToSign)
if err != nil {
    return err
}

// Access signer properties
algorithm := signer.Algorithm()  // e.g., "RS256", "ES256"
keyID := signer.KeyID()          // "my-key-id"
pubKey := signer.PublicKey()     // Public key for verification
```

### HSM Signing (with PKCS#11)

```go
// Build with: go build -tags=pkcs11

signer, err := pki.NewPKCS11Signer(&pki.PKCS11Config{
    ModulePath: "/usr/lib/softhsm/libsofthsm2.so",
    SlotID:     0,
    PIN:        "1234",
    KeyLabel:   "signing-key",
    KeyID:      "hsm-key-1",
})
if err != nil {
    return err
}
defer signer.Close()

// Use same Signer interface as software
signature, err := signer.Sign(ctx, data)
```

### Key Type Validation

```go
keyLoader := pki.NewKeyLoader()
key, _ := keyLoader.LoadPrivateKey("/path/to/key.pem")

// Validate it's an RSA key
if err := keyLoader.ValidateKeyType(key, "RSA"); err != nil {
    return fmt.Errorf("invalid key type: %w", err)
}

// Get algorithm for the key
alg, err := keyLoader.GetKeyAlgorithm(key)
// Returns: "RS256" for RSA, "ES256"/"ES384"/"ES512" for ECDSA
```

## Supported Key Formats

### PKCS#8 (Preferred)
```
-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----
```
Supports both RSA and ECDSA keys.

### PKCS#1 (RSA)
```
-----BEGIN RSA PRIVATE KEY-----
...
-----END RSA PRIVATE KEY-----
```
RSA keys only.

### SEC1 (EC)
```
-----BEGIN EC PRIVATE KEY-----
...
-----END EC PRIVATE KEY-----
```
ECDSA keys only.

## Certificate Chain Format

Certificate chains should be in PEM format with multiple certificates:

```
-----BEGIN CERTIFICATE-----
(Signing certificate)
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
(Intermediate CA)
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
(Root CA)
-----END CERTIFICATE-----
```

## Components Using PKI Package

### Using KeyLoader
- **Verifier (`internal/verifier/apiv1`)**: OpenID4VP request object signing, OIDC Provider tokens
- **OAuth2 (`pkg/oauth2`)**: Authorization server metadata signing
- **OpenID4VCI (`pkg/openid4vci`)**: Credential issuer metadata signing

### Using KeyLoader with HSM
- **Issuer (`internal/issuer/apiv1`)**: Can load keys from HSM for credential signing
- **Any component**: KeyLoader supports both file-based and HSM-based key loading

### Using Signer Interface
- **Issuer (`internal/issuer/apiv1`)**: Credential signing with software or HSM keys
- **Registry (`internal/registry`)**: Token status list signing

## HSM Integration Details

KeyLoader now supports PKCS#11 HSM integration through two approaches:

### 1. KeyLoader with HSM (Recommended)
```go
// Create loader with HSM config
kl := pki.NewKeyLoaderWithPKCS11(&pki.PKCS11Config{...})

// Load key material from HSM
km, err := kl.LoadKeyMaterialFromHSM("key-label")

// km.PrivateKey is a PKCS11PrivateKey that implements crypto.Signer
// It can be used with standard Go crypto interfaces
```

### 2. PKCS11Signer (Legacy, for compatibility)
```go
// Direct signer creation for backward compatibility
signer, err := pki.NewPKCS11Signer(&pki.PKCS11Config{...})
defer signer.Close()

// Use Signer interface
sig, err := signer.Sign(ctx, data)
```

**Key Difference**: 
- `KeyLoader` returns `crypto.Signer` compatible keys that work with standard crypto packages
- `PKCS11Signer` implements the custom `Signer` interface with automatic session management
- Both require `-tags=pkcs11` build flag

## Algorithm Selection

The package automatically selects appropriate algorithms based on key properties:

### RSA Keys
- **2048-3071 bits** → RS256 (SHA-256)
- **3072-4095 bits** → RS384 (SHA-384)
- **4096+ bits** → RS512 (SHA-512)

### ECDSA Keys
- **P-256** (secp256r1) → ES256 (SHA-256)
- **P-384** (secp384r1) → ES384 (SHA-384)
- **P-521** (secp521r1) → ES512 (SHA-512)

Algorithm selection uses optimized map lookups for O(1) performance.

## Migration Notes

### From Custom Key Loading
```go
// Before
keyData, err := os.ReadFile(keyPath)
block, _ := pem.Decode(keyData)
privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
// ... multiple fallback attempts ...

// After
keyLoader := pki.NewKeyLoader()
km, err := keyLoader.LoadKeyMaterial(keyPath, chainPath)
```

## Architecture

### Type Hierarchy
```
KeyLoader (unified interface)
├── LoadKeyMaterial(id, chain) → auto-detects source
│   ├── → LoadPrivateKey(path) if file-based
│   └── → loadKeyMaterialFromHSM(label) if HSM-based
├── LoadKeyMaterialFromFile(path, chain) → explicit file
└── LoadKeyMaterialFromHSM(label) → explicit HSM (deprecated)

Returns: KeyMaterial
├── PrivateKey: crypto.PrivateKey (crypto.Signer compatible)
├── Cert: *x509.Certificate
├── Chain: []string (base64-encoded DER)
└── SigningMethod: jwt.SigningMethod
```

### Design Benefits

1. **Source Transparency**: Components don't need to know if keys come from files or HSM
2. **Configuration-Based**: Key source determined by KeyLoader setup, not by calling code
3. **Standard Interfaces**: All keys implement `crypto.Signer`, work with standard Go crypto
4. **Backward Compatible**: Explicit methods still available for migration
5. **Zero Code Changes**: Switch from files to HSM by changing only KeyLoader initialization

### Internal Optimizations
- **algorithmHashMap**: O(1) hash function lookup by algorithm name
- **ecdsaSigningMethods**: O(1) signing method lookup by curve bits
- **getCurveBits()**: Direct curve comparison instead of string parsing
- **getSigningMethod()**: Unified algorithm detection used by both KeyLoader and SoftwareSigner

## Future Enhancements

Planned features:

1. **Key Caching**: In-memory cache to avoid repeated disk reads
2. **Key Watching**: Auto-reload on file changes
3. **Cloud KMS**: AWS KMS, Azure Key Vault, Google Cloud KMS
4. **Byte Array Input**: Load keys from memory instead of files only
5. **Key Rotation**: Automatic key rotation support with graceful handoff
6. **Metrics**: Track key usage, signature operations, and performance

## Testing

See `keyloader_test.go` for examples of testing key loading functionality.

```bash
go test ./pkg/pki/...
```

## Error Handling

KeyLoader provides detailed error messages:

- `"failed to read key file"`: File not found or permission denied
- `"failed to decode PEM block"`: Invalid PEM format
- `"failed to parse PKCS#8 private key"`: Invalid key encoding
- `"unsupported key type"`: Unknown PEM block type
- `"expected RSA key, got *ecdsa.PrivateKey"`: Type validation failed

## See Also

- Original key parsing: `pki.go`
- JWK operations: `jwk.go`
