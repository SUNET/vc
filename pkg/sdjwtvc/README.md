# SD-JWT VC Package (sdjwtvc)

This package implements **SD-JWT-based Verifiable Credentials (SD-JWT VC)** per [draft-ietf-oauth-sd-jwt-vc-13](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/13/).

## Specifications

This implementation is compliant with:

- **SD-JWT VC draft-13**: https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/13/
- **SD-JWT draft-22**: https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/22/

## Key Features

### SD-JWT VC Compliance (draft-13)

#### Media Type (Section 3.1)
- Uses `application/dc+sd-jwt` media type
- JWT header `typ` claim: `dc+sd-jwt`
- Also accepts `vc+sd-jwt` during transition period

#### Required Claims (Section 3.2.2)
- `vct`: Verifiable Credential Type identifier (REQUIRED)
- `iss`: Issuer identifier (OPTIONAL but recommended)
- `iat`: Issuance time (OPTIONAL)
- `exp`: Expiration time (OPTIONAL)
- `cnf`: Confirmation method for Key Binding (OPTIONAL, REQUIRED for Key Binding)
- `_sd_alg`: Hash algorithm (automatically set based on hash method used)

#### Type Metadata (Section 6)
Full support for **VCTM (Verifiable Credential Type Metadata)**:

- **Type identification** (`vct` field)
- **Display metadata** (Section 8):
  - Locale-specific rendering
  - Simple rendering (logo, colors)
  - SVG templates with properties
- **Claim metadata** (Section 9):
  - Claim paths for nested structures
  - Display labels per locale
  - Selective disclosure rules (`sd`: "always", "allowed", "never")
  - Mandatory claim indicators
  - SVG template placeholders
- **Type extension** (`extends` field)
- **Integrity protection** (Section 7):
  - Subresource Integrity hashes
  - `vct#integrity`, `extends#integrity`, `uri#integrity`

### SD-JWT Core Features (draft-22)

- **Selective Disclosure**: 
  - Object properties (Section 4.2.1)
  - Array elements (Section 4.2.2)
  - Recursive structures (Section 4.2.6)
- **Security**:
  - Cryptographically secure random salts (128-bit entropy)
  - Decoy digests to obscure claim count (Section 4.2.5)
  - Hash-based disclosure protection
- **Hash Algorithms**:
  - SHA-256 (default)
  - SHA-384
  - SHA-512
  - SHA3-256
  - SHA3-512

## Examples

See [example_test.go](example_test.go) for runnable examples (`go test -run Example`).

## API Reference

### Credential Creation

#### `BuildCredential`

```go
func (c *Client) BuildCredential(
    issuer string,
    keyID string,
    privateKey any,
    credentialType string,
    documentData []byte,
    holderJWK map[string]any,
    vctm *VCTM,
    opts *CredentialOptions,
) (string, error)
```

Creates a complete SD-JWT VC credential.

**Parameters:**
- `issuer`: Issuer identifier (used in `iss` claim)
- `keyID`: Key identifier for JWT header `kid`
- `privateKey`: Signing key (*ecdsa.PrivateKey or *rsa.PrivateKey)
- `credentialType`: Credential type identifier (used in `vct` claim)
- `documentData`: JSON-encoded credential claims
- `holderJWK`: Holder's public key in JWK format (for key binding)
- `vctm`: Verifiable Credential Type Metadata
- `opts`: Optional parameters (nil for defaults)

**Returns:** Complete SD-JWT string with disclosures

### Credential Verification

#### `ParseAndVerify`

```go
func (c *Client) ParseAndVerify(
    sdJWT string,
    publicKey any,
    opts *VerificationOptions,
) (*VerificationResult, error)
```

Parses and verifies an SD-JWT VC credential.

**Parameters:**
- `sdJWT`: The SD-JWT string (format: `<JWT>~<Disclosure1>~...~[<KB-JWT>]`)
- `publicKey`: Issuer's public key (*ecdsa.PublicKey or *rsa.PublicKey)
- `opts`: Verification options (nil for defaults)

**Returns:** `VerificationResult` with parsed claims and validity status

#### `VerificationResult`

```go
type VerificationResult struct {
    Valid             bool              // Overall validity (true if no errors)
    Header            map[string]any    // JWT header
    Claims            map[string]any    // All claims (including disclosed)
    DisclosedClaims   map[string]any    // Only selectively disclosed claims
    Disclosures       []Disclosure      // Parsed disclosure structures
    VCTM              *VCTM            // Type metadata (if present in header)
    KeyBindingValid   bool              // Whether KB-JWT signature verified
    KeyBindingClaims  map[string]any    // KB-JWT claims (if present)
    Errors            []error           // Any validation errors encountered
}
```

#### `VerificationOptions`

```go
type VerificationOptions struct {
    RequireKeyBinding bool              // Whether KB-JWT must be present
    ExpectedNonce     string            // Nonce to validate in KB-JWT
    ExpectedAudience  string            // Audience to validate in KB-JWT
    AllowedClockSkew  time.Duration     // Allowed time skew (default: 5 min)
    ValidateTime      bool              // Whether to validate exp/iat (default: true)
}
```

### Key Binding

#### `CreateKeyBindingJWT`

```go
func CreateKeyBindingJWT(
    sdJWT string,
    nonce string,
    audience string,
    holderPrivateKey any,
    hashAlg string,
) (string, error)
```

Creates a Key Binding JWT to prove possession of the holder's key.

**Parameters:**
- `sdJWT`: The SD-JWT string (without KB-JWT)
- `nonce`: Freshness value from verifier
- `audience`: Verifier's identifier
- `holderPrivateKey`: Holder's private key
- `hashAlg`: Hash algorithm ("sha-256", "sha-384", "sha-512", etc.)

**Returns:** KB-JWT string to append to SD-JWT

## Compliance Notes

### Media Type Transition

Per Section 3.2.1 of draft-13:

> "Note that this draft used vc+sd-jwt as the value of the typ header from its inception in July 2023 until November 2024 when it was changed to dc+sd-jwt... It is RECOMMENDED that Verifiers and Holders accept both vc+sd-jwt and dc+sd-jwt as the value of the typ header for a reasonable transitional period."

This package uses `dc+sd-jwt` as the default but systems should accept both values.

### VCTM vs Core SD-JWT

The **VCTM (Verifiable Credential Type Metadata)** is defined in SD-JWT VC specification (Section 6), NOT in the core SD-JWT specification. VCTM provides:

- **Display metadata**: How to render credentials in wallets
- **Claim metadata**: Validation rules and selective disclosure policies
- **Type relationships**: Extension and composition of credential types

The core SD-JWT spec (draft-22) only defines the selective disclosure mechanism itself.

### Hash Algorithm Selection

The `_sd_alg` claim is automatically set based on the hash method provided:

```go
// SHA-256 (most common)
credential, _ := client.MakeCredential(sha256.New(), data, vctm)
// Sets _sd_alg to "sha-256"

// SHA3-512
credential, _ := client.MakeCredential(sha3.New512(), data, vctm)
// Sets _sd_alg to "sha3-512"
```

## References

- [SD-JWT VC Specification (draft-13)](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/13/)
- [SD-JWT Specification (draft-22)](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/22/)
- [IANA Hash Algorithm Registry](https://www.iana.org/assignments/named-information/named-information.xhtml)
- [W3C Subresource Integrity](https://www.w3.org/TR/SRI/)
