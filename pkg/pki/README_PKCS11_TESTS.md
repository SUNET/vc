# PKCS#11 Integration Tests

This directory contains comprehensive integration tests for PKCS#11 HSM functionality using SoftHSM2.

## Prerequisites

The tests require SoftHSM2 and OpenSC to be installed on your system:

```bash
# Install dependencies
make test-env

# Or manually:
sudo apt-get update
sudo apt-get install -y softhsm2 opensc
```

## Running the Tests

Run all PKCS#11 tests:

```bash
go test -tags=pkcs11 -v ./pkg/pki
```

Run specific test categories:

```bash
# RSA key tests
go test -tags=pkcs11 -v ./pkg/pki -run TestKeyLoader_LoadKeyMaterial_HSM_RSA

# EC key tests
go test -tags=pkcs11 -v ./pkg/pki -run TestKeyLoader_LoadKeyMaterial_HSM_EC

# Error handling tests
go test -tags=pkcs11 -v ./pkg/pki -run "TestKeyLoader_LoadKeyMaterial_HSM_.*"

# Signing tests
go test -tags=pkcs11 -v ./pkg/pki -run TestPKCS11Signer_Sign

# Fallback tests
go test -tags=pkcs11 -v ./pkg/pki -run TestKeyLoader_LoadKeyMaterial_Fallback
```

## Test Coverage

The test suite covers:

1. **RSA Key Operations**
   - Loading RSA-2048 keys from HSM
   - Verifying RSA public key extraction
   - Testing RSA signing method detection

2. **EC Key Operations**
   - Loading ECDSA P-256 keys from HSM
   - Verifying EC public key extraction
   - Testing EC signing method detection

3. **Error Handling**
   - Non-existent key labels
   - Invalid PINs
   - Invalid module paths
   - Invalid slot IDs

4. **Fallback Mechanisms**
   - HSM-to-file fallback when HSM unavailable
   - Priority-based key source selection

5. **Cryptographic Operations**
   - ECDSA signing with HSM keys
   - Signature verification
   - Raw vs DER signature format handling

## Implementation Details

### SoftHSM2 Setup

Each test creates an isolated SoftHSM2 instance with:
- Temporary token directory
- Dedicated configuration file
- Unique token with test credentials
- Auto-cleanup on test completion

### Key Generation

Tests use `pkcs11-tool` to generate keys in the HSM:
- RSA: 2048-bit keys
- EC: P-256 (prime256v1) curve

### Slot Detection

The tests automatically detect the correct slot ID for the initialized token, handling the fact that SoftHSM2 assigns tokens to free slots dynamically.

## Architecture Notes

### Byte Order

PKCS#11 attributes are returned in platform-native byte order (little-endian on x86_64). The `bytesToUint` helper function handles this correctly.

### EC Point Format

SoftHSM2 wraps EC points in DER OCTET STRING format (0x04 LENGTH DATA). The tests handle unwrapping this encoding to extract the raw uncompressed point (0x04 || X || Y).

### Signature Format

PKCS#11 ECDSA signatures are returned in raw format (R || S as concatenated byte arrays), not ASN.1 DER. Tests handle both formats for verification.

## CI/CD Integration

To run these tests in CI/CD pipelines, ensure SoftHSM2 and OpenSC are installed in the build environment:

```yaml
# GitHub Actions example
- name: Install test dependencies
  run: |
    sudo apt-get update
    sudo apt-get install -y softhsm2 opensc

- name: Run PKCS#11 tests
  run: go test -tags=pkcs11 -v ./pkg/pki
```

## Troubleshooting

### Module Not Found

If you see "failed to load PKCS#11 module", the SoftHSM2 library is not installed or not in a standard location. Install softhsm2 or update the module path search in `findSoftHSM2Module()`.

### Token Initialization Fails

Ensure you have write permissions to create temporary directories. The tests use `os.MkdirTemp()` which respects `$TMPDIR`.

### Tests Are Slow

Each test initializes a new token and generates keys. This is intentional for isolation. Use `-run` to execute specific tests during development.
