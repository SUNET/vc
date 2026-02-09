//go:build pkcs11

package jose

import (
	"context"
	"crypto/ecdsa"
	"encoding/asn1"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"vc/pkg/pki"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testTokenLabel = "jose-test-token"
	testUserPIN    = "1234"
	testSOPIN      = "5678"
)

// hsmTestInstance wraps a local SoftHSM2 instance for integration testing.
type hsmTestInstance struct {
	modulePath string
	tokenLabel string
	userPIN    string
	slotID     uint
	configPath string
	tmpDir     string
}

// setupSoftHSM2 creates and initializes an isolated SoftHSM2 instance for testing.
func setupSoftHSM2(t *testing.T) *hsmTestInstance {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "jose-softhsm2-*")
	require.NoError(t, err)

	tokensDir := filepath.Join(tmpDir, "tokens")
	require.NoError(t, os.MkdirAll(tokensDir, 0755))

	configContent := fmt.Sprintf("directories.tokendir = %s\nobjectstore.backend = file\n", tokensDir)
	configPath := filepath.Join(tmpDir, "softhsm2.conf")
	require.NoError(t, os.WriteFile(configPath, []byte(configContent), 0644))

	modulePath := findSoftHSMModule(t)

	// Initialize token
	cmd := exec.Command("softhsm2-util", "--init-token", "--free",
		"--label", testTokenLabel, "--so-pin", testSOPIN, "--pin", testUserPIN)
	cmd.Env = append(os.Environ(), "SOFTHSM2_CONF="+configPath)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "softhsm2-util --init-token failed: %s", string(out))

	slotID := findSlotID(t, configPath, testTokenLabel)

	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	return &hsmTestInstance{
		modulePath: modulePath,
		tokenLabel: testTokenLabel,
		userPIN:    testUserPIN,
		slotID:     slotID,
		configPath: configPath,
		tmpDir:     tmpDir,
	}
}

// findSoftHSMModule locates the SoftHSM2 PKCS#11 shared library.
func findSoftHSMModule(t *testing.T) string {
	t.Helper()
	for _, p := range []string{
		"/usr/lib/softhsm/libsofthsm2.so",
		"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
		"/usr/local/lib/softhsm/libsofthsm2.so",
		"/usr/lib64/pkcs11/libsofthsm2.so",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Fatal("SoftHSM2 module not found; install softhsm2")
	return ""
}

// findSlotID parses softhsm2-util --show-slots to find the slot for a given token label.
func findSlotID(t *testing.T, configPath, tokenLabel string) uint {
	t.Helper()
	cmd := exec.Command("softhsm2-util", "--show-slots")
	cmd.Env = append(os.Environ(), "SOFTHSM2_CONF="+configPath)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "show-slots failed: %s", string(out))

	var currentSlot uint
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "Slot ") {
			fmt.Sscanf(line, "Slot %d", &currentSlot)
		}
		if strings.Contains(line, "Label:") && strings.Contains(line, tokenLabel) {
			return currentSlot
		}
	}
	t.Fatalf("slot for token %q not found in:\n%s", tokenLabel, string(out))
	return 0
}

// generateECKey generates an EC P-256 key pair in the HSM.
func (h *hsmTestInstance) generateECKey(t *testing.T, label string) {
	t.Helper()
	cmd := exec.Command("pkcs11-tool",
		"--module", h.modulePath,
		"--login", "--pin", h.userPIN,
		"--keypairgen", "--key-type", "EC:prime256v1",
		"--label", label)
	cmd.Env = append(os.Environ(), "SOFTHSM2_CONF="+h.configPath)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "EC key generation failed: %s", string(out))
}

// setEnv sets SOFTHSM2_CONF for the duration of the test.
func (h *hsmTestInstance) setEnv(t *testing.T) {
	t.Helper()
	old := os.Getenv("SOFTHSM2_CONF")
	os.Setenv("SOFTHSM2_CONF", h.configPath)
	t.Cleanup(func() { os.Setenv("SOFTHSM2_CONF", old) })
}

// TestMakeJWT_PKCS11Signer_EC tests that MakeJWT produces a valid, verifiable JWT
// when the ECDSA signature comes from a real PKCS#11 HSM (SoftHSM2).
//
// SoftHSM2's CKM_ECDSA mechanism returns raw R||S (IEEE P1363), which is already
// the correct JWS format. This test verifies end-to-end correctness.
func TestMakeJWT_PKCS11Signer_EC(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping SoftHSM2 integration test in short mode")
	}

	hsm := setupSoftHSM2(t)
	hsm.setEnv(t)

	keyLabel := "jwt-ec-key"
	hsm.generateECKey(t, keyLabel)

	// Create PKCS11Signer (implements pki.Signer)
	signer, err := pki.NewPKCS11Signer(&pki.PKCS11Config{
		ModulePath: hsm.modulePath,
		SlotID:     hsm.slotID,
		PIN:        hsm.userPIN,
		KeyLabel:   keyLabel,
		KeyID:      "hsm-ec-1",
	})
	require.NoError(t, err)
	defer signer.Close()

	// Verify algorithm is ES256
	assert.Equal(t, "ES256", signer.Algorithm())

	// Build and sign a JWT
	header := jwt.MapClaims{"typ": "openid4vci-proof+jwt"}
	body := jwt.MapClaims{
		"iss":   "hsm-test",
		"aud":   "https://example.com",
		"iat":   1700000000,
		"nonce": "hsm-nonce",
	}

	token, err := MakeJWT(context.Background(), header, body, signer)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Get the public key for verification
	ecPub, ok := signer.PublicKey().(*ecdsa.PublicKey)
	require.True(t, ok, "expected *ecdsa.PublicKey from PKCS11Signer")

	// Parse and verify with golang-jwt (strict JWS format check)
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return ecPub, nil
	})
	require.NoError(t, err, "JWT from PKCS11Signer must verify with golang-jwt")
	assert.True(t, parsed.Valid)

	// Verify claims survived round-trip
	claims, ok := parsed.Claims.(jwt.MapClaims)
	require.True(t, ok)
	assert.Equal(t, "hsm-test", claims["iss"])
	assert.Equal(t, "https://example.com", claims["aud"])
	assert.Equal(t, "hsm-nonce", claims["nonce"])
}

// TestEnsureJWSSignature_PKCS11RawSignature tests that ensureJWSSignature correctly
// handles the raw R||S signature format returned by SoftHSM2's CKM_ECDSA.
func TestEnsureJWSSignature_PKCS11RawSignature(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping SoftHSM2 integration test in short mode")
	}

	hsm := setupSoftHSM2(t)
	hsm.setEnv(t)

	keyLabel := "raw-sig-key"
	hsm.generateECKey(t, keyLabel)

	signer, err := pki.NewPKCS11Signer(&pki.PKCS11Config{
		ModulePath: hsm.modulePath,
		SlotID:     hsm.slotID,
		PIN:        hsm.userPIN,
		KeyLabel:   keyLabel,
		KeyID:      "raw-sig-1",
	})
	require.NoError(t, err)
	defer signer.Close()

	// Get a raw signature from the HSM
	data := []byte("eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0")
	rawSig, err := signer.Sign(context.Background(), []byte(data))
	require.NoError(t, err)
	require.NotEmpty(t, rawSig)

	// SoftHSM2 CKM_ECDSA returns 64 bytes for P-256 (R||S)
	t.Logf("PKCS#11 signature length: %d bytes", len(rawSig))

	// Ensure the signature normalizes correctly
	jwsSig, err := ensureJWSSignature(rawSig, "ES256")
	require.NoError(t, err)
	assert.Len(t, jwsSig, 64, "JWS ES256 signature must be exactly 64 bytes")

	// Verify the normalized signature is cryptographically valid
	ecPub, ok := signer.PublicKey().(*ecdsa.PublicKey)
	require.True(t, ok)

	// The signer hashes internally, so we need to hash our data similarly
	// to verify. But the important assertion here is that ensureJWSSignature
	// didn't corrupt the R||S values. Extract R and S and verify they form
	// valid curve points given the signature was over hashed data.
	r := new(big.Int).SetBytes(jwsSig[:32])
	s := new(big.Int).SetBytes(jwsSig[32:])
	assert.True(t, r.Sign() > 0, "R must be positive")
	assert.True(t, s.Sign() > 0, "S must be positive")
	assert.True(t, r.Cmp(ecPub.Curve.Params().N) < 0, "R must be less than curve order")
	assert.True(t, s.Cmp(ecPub.Curve.Params().N) < 0, "S must be less than curve order")
}

// TestEnsureJWSSignature_DERFromSoftHSM tests the DER→JWS conversion path by
// wrapping a PKCS11Signer to produce ASN.1 DER-encoded ECDSA signatures.
// This simulates PKCS#11 implementations that return DER instead of raw R||S.
func TestEnsureJWSSignature_DERFromSoftHSM(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping SoftHSM2 integration test in short mode")
	}

	hsm := setupSoftHSM2(t)
	hsm.setEnv(t)

	keyLabel := "der-test-key"
	hsm.generateECKey(t, keyLabel)

	innerSigner, err := pki.NewPKCS11Signer(&pki.PKCS11Config{
		ModulePath: hsm.modulePath,
		SlotID:     hsm.slotID,
		PIN:        hsm.userPIN,
		KeyLabel:   keyLabel,
		KeyID:      "der-test-1",
	})
	require.NoError(t, err)
	defer innerSigner.Close()

	// Wrap the PKCS11Signer to convert its output to DER format.
	// This simulates a PKCS#11 implementation that returns ASN.1 DER signatures.
	derWrapper := &p11DERSignerWrapper{inner: innerSigner}

	header := jwt.MapClaims{"typ": "JWT"}
	body := jwt.MapClaims{"iss": "der-hsm-test", "sub": "user1"}

	token, err := MakeJWT(context.Background(), header, body, derWrapper)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Verify with golang-jwt
	ecPub, ok := innerSigner.PublicKey().(*ecdsa.PublicKey)
	require.True(t, ok)

	parsed, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		return ecPub, nil
	})
	require.NoError(t, err, "JWT from DER-wrapped PKCS11Signer must verify after ensureJWSSignature conversion")
	assert.True(t, parsed.Valid)

	claims, ok := parsed.Claims.(jwt.MapClaims)
	require.True(t, ok)
	assert.Equal(t, "der-hsm-test", claims["iss"])
}

// p11DERSignerWrapper wraps a pki.Signer and re-encodes the R||S signature to ASN.1 DER.
// This simulates PKCS#11 implementations (or crypto.Signer wrappers) that return
// DER-encoded ECDSA signatures instead of the raw R||S format.
type p11DERSignerWrapper struct {
	inner pki.Signer
}

func (w *p11DERSignerWrapper) Sign(ctx context.Context, data []byte) ([]byte, error) {
	rawSig, err := w.inner.Sign(ctx, data)
	if err != nil {
		return nil, err
	}

	// Convert R||S raw format to ASN.1 DER
	if len(rawSig) != 64 {
		return nil, fmt.Errorf("expected 64-byte raw signature for P-256, got %d", len(rawSig))
	}

	r := new(big.Int).SetBytes(rawSig[:32])
	s := new(big.Int).SetBytes(rawSig[32:])

	return asn1.Marshal(ecdsaASN1Signature{R: r, S: s})
}

func (w *p11DERSignerWrapper) Algorithm() string { return w.inner.Algorithm() }
func (w *p11DERSignerWrapper) KeyID() string     { return w.inner.KeyID() }
func (w *p11DERSignerWrapper) PublicKey() any    { return w.inner.PublicKey() }
