//go:build pkcs11

package pki_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/pki"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// SoftHSM2 default configuration
	defaultTokenLabel = "test-token"
	defaultUserPIN    = "1234"
	defaultSOPIN      = "5678"
	defaultSlotID     = uint(0)
)

// softhsmInstance wraps local SoftHSM2 functionality
type softhsmInstance struct {
	modulePath string
	tokenLabel string
	userPIN    string
	slotID     uint
	configPath string
	tokensDir  string
	tmpDir     string
}

// setupLocalSoftHSM2 creates and initializes a local SoftHSM2 instance
func setupLocalSoftHSM2(t *testing.T) *softhsmInstance {
	t.Helper()

	// Create temporary directories for SoftHSM2 configuration
	tmpDir, err := os.MkdirTemp("", "softhsm2-test-*")
	require.NoError(t, err)

	tokensDir := filepath.Join(tmpDir, "tokens")
	require.NoError(t, os.MkdirAll(tokensDir, 0o755))

	// Create SoftHSM2 configuration file
	configContent := fmt.Sprintf(`# SoftHSM v2 configuration file
directories.tokendir = %s
objectstore.backend = file
log.level = INFO
slots.removable = false
`, tokensDir)
	configPath := filepath.Join(tmpDir, "softhsm2.conf")
	require.NoError(t, os.WriteFile(configPath, []byte(configContent), 0o644))

	// Find SoftHSM2 module path
	modulePath := findSoftHSM2Module(t)

	// Initialize token - use free slot
	cmd := exec.Command("softhsm2-util", "--init-token", "--free",
		"--label", defaultTokenLabel, "--so-pin", defaultSOPIN, "--pin", defaultUserPIN)
	cmd.Env = append(os.Environ(), "SOFTHSM2_CONF="+configPath)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to initialize token: %s", string(output))

	// Find the slot ID for the token we just created
	slotID := findTokenSlot(t, configPath, defaultTokenLabel)

	t.Cleanup(func() {
		os.RemoveAll(tmpDir)
	})

	return &softhsmInstance{
		modulePath: modulePath,
		tokenLabel: defaultTokenLabel,
		userPIN:    defaultUserPIN,
		slotID:     slotID,
		configPath: configPath,
		tokensDir:  tokensDir,
		tmpDir:     tmpDir,
	}
}

// findSoftHSM2Module locates the SoftHSM2 PKCS#11 module
func findSoftHSM2Module(t *testing.T) string {
	t.Helper()

	// Common locations for SoftHSM2 module
	possiblePaths := []string{
		"/usr/lib/softhsm/libsofthsm2.so",
		"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
		"/usr/local/lib/softhsm/libsofthsm2.so",
		"/usr/lib64/pkcs11/libsofthsm2.so",
	}

	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	t.Fatal("Could not find SoftHSM2 module. Please install softhsm2 package.")
	return ""
}

// findTokenSlot finds the slot ID for a token with the given label
func findTokenSlot(t *testing.T, configPath, tokenLabel string) uint {
	t.Helper()

	cmd := exec.Command("softhsm2-util", "--show-slots")
	cmd.Env = append(os.Environ(), "SOFTHSM2_CONF="+configPath)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to list slots: %s", string(output))

	// Parse output to find slot with our token label
	// Output format:
	// Slot 0
	//     Slot info:
	//         ...
	//     Token info:
	//         Label:       test-token
	lines := strings.Split(string(output), "\n")
	var currentSlot uint
	for i, line := range lines {
		if strings.HasPrefix(line, "Slot ") {
			fmt.Sscanf(line, "Slot %d", &currentSlot)
		}
		if strings.Contains(line, "Label:") && strings.Contains(line, tokenLabel) {
			return currentSlot
		}
		// Also check if the next line after "Label:" contains our token
		if i > 0 && strings.Contains(lines[i-1], "Label:") && strings.TrimSpace(line) == tokenLabel {
			return currentSlot
		}
	}

	t.Fatalf("Could not find slot for token %s", tokenLabel)
	return 0
}

// generateKeyPair generates a key pair in the HSM
func (s *softhsmInstance) generateKeyPair(t *testing.T, keyType string, keyLabel string) {
	t.Helper()

	var args []string
	switch keyType {
	case "RSA":
		args = []string{
			"--module", s.modulePath, "--login", "--pin", s.userPIN,
			"--keypairgen", "--key-type", "rsa:2048", "--label", keyLabel,
		}
	case "EC":
		args = []string{
			"--module", s.modulePath, "--login", "--pin", s.userPIN,
			"--keypairgen", "--key-type", "EC:prime256v1", "--label", keyLabel,
		}
	default:
		t.Fatalf("Unsupported key type: %s", keyType)
	}

	cmd := exec.Command("pkcs11-tool", args...)
	cmd.Env = append(os.Environ(), "SOFTHSM2_CONF="+s.configPath)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Key generation failed: %s", string(output))
}

// listObjects lists all objects in the token
func (s *softhsmInstance) listObjects(t *testing.T) string {
	t.Helper()

	cmd := exec.Command("pkcs11-tool", "--module", s.modulePath, "--login",
		"--pin", s.userPIN, "--list-objects")
	cmd.Env = append(os.Environ(), "SOFTHSM2_CONF="+s.configPath)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "List objects failed: %s", string(output))

	return string(output)
}

func TestKeyLoader_LoadKeyMaterial_HSM_RSA(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	hsm := setupLocalSoftHSM2(t)
	keyLabel := "test-rsa-key"

	// Generate RSA key pair in HSM
	hsm.generateKeyPair(t, "RSA", keyLabel)

	// Verify key exists
	objects := hsm.listObjects(t)
	assert.Contains(t, objects, keyLabel, "Key should be visible in HSM")

	// Load key material
	loader := pki.NewKeyLoader()
	config := &pki.KeyConfig{
		PKCS11: &pki.PKCS11Config{
			ModulePath: hsm.modulePath,
			SlotID:     hsm.slotID,
			PIN:        hsm.userPIN,
			KeyLabel:   keyLabel,
		},
		EnableHSM: true,
	}

	// Set environment variable for SoftHSM2
	oldConf := os.Getenv("SOFTHSM2_CONF")
	os.Setenv("SOFTHSM2_CONF", hsm.configPath)
	defer os.Setenv("SOFTHSM2_CONF", oldConf)

	km, err := loader.LoadKeyMaterial(config)
	require.NoError(t, err)
	require.NotNil(t, km)
	require.NotNil(t, km.PrivateKey)
	require.NotNil(t, km.SigningMethod)

	// Verify it's an RSA key
	hsmKey, ok := km.PrivateKey.(*pki.PKCS11PrivateKey)
	require.True(t, ok, "Expected PKCS11PrivateKey type")

	_, isRSA := hsmKey.PublicKey.(*rsa.PublicKey)
	assert.True(t, isRSA, "Expected RSA public key")
}

func TestKeyLoader_LoadKeyMaterial_HSM_EC(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	hsm := setupLocalSoftHSM2(t)
	keyLabel := "test-ec-key"

	// Generate EC key pair in HSM
	hsm.generateKeyPair(t, "EC", keyLabel)

	// Verify key exists
	objects := hsm.listObjects(t)
	assert.Contains(t, objects, keyLabel, "Key should be visible in HSM")

	// Load key material
	loader := pki.NewKeyLoader()
	config := &pki.KeyConfig{
		PKCS11: &pki.PKCS11Config{
			ModulePath: hsm.modulePath,
			SlotID:     hsm.slotID,
			PIN:        hsm.userPIN,
			KeyLabel:   keyLabel,
		},
		EnableHSM: true,
	}

	// Set environment variable for SoftHSM2
	oldConf := os.Getenv("SOFTHSM2_CONF")
	os.Setenv("SOFTHSM2_CONF", hsm.configPath)
	defer os.Setenv("SOFTHSM2_CONF", oldConf)

	km, err := loader.LoadKeyMaterial(config)
	require.NoError(t, err)
	require.NotNil(t, km)
	require.NotNil(t, km.PrivateKey)
	require.NotNil(t, km.SigningMethod)

	// Verify it's an EC key
	hsmKey, ok := km.PrivateKey.(*pki.PKCS11PrivateKey)
	require.True(t, ok, "Expected PKCS11PrivateKey type")

	ecKey, isEC := hsmKey.PublicKey.(*ecdsa.PublicKey)
	assert.True(t, isEC, "Expected ECDSA public key")
	if isEC {
		assert.Equal(t, elliptic.P256(), ecKey.Curve)
	}
}

func TestKeyLoader_LoadKeyMaterial_HSM_KeyNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	hsm := setupLocalSoftHSM2(t)
	keyLabel := "non-existent-key"

	// Try to load non-existent key
	loader := pki.NewKeyLoader()
	config := &pki.KeyConfig{
		PKCS11: &pki.PKCS11Config{
			ModulePath: hsm.modulePath,
			SlotID:     hsm.slotID,
			PIN:        hsm.userPIN,
			KeyLabel:   keyLabel,
		},
		EnableHSM: true,
	}

	// Set environment variable for SoftHSM2
	oldConf := os.Getenv("SOFTHSM2_CONF")
	os.Setenv("SOFTHSM2_CONF", hsm.configPath)
	defer os.Setenv("SOFTHSM2_CONF", oldConf)

	km, err := loader.LoadKeyMaterial(config)
	assert.Error(t, err)
	assert.Nil(t, km)
	assert.Contains(t, err.Error(), "private key not found")
}

func TestKeyLoader_LoadKeyMaterial_HSM_WrongPIN(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	hsm := setupLocalSoftHSM2(t)
	keyLabel := "test-key"
	hsm.generateKeyPair(t, "RSA", keyLabel)

	// Try to load with wrong PIN
	loader := pki.NewKeyLoader()
	config := &pki.KeyConfig{
		PKCS11: &pki.PKCS11Config{
			ModulePath: hsm.modulePath,
			SlotID:     hsm.slotID,
			PIN:        "wrong-pin",
			KeyLabel:   keyLabel,
		},
		EnableHSM: true,
	}

	// Set environment variable for SoftHSM2
	oldConf := os.Getenv("SOFTHSM2_CONF")
	os.Setenv("SOFTHSM2_CONF", hsm.configPath)
	defer os.Setenv("SOFTHSM2_CONF", oldConf)

	km, err := loader.LoadKeyMaterial(config)
	assert.Error(t, err)
	assert.Nil(t, km)
	assert.Contains(t, err.Error(), "failed to login")
}

func TestKeyLoader_LoadKeyMaterial_HSM_InvalidModule(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Try to load with invalid module path
	loader := pki.NewKeyLoader()
	config := &pki.KeyConfig{
		PKCS11: &pki.PKCS11Config{
			ModulePath: "/nonexistent/libsofthsm2.so",
			SlotID:     0,
			PIN:        defaultUserPIN,
			KeyLabel:   "test-key",
		},
		EnableHSM: true,
	}

	km, err := loader.LoadKeyMaterial(config)
	assert.Error(t, err)
	assert.Nil(t, km)
	assert.Contains(t, err.Error(), "failed to load PKCS#11 module")
}

func TestKeyLoader_LoadKeyMaterial_Fallback_HSMToFile(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create file-based key as fallback
	tmpDir, err := os.MkdirTemp("", "pki-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	keyPath := filepath.Join(tmpDir, "test.key")
	certPath := filepath.Join(tmpDir, "test.crt")
	createTestKeyPairForFallback(t, keyPath, certPath)

	// Configure with both HSM (invalid) and file (valid)
	loader := pki.NewKeyLoader()
	config := &pki.KeyConfig{
		PrivateKeyPath: keyPath,
		ChainPath:      certPath,
		PKCS11: &pki.PKCS11Config{
			ModulePath: "/nonexistent/libsofthsm2.so",
			SlotID:     0,
			PIN:        defaultUserPIN,
			KeyLabel:   "test-key",
		},
		EnableFile: true,
		EnableHSM:  true,
		Priority:   []pki.KeySource{pki.KeySourceHSM, pki.KeySourceFile},
	}

	km, err := loader.LoadKeyMaterial(config)
	require.NoError(t, err, "Should fallback to file when HSM fails")
	require.NotNil(t, km)
	require.NotNil(t, km.PrivateKey)

	// Verify it loaded from file (not HSM wrapper)
	_, isHSMKey := km.PrivateKey.(*pki.PKCS11PrivateKey)
	assert.False(t, isHSMKey, "Should have loaded from file, not HSM")
}

func TestPKCS11Signer_Sign(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	hsm := setupLocalSoftHSM2(t)
	keyLabel := "test-signing-key"

	// Generate EC key pair in HSM
	hsm.generateKeyPair(t, "EC", keyLabel)

	// Load key material
	loader := pki.NewKeyLoader()
	config := &pki.KeyConfig{
		PKCS11: &pki.PKCS11Config{
			ModulePath: hsm.modulePath,
			SlotID:     hsm.slotID,
			PIN:        hsm.userPIN,
			KeyLabel:   keyLabel,
		},
		EnableHSM: true,
	}

	// Set environment variable for SoftHSM2
	oldConf := os.Getenv("SOFTHSM2_CONF")
	os.Setenv("SOFTHSM2_CONF", hsm.configPath)
	defer os.Setenv("SOFTHSM2_CONF", oldConf)

	km, err := loader.LoadKeyMaterial(config)
	require.NoError(t, err)

	// Test signing operation using crypto.Signer interface
	message := []byte("test message to sign")
	hash := sha256.Sum256(message)

	signer, ok := km.PrivateKey.(crypto.Signer)
	require.True(t, ok, "Expected crypto.Signer interface")

	signature, err := signer.Sign(nil, hash[:], crypto.SHA256)
	require.NoError(t, err)
	require.NotEmpty(t, signature)

	// Verify signature with public key
	hsmKey := km.PrivateKey.(*pki.PKCS11PrivateKey)
	ecKey := hsmKey.PublicKey.(*ecdsa.PublicKey)

	// PKCS#11 ECDSA signatures are in raw format (R || S), not ASN.1 DER
	// For P256 curve, R and S are each 32 bytes
	if len(signature) == 64 {
		// Raw format - convert to big.Int for verification
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:])
		valid := ecdsa.Verify(ecKey, hash[:], r, s)
		assert.True(t, valid, "Signature should be valid (raw format)")
	} else {
		// ASN.1 DER format
		valid := ecdsa.VerifyASN1(ecKey, hash[:], signature)
		assert.True(t, valid, "Signature should be valid (DER format)")
	}
}

// createTestKeyPairForFallback creates a test RSA key pair for fallback testing
func createTestKeyPairForFallback(t *testing.T, keyPath, certPath string) {
	t.Helper()

	// Generate a simple RSA key pair for testing
	cmd := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
		"-keyout", keyPath, "-out", certPath, "-days", "1",
		"-subj", "/CN=test")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to create test key pair: %s", string(output))
}
