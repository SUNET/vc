// Example: Source-transparent key loading using KeyConfig
// This demonstrates how components don't need to care about key sources

package pki_test

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"github.com/SUNET/vc/pkg/pki"
)

// SigningService doesn't care whether keys come from files or HSM
type SigningService struct {
	keyLoader *pki.KeyLoader
	keyConfig *pki.KeyConfig
}

func (s *SigningService) Sign(data []byte) ([]byte, error) {
	// Same code for both file and HSM keys!
	km, err := s.keyLoader.LoadKeyMaterial(s.keyConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to load key: %w", err)
	}

	// Use standard crypto.Signer interface
	signer := km.PrivateKey.(crypto.Signer)
	hash := crypto.SHA256.New()
	hash.Write(data)
	digest := hash.Sum(nil)

	signature, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	fmt.Printf("Signed with algorithm: %s\n", km.SigningMethod.Alg())
	return signature, nil
}

// Example demonstrates transparent key loading with KeyConfig
func Example_transparentKeyLoading() {
	data := []byte("data to sign")
	keyLoader := pki.NewKeyLoader()

	// Scenario 1: Development with file-based keys
	fmt.Println("=== Development (File-based keys) ===")
	devConfig := &pki.KeyConfig{
		PrivateKeyPath:  "/path/to/dev/key.pem",
		ChainPath: "/path/to/dev/chain.pem",
	}
	devService := &SigningService{
		keyLoader: keyLoader,
		keyConfig: devConfig,
	}
	sig, err := devService.Sign(data)
	if err != nil {
		fmt.Printf("Dev signing error: %v\n", err)
	} else {
		fmt.Printf("Signature length: %d bytes\n\n", len(sig))
	}

	// Scenario 2: Production with HSM keys
	// SAME component code, just different KeyConfig!
	fmt.Println("=== Production (HSM keys) ===")
	prodConfig := &pki.KeyConfig{
		PrivateKeyPath: "production-signing-key", // HSM label
		PKCS11: &pki.PKCS11Config{
			ModulePath: "/usr/lib/softhsm/libsofthsm2.so",
			SlotID:     0,
			PIN:        "1234",
			KeyID:      "prod-key-1",
		},
	}
	prodService := &SigningService{
		keyLoader: keyLoader,
		keyConfig: prodConfig,
	}
	sig, err = prodService.Sign(data)
	if err != nil {
		fmt.Printf("Production signing error: %v\n", err)
	} else {
		fmt.Printf("Signature length: %d bytes\n", len(sig))
	}

	// Scenario 3: Fallback configuration (try HSM first, fall back to file)
	fmt.Println("=== Fallback (HSM → File) ===")
	fallbackConfig := &pki.KeyConfig{
		PrivateKeyPath:  "/backup/key.pem",
		ChainPath: "/backup/chain.pem",
		PKCS11: &pki.PKCS11Config{
			ModulePath: "/usr/lib/softhsm/libsofthsm2.so",
			SlotID:     0,
			PIN:        "1234",
			KeyID:      "fallback-key",
		},
		Priority: []pki.KeySource{pki.KeySourceHSM, pki.KeySourceFile},
	}
	fallbackService := &SigningService{
		keyLoader: keyLoader,
		keyConfig: fallbackConfig,
	}
	sig, err = fallbackService.Sign(data)
	if err != nil {
		fmt.Printf("Fallback signing error: %v\n", err)
	} else {
		fmt.Printf("Signature length: %d bytes\n", len(sig))
	}

	// Key benefits:
	// 1. SigningService code is identical for all scenarios
	// 2. Switch sources by changing only KeyConfig
	// 3. No conditional logic based on key source
	// 4. Support fallback scenarios with Priority
	// 5. Enable/disable sources with flags
}
