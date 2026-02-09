package pki

import (
	"crypto/x509"
)

// LoadSigner loads key material and creates a pki.Signer from the configuration.
// Supports both software keys and HSM-backed keys.
// Returns the signer, signing certificate, and certificate chain.
func LoadSigner(cfg *KeyConfig) (Signer, *x509.Certificate, []string, error) {
	// Use centralized KeyLoader (supports both file and HSM)
	keyLoader := NewKeyLoader()
	km, err := keyLoader.LoadKeyMaterial(cfg)
	if err != nil {
		return nil, nil, nil, err
	}

	// Create pki.Signer from the key material (handles both software and HSM keys)
	signer := NewKeyMaterialSigner(km)

	return signer, km.Cert, km.Chain, nil
}
