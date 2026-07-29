//go:build !pkcs11

package pki

import (
	"context"
)

// PKCS11Config holds configuration for PKCS#11 HSM connection.
type PKCS11Config struct {
	// ModulePath is the path to the PKCS#11 library
	ModulePath string `yaml:"module_path" doc_example:"\"/usr/lib/softhsm/libsofthsm2.so\""`
	// SlotID is the HSM slot ID
	SlotID uint `yaml:"slot_id" doc_example:"0"`
	// PIN is the user PIN for the slot
	PIN string `yaml:"pin" doc_example:"\"1234\""`
	// KeyLabel is the label of the key to use
	KeyLabel string `yaml:"key_label" doc_example:"\"my-signing-key\""`
	// KeyID is the identifier for the JWT kid header
	KeyID string `yaml:"key_id" doc_example:"\"key-1\""`
}

// PKCS11Signer is a stub when PKCS#11 support is not compiled in.
type PKCS11Signer struct{}

// NewPKCS11Signer returns an error when PKCS#11 support is not compiled in.
func NewPKCS11Signer(config *PKCS11Config) (*PKCS11Signer, error) {
	return nil, ErrPKCS11NotSupported
}

// Sign is not supported without PKCS#11.
func (s *PKCS11Signer) Sign(ctx context.Context, data []byte) ([]byte, error) {
	return nil, ErrPKCS11NotSupported
}

// Algorithm is not supported without PKCS#11.
func (s *PKCS11Signer) Algorithm() string {
	return ""
}

// KeyID is not supported without PKCS#11.
func (s *PKCS11Signer) KeyID() string {
	return ""
}

// PublicKey is not supported without PKCS#11.
func (s *PKCS11Signer) PublicKey() any {
	return nil
}

// Close is a no-op without PKCS#11.
func (s *PKCS11Signer) Close() error {
	return nil
}
