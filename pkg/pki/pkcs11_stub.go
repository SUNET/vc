//go:build !pkcs11

package pki

import (
	"context"
)

// PKCS11Config holds configuration for PKCS#11 HSM connection.
type PKCS11Config struct {
	ModulePath string `yaml:"module_path"`
	SlotID     uint   `yaml:"slot_id"`
	PIN        string `yaml:"pin"`
	KeyLabel   string `yaml:"key_label"`
	KeyID      string `yaml:"key_id"`
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
