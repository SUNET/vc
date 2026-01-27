//go:build !pkcs11

package pki

// loadKeyMaterialFromHSMWithConfig stub returns an error when PKCS11 is not enabled
func (kl *KeyLoader) loadKeyMaterialFromHSMWithConfig(keyLabel string, hsmConfig *PKCS11Config) (*KeyMaterial, error) {
	return nil, ErrPKCS11NotSupported
}
