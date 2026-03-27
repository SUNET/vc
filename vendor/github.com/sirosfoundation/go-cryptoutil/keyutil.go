package cryptoutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// PrivateKeyParser tries to parse a DER-encoded private key that the standard
// library cannot handle. Return the key on success, or ErrNotHandled if the
// parser does not recognize this key type.
type PrivateKeyParser func(der []byte) (crypto.PrivateKey, error)

// ParsePrivateKey parses a DER-encoded private key, trying Go's standard
// parsers (PKCS#8, EC, PKCS#1) first, then registered KeyParsers.
func (ext *Extensions) ParsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	for _, p := range ext.KeyParsers {
		key, err := p(der)
		if err == nil {
			return key, nil
		}
		if errors.Is(err, ErrNotHandled) {
			continue
		}
		return nil, err
	}
	return nil, fmt.Errorf("cryptoutil: failed to parse private key")
}

// ParsePrivateKeyPEM parses a PEM-encoded private key. Supports RSA PRIVATE KEY,
// EC PRIVATE KEY, and PRIVATE KEY block types, plus registered extension parsers.
func (ext *Extensions) ParsePrivateKeyPEM(pemData []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("cryptoutil: no PEM block found")
	}
	return ext.ParsePrivateKey(block.Bytes)
}

// PublicKeyFromSigner extracts the public key from a crypto.Signer.
func PublicKeyFromSigner(s crypto.Signer) crypto.PublicKey {
	return s.Public()
}

// IsECDSAKey returns true if the public key is an ECDSA key.
func IsECDSAKey(pub crypto.PublicKey) bool {
	_, ok := pub.(*ecdsa.PublicKey)
	return ok
}

// IsRSAKey returns true if the public key is an RSA key.
func IsRSAKey(pub crypto.PublicKey) bool {
	_, ok := pub.(*rsa.PublicKey)
	return ok
}

// IsEdDSAKey returns true if the public key is an Ed25519 key.
func IsEdDSAKey(pub crypto.PublicKey) bool {
	_, ok := pub.(ed25519.PublicKey)
	return ok
}
