package revocation

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// LoadStatusListKeyPEM reads the public key that signs Status List Tokens
// from a PEM file, accepting either a bare public key (PUBLIC KEY /
// SubjectPublicKeyInfo) or a certificate carrying one.
//
// This exists because an issuer identity is not always enough to FIND a
// key: a status service may publish its authorization-server JWKS while
// signing status lists with a separate key that is exposed nowhere a
// resolver can follow. Naming the key directly is then the only way to
// verify anything it emits.
func LoadStatusListKeyPEM(path string) (crypto.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading status list signing key %q: %w", path, err)
	}

	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("status list signing key %q is not PEM", path)
	}

	switch block.Type {
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("status list signing key %q is not a valid SubjectPublicKeyInfo: %w", path, err)
		}
		return key, nil
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("status list signing key %q is not a valid certificate: %w", path, err)
		}
		return cert.PublicKey, nil
	default:
		// Named rather than guessed: a PRIVATE KEY here is a deployment
		// mistake worth reporting as itself, not something to try parsing.
		return nil, fmt.Errorf("status list signing key %q has PEM type %q; expected PUBLIC KEY or CERTIFICATE", path, block.Type)
	}
}
