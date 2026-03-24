package pki

import (
	"crypto/x509"

	"github.com/sirosfoundation/go-cryptoutil"
)

// ParseCertificate parses a DER-encoded certificate using extension-aware
// parsing if ext is non-nil, falling back to standard x509.ParseCertificate.
func ParseCertificate(der []byte, ext *cryptoutil.Extensions) (*x509.Certificate, error) {
	if ext != nil {
		return ext.ParseCertificate(der)
	}
	return x509.ParseCertificate(der)
}
