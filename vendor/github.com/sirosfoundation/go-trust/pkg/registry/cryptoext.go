package registry

import (
	"crypto/x509"
	"encoding/pem"

	"github.com/sirosfoundation/go-cryptoutil"
)

// ParseCertificate parses a DER-encoded certificate using the given extensions.
// If ext is nil, falls back to standard x509.ParseCertificate.
func ParseCertificate(der []byte, ext *cryptoutil.Extensions) (*x509.Certificate, error) {
	if ext != nil {
		return ext.ParseCertificate(der)
	}
	return x509.ParseCertificate(der)
}

// ParseCertificatesPEM parses all certificates from PEM data using the given extensions.
// If ext is nil, falls back to standard x509 parsing.
func ParseCertificatesPEM(pemData []byte, ext *cryptoutil.Extensions) ([]*x509.Certificate, error) {
	if ext != nil {
		return ext.ParseCertificatesPEM(pemData)
	}
	var certs []*x509.Certificate
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}
			certs = append(certs, cert)
		}
	}
	return certs, nil
}
