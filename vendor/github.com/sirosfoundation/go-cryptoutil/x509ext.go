// Package cryptoutil provides extensible cryptographic utilities for certificate
// parsing, signature verification, key management, and algorithm mapping.
//
// The core type is [Extensions], which holds pluggable parsers, verifiers,
// and algorithm mappers. The standard library functions are always tried first;
// registered extensions act as fallbacks for algorithm families that Go's
// crypto/x509 does not support (e.g. Brainpool curves, PQ algorithms).
package cryptoutil

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// ErrNotHandled signals that an extension does not handle this input.
// Extensions should return this (not nil) when declining to process.
var ErrNotHandled = errors.New("cryptoutil: not handled by this extension")

// CertificateParser tries to parse a DER-encoded certificate that the
// standard library rejected. Return the certificate on success, or
// ErrNotHandled if the parser does not recognize this certificate type.
type CertificateParser func(der []byte) (*x509.Certificate, error)

// SignatureVerifier verifies a signature on signed data using a certificate
// whose key type the standard library cannot handle. Return nil on success,
// ErrNotHandled if not applicable, or an error describing the failure.
type SignatureVerifier func(cert *x509.Certificate, algo x509.SignatureAlgorithm, signed, signature []byte) error

// Extensions holds registered crypto extensions. Pass an instance through
// your application's configuration; use [New] to create one with defaults.
type Extensions struct {
	Parsers    []CertificateParser
	Verifiers  []SignatureVerifier
	Algorithms *AlgorithmRegistry
	KeyParsers []PrivateKeyParser
}

// New returns an Extensions with an empty AlgorithmRegistry initialized.
func New() *Extensions {
	return &Extensions{
		Algorithms: NewAlgorithmRegistry(),
	}
}

// ParseCertificate tries Go's x509.ParseCertificate first, then each
// registered CertificateParser in order. Returns the first successful result.
// If stdlib parses the certificate but cannot extract the public key
// (PublicKey is nil), extension parsers are also tried.
func (ext *Extensions) ParseCertificate(der []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err == nil && cert.PublicKey != nil {
		return cert, nil
	}
	stdCert := cert // may be non-nil with PublicKey==nil
	stdErr := err
	for _, p := range ext.Parsers {
		cert, err = p(der)
		if err == nil {
			return cert, nil
		}
		if errors.Is(err, ErrNotHandled) {
			continue
		}
		return nil, err
	}
	// No extension parser handled it. Return whatever stdlib gave us.
	if stdCert != nil {
		return stdCert, nil
	}
	return nil, stdErr
}

// CheckSignature tries the standard cert.CheckSignature first, then each
// registered SignatureVerifier. Returns nil on the first successful verification.
func (ext *Extensions) CheckSignature(cert *x509.Certificate, algo x509.SignatureAlgorithm, signed, signature []byte) error {
	err := cert.CheckSignature(algo, signed, signature)
	if err == nil {
		return nil
	}
	stdErr := err
	for _, v := range ext.Verifiers {
		err = v(cert, algo, signed, signature)
		if err == nil {
			return nil
		}
		if errors.Is(err, ErrNotHandled) {
			continue
		}
		return err
	}
	return stdErr
}

// ParseCertificatesPEM parses all certificates from PEM-encoded data,
// using ext.ParseCertificate for each block so that extended algorithms
// (brainpool, PQ, etc.) are supported. Non-CERTIFICATE blocks are skipped.
func (ext *Extensions) ParseCertificatesPEM(pemData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := ext.ParseCertificate(block.Bytes)
		if err != nil {
			return certs, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}
