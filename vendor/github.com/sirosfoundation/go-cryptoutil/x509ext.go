// Package cryptoutil provides extensible cryptographic utilities for certificate
// parsing, signature verification, key management, and algorithm mapping.
//
// The core type is [Extensions], which holds pluggable parsers, verifiers,
// and algorithm mappers. The standard library functions are always tried first;
// registered extensions act as fallbacks for algorithm families that Go's
// crypto/x509 does not support (e.g. Brainpool curves, PQ algorithms).
package cryptoutil

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
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

// CheckSignatureXMLDSIG verifies a signature using an XML-DSIG algorithm URI
// (e.g. "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256").
// It resolves the URI via the AlgorithmRegistry, tries the standard
// x509.Certificate.CheckSignature if possible, and falls back to registered
// SignatureVerifiers. This enables verification of non-standard algorithms
// (e.g. brainpool) that have registered XML-DSIG URIs.
func (ext *Extensions) CheckSignatureXMLDSIG(cert *x509.Certificate, xmldsigURI string, signed, signature []byte) error {
	// Look up the algorithm in the registry
	algo := ext.Algorithms.ByXMLDSIG(xmldsigURI)
	if algo == nil {
		return fmt.Errorf("cryptoutil: unknown XML-DSIG algorithm %q", xmldsigURI)
	}

	// Try standard x509 signature algorithms first (works for NIST curves, RSA)
	x509algo := xmldsigToX509Algorithm(xmldsigURI)
	if x509algo != x509.UnknownSignatureAlgorithm {
		err := cert.CheckSignature(x509algo, signed, signature)
		if err == nil {
			return nil
		}
		// Fall through to extension verifiers
	}

	// Try extension verifiers with the hash from the algorithm registry
	for _, v := range ext.Verifiers {
		// Map the XML-DSIG URI to the closest x509.SignatureAlgorithm for the verifier
		x509AlgoForVerifier := hashToECDSAAlgorithm(algo.Hash)
		err := v(cert, x509AlgoForVerifier, signed, signature)
		if err == nil {
			return nil
		}
		if errors.Is(err, ErrNotHandled) {
			continue
		}
		return err
	}

	return fmt.Errorf("cryptoutil: no verifier handled XML-DSIG algorithm %q", xmldsigURI)
}

// xmldsigToX509Algorithm maps well-known XML-DSIG URIs to x509.SignatureAlgorithm.
func xmldsigToX509Algorithm(uri string) x509.SignatureAlgorithm {
	switch uri {
	case "http://www.w3.org/2000/09/xmldsig#rsa-sha1":
		return x509.SHA1WithRSA
	case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":
		return x509.SHA256WithRSA
	case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384":
		return x509.SHA384WithRSA
	case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512":
		return x509.SHA512WithRSA
	case "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1":
		return x509.ECDSAWithSHA1
	case "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256":
		return x509.ECDSAWithSHA256
	case "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384":
		return x509.ECDSAWithSHA384
	case "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512":
		return x509.ECDSAWithSHA512
	default:
		return x509.UnknownSignatureAlgorithm
	}
}

// hashToECDSAAlgorithm maps a crypto.Hash to the closest ECDSA x509.SignatureAlgorithm.
// This is used to pass a meaningful algorithm to extension verifiers that determine
// the hash from the x509.SignatureAlgorithm parameter.
func hashToECDSAAlgorithm(h crypto.Hash) x509.SignatureAlgorithm {
	switch h {
	case crypto.SHA256:
		return x509.ECDSAWithSHA256
	case crypto.SHA384:
		return x509.ECDSAWithSHA384
	case crypto.SHA512:
		return x509.ECDSAWithSHA512
	case crypto.SHA1:
		return x509.ECDSAWithSHA1
	default:
		return x509.ECDSAWithSHA256
	}
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
