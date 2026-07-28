package rpcert

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// X509RegistrationCertValidator validates X.509-format registration certificates.
// This is the initial implementation; other formats (SD-JWT, CBOR) can be added
// by implementing the RegistrationCertValidator interface.
type X509RegistrationCertValidator struct {
	// roots is the certificate pool for Registration Certificate Provider CAs.
	roots *x509.CertPool
}

// NewX509RegistrationCertValidator creates a new X.509 registration cert validator.
// The roots pool should contain trusted Registration Certificate Provider CA certificates
// (from the Trusted List).
func NewX509RegistrationCertValidator(roots *x509.CertPool) *X509RegistrationCertValidator {
	return &X509RegistrationCertValidator{roots: roots}
}

// Validate parses PEM-encoded X.509 certificate data (single cert or bundle),
// validates the leaf certificate's chain against the trusted roots, and extracts
// entitlement information. When a PEM bundle is provided, the first CERTIFICATE
// block is treated as the leaf and subsequent ones are added as intermediates.
func (v *X509RegistrationCertValidator) Validate(_ context.Context, certData []byte) (*RPEntitlements, error) {
	var cert *x509.Certificate
	intermediates := x509.NewCertPool()
	remaining := certData

	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest

		if block.Type != "CERTIFICATE" {
			continue
		}

		parsed, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse X.509 certificate: %w", err)
		}

		if cert == nil {
			cert = parsed // first CERTIFICATE block is the leaf
		} else {
			intermediates.AddCert(parsed)
		}
	}

	if cert == nil {
		return nil, fmt.Errorf("no CERTIFICATE PEM block found in input")
	}

	// Validate certificate chain — nil roots is an error (avoids
	// implicit fallback to the host system root store)
	if v.roots == nil {
		return nil, fmt.Errorf("no trust anchors configured for registration certificate validation")
	}
	opts := x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err := cert.Verify(opts); err != nil {
		return nil, fmt.Errorf("registration certificate chain validation failed: %w", err)
	}

	// Extract entitlements from the certificate
	entitlements := &RPEntitlements{
		RegistrationStatus: StatusRegistered,
		ValidFrom:          &cert.NotBefore,
		ValidUntil:         &cert.NotAfter,
	}

	// Extract RP identifier from Subject
	if cert.Subject.SerialNumber != "" {
		entitlements.RPIdentifier = cert.Subject.SerialNumber
	} else if len(cert.Subject.Organization) > 0 {
		entitlements.RPIdentifier = cert.Subject.Organization[0]
	} else {
		entitlements.RPIdentifier = cert.Subject.CommonName
	}

	// TODO: Extract allowed attributes and purpose from certificate extensions
	// when the WRPRC extension OIDs are finalized by the ETSI specifications.
	// For now, allowed attributes would need to be looked up from the National Register.

	entitlements.Raw = cert

	return entitlements, nil
}

// Format returns "x509".
func (v *X509RegistrationCertValidator) Format() string {
	return "x509"
}
