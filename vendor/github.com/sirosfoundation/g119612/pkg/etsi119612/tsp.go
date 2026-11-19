package etsi119612

import (
	"crypto/x509"
	"encoding/base64"
	"slices"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/sirosfoundation/go-cryptoutil"
)

// CertParseErrorKind categorizes the type of certificate parsing failure.
type CertParseErrorKind string

const (
	CertParseErrUnsupportedCurve CertParseErrorKind = "unsupported_elliptic_curve"
	CertParseErrInvalidRSA       CertParseErrorKind = "invalid_rsa_key"
	CertParseErrInvalidASN1      CertParseErrorKind = "invalid_asn1"
	CertParseErrBase64           CertParseErrorKind = "invalid_base64"
	CertParseErrMalformedRSA     CertParseErrorKind = "malformed_rsa_encoding"
	CertParseErrOther            CertParseErrorKind = "other"
)

// ClassifyCertParseError determines the kind of certificate parsing error from the error message.
func ClassifyCertParseError(err error) CertParseErrorKind {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "unsupported elliptic curve"):
		return CertParseErrUnsupportedCurve
	case strings.Contains(msg, "RSA modulus is not a positive number"):
		return CertParseErrInvalidRSA
	case strings.Contains(msg, "RSA key missing NULL parameters"):
		return CertParseErrMalformedRSA
	case strings.Contains(msg, "invalid RDNSequence") ||
		strings.Contains(msg, "invalid basic constraints") ||
		strings.Contains(msg, "invalid PrintableString"):
		return CertParseErrInvalidASN1
	default:
		return CertParseErrOther
	}
}

// CertParseStats tracks certificate parsing outcomes for a trust service or set of services.
type CertParseStats struct {
	Total   int                        // Total certificates encountered
	Parsed  int                        // Successfully parsed
	Skipped map[CertParseErrorKind]int // Skipped by error kind
}

// NewCertParseStats creates a new CertParseStats instance.
func NewCertParseStats() *CertParseStats {
	return &CertParseStats{
		Skipped: make(map[CertParseErrorKind]int),
	}
}

// RecordSuccess records a successfully parsed certificate.
func (s *CertParseStats) RecordSuccess() {
	s.Total++
	s.Parsed++
}

// RecordSkip records a certificate that was skipped due to a parsing error.
func (s *CertParseStats) RecordSkip(kind CertParseErrorKind) {
	s.Total++
	s.Skipped[kind]++
}

// TotalSkipped returns the total number of skipped certificates.
func (s *CertParseStats) TotalSkipped() int {
	n := 0
	for _, v := range s.Skipped {
		n += v
	}
	return n
}

// Merge adds the counts from another CertParseStats into this one.
func (s *CertParseStats) Merge(other *CertParseStats) {
	if other == nil {
		return
	}
	s.Total += other.Total
	s.Parsed += other.Parsed
	for kind, count := range other.Skipped {
		s.Skipped[kind] += count
	}
}

const ServiceStatusGranted string = "https://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted/"

// A struct representing configuration of the validation process. By default the ServiceStatus field
// contains a single element (ServiceStatusGranted) that represents the standardized value for indicating
// that the trust service provider is valid and granted access in the trust status list (ie not withdrawn).
// The ServiceTypeIdentifier is a list of allowed service types. When creating the CertPool for use in
// certificate validation the ServiceTypeIdentifier can be populated with a list of allowed types. If left
// empty this means every service type is allowed.
type TSPServicePolicy struct {
	ServiceTypeIdentifier []string
	ServiceStatus         []string
}

// A constant TSPServicePolicy instance that represents a standard policy with an empty ServiceTypeIdentifier array.
var (
	PolicyAll = NewTSPServicePolicy()
)

// Add an element to the ServiceTypeIdentifier array.
func (tc *TSPServicePolicy) AddServiceTypeIdentifier(sti string) {
	tc.ServiceTypeIdentifier = append(tc.ServiceTypeIdentifier, sti)
}

// Add an element to the ServiceStatus array. Note that adding to this array without first removing the standard "granted"
// element may not yield the expected results.
func (tc *TSPServicePolicy) AddServiceStatus(status string) {
	tc.ServiceStatus = append(tc.ServiceStatus, status)
}

// Create a standard TSPServicePolicy instance. Calling this creates the same object as the "PolicyAll" constant.
func NewTSPServicePolicy() *TSPServicePolicy {
	tc := TSPServicePolicy{ServiceTypeIdentifier: make([]string, 0), ServiceStatus: make([]string, 0)}
	tc.AddServiceStatus(ServiceStatusGranted)
	return &tc
}

// WithCertificateResults iterates X.509 digital identities for this trust service,
// calling cb for each successfully parsed certificate, and returning aggregate
// parse statistics (including counts and reasons for any that could not be parsed).
// If ext is provided, it is used for certificate parsing (enabling support for
// brainpool curves and other extended algorithms).
func (svc *TSPServiceType) WithCertificateResults(cb func(*x509.Certificate), ext ...*cryptoutil.Extensions) *CertParseStats {
	stats := NewCertParseStats()
	if svc.TslServiceInformation.TslServiceDigitalIdentity == nil {
		return stats
	}
	for _, id := range svc.TslServiceInformation.TslServiceDigitalIdentity.DigitalId {
		if len(id.X509Certificate) > 0 {
			data, err := base64.StdEncoding.DecodeString(string(id.X509Certificate))
			if err != nil {
				stats.RecordSkip(CertParseErrBase64)
				continue
			}
			var cert *x509.Certificate
			if len(ext) > 0 && ext[0] != nil {
				cert, err = ext[0].ParseCertificate(data)
			} else {
				cert, err = x509.ParseCertificate(data)
			}
			if err != nil {
				stats.RecordSkip(ClassifyCertParseError(err))
				continue
			}
			stats.RecordSuccess()
			cb(cert)
		}
	}
	if skipped := stats.TotalSkipped(); skipped > 0 {
		svcName := "Unknown"
		if svc.TslServiceInformation.ServiceName != nil {
			svcName = FindByLanguage(svc.TslServiceInformation.ServiceName, "en", "Unknown")
		}
		log.Warnf("g119612: [TSP: %s] Skipped %d/%d certificates (unsupported by Go x509 parser)",
			svcName, skipped, stats.Total)
	}
	return stats
}

// WithCertificates calls cb for each successfully parsed X.509 certificate in
// this trust service's digital identity. Certificates that cannot be parsed
// (e.g. unsupported elliptic curves, malformed ASN.1) are silently skipped.
// Use WithCertificateResults for structured error tracking.
func (svc *TSPServiceType) WithCertificates(cb func(*x509.Certificate), ext ...*cryptoutil.Extensions) {
	svc.WithCertificateResults(cb, ext...)
}

// Checks a Trust Service for validity during certificate validation.
func (tsp *TSPType) Validate(svc *TSPServiceType, chain []*x509.Certificate, policy *TSPServicePolicy) error {

	if !slices.Contains(policy.ServiceStatus, svc.TslServiceInformation.TslServiceStatus) {
		return ErrInvalidStatus
	}

	if len(policy.ServiceTypeIdentifier) > 0 && !slices.Contains(policy.ServiceTypeIdentifier, svc.TslServiceInformation.TslServiceTypeIdentifier) {
		return ErrInvalidConstraints
	}

	return nil
}

// Summary returns a human-readable summary of scheme-level information for this TSL.
func (tsl *TSL) Summary() map[string]interface{} {
	m := make(map[string]interface{})
	if tsl == nil {
		return m
	}
	m["scheme_operator_name"] = tsl.SchemeOperatorName()
	m["num_trust_service_providers"] = tsl.NumberOfTrustServiceProviders()
	m["summary"] = tsl.String()
	return m
}
