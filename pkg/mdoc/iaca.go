// Package mdoc provides IACA (Issuing Authority Certificate Authority) management
// per ISO/IEC 18013-5:2021 Annex B.
package mdoc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"
)

// OIDs defined in ISO 18013-5 Annex B.
var (
	// OIDMobileDriverLicence is the extended key usage OID for mDL.
	OIDMobileDriverLicence = asn1.ObjectIdentifier{1, 0, 18013, 5, 1, 2}

	// OIDIssuerCertificate is the extended key usage for IACA certificates.
	OIDIssuerCertificate = asn1.ObjectIdentifier{1, 0, 18013, 5, 1, 6}

	// OIDMDLDocumentSigner is for Document Signer certificates.
	OIDMDLDocumentSigner = asn1.ObjectIdentifier{1, 0, 18013, 5, 1, 6}

	// OIDCRLDistributionPoints for CRL distribution.
	OIDCRLDistributionPoints = asn1.ObjectIdentifier{2, 5, 29, 31}

	// OIDAuthorityInfoAccess for OCSP.
	OIDAuthorityInfoAccess = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
)

// IACACertProfile represents the certificate profile requirements.
type IACACertProfile string

const (
	// ProfileIACA is for the root IACA certificate.
	ProfileIACA IACACertProfile = "IACA"
	// ProfileDS is for Document Signer certificates.
	ProfileDS IACACertProfile = "DS"
)

// IACACertRequest contains the parameters for generating an IACA or DS certificate.
type IACACertRequest struct {
	// Profile specifies IACA (root) or DS (document signer)
	Profile IACACertProfile

	// Subject information
	Country            string // ISO 3166-1 alpha-2
	Organization       string
	OrganizationalUnit string
	CommonName         string

	// Validity period
	NotBefore time.Time
	NotAfter  time.Time

	// Key to certify (public key)
	PublicKey crypto.PublicKey

	// For DS certificates, the issuing IACA
	IssuerCert *x509.Certificate
	IssuerKey  crypto.Signer

	// CRL distribution point URL
	CRLDistributionURL string

	// OCSP responder URL
	OCSPResponderURL string

	// Serial number (optional, generated if not provided)
	SerialNumber *big.Int
}

// IACACertManager manages IACA and Document Signer certificates.
type IACACertManager struct {
	iacaCert *x509.Certificate
	iacaKey  crypto.Signer
	dsCerts  map[string]*x509.Certificate
}

// NewIACACertManager creates a new certificate manager.
func NewIACACertManager() *IACACertManager {
	manager := &IACACertManager{
		dsCerts: make(map[string]*x509.Certificate),
	}
	return manager
}

// LoadIACA loads an existing IACA certificate and key.
func (m *IACACertManager) LoadIACA(cert *x509.Certificate, key crypto.Signer) error {
	if cert == nil {
		return fmt.Errorf("IACA certificate is required")
	}
	if key == nil {
		return fmt.Errorf("IACA private key is required")
	}

	// Verify the key matches the certificate
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		privKey, ok := key.(*ecdsa.PrivateKey)
		if !ok || !privKey.PublicKey.Equal(pub) {
			return fmt.Errorf("IACA key does not match certificate")
		}
	case ed25519.PublicKey:
		privKey, ok := key.(ed25519.PrivateKey)
		if !ok {
			return fmt.Errorf("IACA key does not match certificate type")
		}
		derivedPub := privKey.Public().(ed25519.PublicKey)
		if !derivedPub.Equal(pub) {
			return fmt.Errorf("IACA key does not match certificate")
		}
	default:
		return fmt.Errorf("unsupported key type: %T", cert.PublicKey)
	}

	m.iacaCert = cert
	m.iacaKey = key
	return nil
}

// GenerateIACACertificate generates a self-signed IACA root certificate.
// Per ISO 18013-5 Annex B.1.2.
func (m *IACACertManager) GenerateIACACertificate(req *IACACertRequest) (*x509.Certificate, crypto.Signer, error) {
	if req.Profile != ProfileIACA {
		return nil, nil, fmt.Errorf("invalid profile for IACA certificate: %s", req.Profile)
	}

	// Generate key pair if not provided
	var privateKey crypto.Signer
	var publicKey crypto.PublicKey
	var err error

	if req.PublicKey == nil {
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate key: %w", err)
		}
		publicKey = privateKey.Public()
	} else {
		publicKey = req.PublicKey
		// Caller must provide the private key via IssuerKey if they provide PublicKey
		if req.IssuerKey != nil {
			privateKey = req.IssuerKey
		} else {
			return nil, nil, fmt.Errorf("private key required when public key is provided")
		}
	}

	// Generate serial number if not provided
	serialNumber := req.SerialNumber
	if serialNumber == nil {
		serialNumber, err = generateSerialNumber()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
		}
	}

	// Set validity period
	notBefore := req.NotBefore
	if notBefore.IsZero() {
		notBefore = time.Now().UTC()
	}
	notAfter := req.NotAfter
	if notAfter.IsZero() {
		notAfter = notBefore.AddDate(10, 0, 0) // 10 years default for IACA
	}

	// Build subject
	subject := pkix.Name{
		Country:            []string{req.Country},
		Organization:       []string{req.Organization},
		OrganizationalUnit: []string{req.OrganizationalUnit},
		CommonName:         req.CommonName,
	}

	// IACA certificate template per Annex B.1.2
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		Issuer:                subject, // Self-signed
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0, // Only signs DS certificates
		MaxPathLenZero:        true,
	}

	// Add CRL distribution point if provided
	if req.CRLDistributionURL != "" {
		template.CRLDistributionPoints = []string{req.CRLDistributionURL}
	}

	// Add OCSP responder if provided
	if req.OCSPResponderURL != "" {
		template.OCSPServer = []string{req.OCSPResponderURL}
	}

	// Create the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create IACA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse IACA certificate: %w", err)
	}

	m.iacaCert = cert
	m.iacaKey = privateKey

	return cert, privateKey, nil
}

// IssueDSCertificate issues a Document Signer certificate.
// Per ISO 18013-5 Annex B.1.3.
func (m *IACACertManager) IssueDSCertificate(req *IACACertRequest) (*x509.Certificate, error) {
	if m.iacaCert == nil || m.iacaKey == nil {
		return nil, fmt.Errorf("IACA certificate and key must be loaded first")
	}
	if req.Profile != ProfileDS {
		return nil, fmt.Errorf("invalid profile for DS certificate: %s", req.Profile)
	}
	if req.PublicKey == nil {
		return nil, fmt.Errorf("public key is required for DS certificate")
	}

	// Generate serial number
	serialNumber := req.SerialNumber
	var err error
	if serialNumber == nil {
		serialNumber, err = generateSerialNumber()
		if err != nil {
			return nil, fmt.Errorf("failed to generate serial number: %w", err)
		}
	}

	// Set validity period
	notBefore := req.NotBefore
	if notBefore.IsZero() {
		notBefore = time.Now().UTC()
	}
	notAfter := req.NotAfter
	if notAfter.IsZero() {
		notAfter = notBefore.AddDate(2, 0, 0) // 2 years default for DS
	}

	// Ensure DS certificate validity is within IACA validity
	if notAfter.After(m.iacaCert.NotAfter) {
		notAfter = m.iacaCert.NotAfter
	}

	// Build subject
	subject := pkix.Name{
		Country:            []string{req.Country},
		Organization:       []string{req.Organization},
		OrganizationalUnit: []string{req.OrganizationalUnit},
		CommonName:         req.CommonName,
	}

	// DS certificate template per Annex B.1.3
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Add mDL-specific extended key usage
	template.UnknownExtKeyUsage = []asn1.ObjectIdentifier{OIDMDLDocumentSigner}

	// Add CRL distribution point if provided
	if req.CRLDistributionURL != "" {
		template.CRLDistributionPoints = []string{req.CRLDistributionURL}
	}

	// Add OCSP responder if provided
	if req.OCSPResponderURL != "" {
		template.OCSPServer = []string{req.OCSPResponderURL}
	}

	// Create the certificate signed by IACA
	certDER, err := x509.CreateCertificate(rand.Reader, template, m.iacaCert, req.PublicKey, m.iacaKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create DS certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DS certificate: %w", err)
	}

	// Store in the manager
	m.dsCerts[cert.Subject.CommonName] = cert

	return cert, nil
}

// GetCertificateChain returns the DS certificate chain including IACA.
func (m *IACACertManager) GetCertificateChain(dsCert *x509.Certificate) []*x509.Certificate {
	if dsCert == nil || m.iacaCert == nil {
		return nil
	}
	return []*x509.Certificate{dsCert, m.iacaCert}
}

// ValidateDSCertificate validates a DS certificate against the IACA.
func (m *IACACertManager) ValidateDSCertificate(dsCert *x509.Certificate) error {
	if m.iacaCert == nil {
		return fmt.Errorf("IACA certificate not loaded")
	}

	// Build verification pool
	roots := x509.NewCertPool()
	roots.AddCert(m.iacaCert)

	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if _, err := dsCert.Verify(opts); err != nil {
		return fmt.Errorf("DS certificate verification failed: %w", err)
	}

	// Check key usage
	if dsCert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("DS certificate missing digital signature key usage")
	}

	return nil
}

// GetIACACertificate returns the IACA certificate.
func (m *IACACertManager) GetIACACertificate() *x509.Certificate {
	return m.iacaCert
}

// generateSerialNumber generates a random serial number for certificates.
func generateSerialNumber() (*big.Int, error) {
	// Generate 128-bit random number
	serialNumber := make([]byte, 16)
	if _, err := rand.Read(serialNumber); err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(serialNumber), nil
}

// IACATrustList manages a list of trusted IACA certificates.
type IACATrustList struct {
	trustedCerts map[string]*x509.Certificate // keyed by Subject Key Identifier
}

// NewIACATrustList creates a new trust list.
func NewIACATrustList() *IACATrustList {
	trustList := &IACATrustList{
		trustedCerts: make(map[string]*x509.Certificate),
	}
	return trustList
}

// AddTrustedIACA adds an IACA certificate to the trust list.
func (t *IACATrustList) AddTrustedIACA(cert *x509.Certificate) error {
	if !cert.IsCA {
		return fmt.Errorf("certificate is not a CA")
	}

	// Use subject key identifier as key
	ski := fmt.Sprintf("%x", cert.SubjectKeyId)
	if ski == "" {
		// Fallback to subject DN
		ski = cert.Subject.String()
	}

	t.trustedCerts[ski] = cert
	return nil
}

// IsTrusted checks if a certificate chain is trusted.
func (t *IACATrustList) IsTrusted(chain []*x509.Certificate) error {
	if len(chain) == 0 {
		return fmt.Errorf("empty certificate chain")
	}

	// Build pool from trusted certs
	roots := x509.NewCertPool()
	for _, cert := range t.trustedCerts {
		roots.AddCert(cert)
	}

	// Verify the chain
	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	// If chain has intermediates, add them
	if len(chain) > 1 {
		intermediates := x509.NewCertPool()
		for _, cert := range chain[1:] {
			intermediates.AddCert(cert)
		}
		opts.Intermediates = intermediates
	}

	if _, err := chain[0].Verify(opts); err != nil {
		return fmt.Errorf("certificate chain verification failed: %w", err)
	}

	return nil
}

// GetTrustedIssuers returns all trusted IACA certificates.
func (t *IACATrustList) GetTrustedIssuers() []*x509.Certificate {
	certs := make([]*x509.Certificate, 0, len(t.trustedCerts))
	for _, cert := range t.trustedCerts {
		certs = append(certs, cert)
	}
	return certs
}

// IACATrustInfo contains information about a trusted IACA.
type IACATrustInfo struct {
	Country      string
	Organization string
	CommonName   string
	NotBefore    time.Time
	NotAfter     time.Time
	KeyAlgorithm string
	IsValid      bool
}

// GetTrustInfo returns information about all trusted IACAs.
func (t *IACATrustList) GetTrustInfo() []IACATrustInfo {
	now := time.Now()
	infos := make([]IACATrustInfo, 0, len(t.trustedCerts))

	for _, cert := range t.trustedCerts {
		keyAlg := "unknown"
		switch cert.PublicKey.(type) {
		case *ecdsa.PublicKey:
			keyAlg = "ECDSA"
		case ed25519.PublicKey:
			keyAlg = "Ed25519"
		}

		info := IACATrustInfo{
			Country:      getFirstOrEmpty(cert.Subject.Country),
			Organization: getFirstOrEmpty(cert.Subject.Organization),
			CommonName:   cert.Subject.CommonName,
			NotBefore:    cert.NotBefore,
			NotAfter:     cert.NotAfter,
			KeyAlgorithm: keyAlg,
			IsValid:      now.After(cert.NotBefore) && now.Before(cert.NotAfter),
		}
		infos = append(infos, info)
	}

	return infos
}

func getFirstOrEmpty(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}

// CRLInfo contains information about a Certificate Revocation List.
type CRLInfo struct {
	Issuer          string
	ThisUpdate      time.Time
	NextUpdate      time.Time
	RevokedCount    int
	DistributionURL string
}

// ParseCRLDistributionPoint extracts the CRL distribution URL from a certificate.
func ParseCRLDistributionPoint(cert *x509.Certificate) (*url.URL, error) {
	if len(cert.CRLDistributionPoints) == 0 {
		return nil, fmt.Errorf("no CRL distribution point found")
	}

	return url.Parse(cert.CRLDistributionPoints[0])
}

// ExportCertificateChainPEM exports certificates in PEM format.
func ExportCertificateChainPEM(chain []*x509.Certificate) []byte {
	var result []byte
	for _, cert := range chain {
		var block strings.Builder
		block.WriteString("-----BEGIN CERTIFICATE-----\n")
		// Base64 encode the DER
		b64 := make([]byte, ((len(cert.Raw)+2)/3)*4)
		encodeBase64(b64, cert.Raw)
		// Split into 64-char lines
		for i := 0; i < len(b64); i += 64 {
			end := min(i+64, len(b64))
			block.WriteString(string(b64[i:end]) + "\n")
		}
		block.WriteString("-----END CERTIFICATE-----\n")
		result = append(result, []byte(block.String())...)
	}
	return result
}

// Simple base64 encoding (standard library would be better in production).
func encodeBase64(dst, src []byte) {
	const encodeStd = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	di, si := 0, 0
	n := (len(src) / 3) * 3
	for si < n {
		val := uint(src[si+0])<<16 | uint(src[si+1])<<8 | uint(src[si+2])
		dst[di+0] = encodeStd[val>>18&0x3F]
		dst[di+1] = encodeStd[val>>12&0x3F]
		dst[di+2] = encodeStd[val>>6&0x3F]
		dst[di+3] = encodeStd[val&0x3F]
		si += 3
		di += 4
	}
	remain := len(src) - si
	if remain == 0 {
		return
	}
	val := uint(src[si+0]) << 16
	if remain == 2 {
		val |= uint(src[si+1]) << 8
	}
	dst[di+0] = encodeStd[val>>18&0x3F]
	dst[di+1] = encodeStd[val>>12&0x3F]
	switch remain {
	case 2:
		dst[di+2] = encodeStd[val>>6&0x3F]
		dst[di+3] = '='
	case 1:
		dst[di+2] = '='
		dst[di+3] = '='
	}
}
