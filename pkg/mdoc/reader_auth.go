// Package mdoc implements the ISO/IEC 18013-5:2021 Mobile Driving Licence (mDL) data model.
package mdoc

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
)

// ReaderAuthentication represents the structure to be signed for reader authentication.
// Per ISO 18013-5:2021 section 9.1.4.
type ReaderAuthentication struct {
	// SessionTranscript is the session transcript bytes
	SessionTranscript []byte
	// ItemsRequestBytes is the CBOR-encoded items request
	ItemsRequestBytes []byte
}

// ReaderAuthBuilder builds the ReaderAuth COSE_Sign1 structure.
type ReaderAuthBuilder struct {
	sessionTranscript []byte
	itemsRequest      *ItemsRequest
	readerKey         crypto.Signer
	readerCertChain   []*x509.Certificate
}

// NewReaderAuthBuilder creates a new ReaderAuthBuilder.
func NewReaderAuthBuilder() *ReaderAuthBuilder {
	return &ReaderAuthBuilder{}
}

// WithSessionTranscript sets the session transcript.
func (b *ReaderAuthBuilder) WithSessionTranscript(transcript []byte) *ReaderAuthBuilder {
	b.sessionTranscript = transcript
	return b
}

// WithItemsRequest sets the items request to be signed.
func (b *ReaderAuthBuilder) WithItemsRequest(request *ItemsRequest) *ReaderAuthBuilder {
	b.itemsRequest = request
	return b
}

// WithReaderKey sets the reader's private key and certificate chain.
func (b *ReaderAuthBuilder) WithReaderKey(key crypto.Signer, certChain []*x509.Certificate) *ReaderAuthBuilder {
	b.readerKey = key
	b.readerCertChain = certChain
	return b
}

// Build creates the ReaderAuth COSE_Sign1 structure.
func (b *ReaderAuthBuilder) Build() ([]byte, error) {
	if b.sessionTranscript == nil {
		return nil, errors.New("session transcript is required")
	}
	if b.itemsRequest == nil {
		return nil, errors.New("items request is required")
	}
	if b.readerKey == nil {
		return nil, errors.New("reader key is required")
	}
	if len(b.readerCertChain) == 0 {
		return nil, errors.New("reader certificate chain is required")
	}

	encoder, err := NewCBOREncoder()
	if err != nil {
		return nil, fmt.Errorf("failed to create CBOR encoder: %w", err)
	}

	// Encode items request
	itemsRequestBytes, err := encoder.Marshal(b.itemsRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to encode items request: %w", err)
	}

	// Build ReaderAuthentication structure
	// Per ISO 18013-5: ReaderAuthentication = ["ReaderAuthentication", SessionTranscript, ItemsRequestBytes]
	readerAuth := []any{
		"ReaderAuthentication",
		b.sessionTranscript,
		itemsRequestBytes,
	}

	readerAuthBytes, err := encoder.Marshal(readerAuth)
	if err != nil {
		return nil, fmt.Errorf("failed to encode reader authentication: %w", err)
	}

	// Get algorithm for key
	algorithm, err := AlgorithmForKey(b.readerKey)
	if err != nil {
		return nil, fmt.Errorf("failed to determine algorithm: %w", err)
	}

	// Build x5chain (DER-encoded certificates)
	x5chain := make([][]byte, len(b.readerCertChain))
	for i, cert := range b.readerCertChain {
		x5chain[i] = cert.Raw
	}

	// Create COSE_Sign1 with the reader authentication payload
	sign1, err := Sign1(readerAuthBytes, b.readerKey, algorithm, x5chain, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to sign reader authentication: %w", err)
	}

	// Encode to CBOR
	signedBytes, err := encoder.Marshal(sign1)
	if err != nil {
		return nil, fmt.Errorf("failed to encode signed reader auth: %w", err)
	}

	return signedBytes, nil
}

// BuildDocRequest creates a complete DocRequest with reader authentication.
func (b *ReaderAuthBuilder) BuildDocRequest() (*DocRequest, error) {
	if b.itemsRequest == nil {
		return nil, errors.New("items request is required")
	}

	encoder, err := NewCBOREncoder()
	if err != nil {
		return nil, fmt.Errorf("failed to create CBOR encoder: %w", err)
	}

	// Encode items request
	itemsRequestBytes, err := encoder.Marshal(b.itemsRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to encode items request: %w", err)
	}

	docRequest := &DocRequest{
		ItemsRequest: itemsRequestBytes,
	}

	// Add reader auth if we have credentials
	if b.readerKey != nil && len(b.readerCertChain) > 0 && b.sessionTranscript != nil {
		readerAuth, err := b.Build()
		if err != nil {
			return nil, fmt.Errorf("failed to build reader auth: %w", err)
		}
		docRequest.ReaderAuth = readerAuth
	}

	return docRequest, nil
}

// ReaderAuthVerifier verifies reader authentication on the device side.
type ReaderAuthVerifier struct {
	sessionTranscript []byte
	trustedReaders    *ReaderTrustList
}

// ReaderTrustList maintains a list of trusted reader certificates or CAs.
type ReaderTrustList struct {
	trustedCerts []*x509.Certificate
	trustedCAs   []*x509.Certificate
	// intentMapping maps certificate subjects to allowed intents/namespaces
	intentMapping map[string][]string
}

// NewReaderTrustList creates a new ReaderTrustList.
func NewReaderTrustList() *ReaderTrustList {
	return &ReaderTrustList{
		trustedCerts:  make([]*x509.Certificate, 0),
		trustedCAs:    make([]*x509.Certificate, 0),
		intentMapping: make(map[string][]string),
	}
}

// AddTrustedCertificate adds a directly trusted reader certificate.
func (t *ReaderTrustList) AddTrustedCertificate(cert *x509.Certificate) {
	t.trustedCerts = append(t.trustedCerts, cert)
}

// AddTrustedCA adds a trusted CA that can issue reader certificates.
func (t *ReaderTrustList) AddTrustedCA(cert *x509.Certificate) {
	t.trustedCAs = append(t.trustedCAs, cert)
}

// SetIntentMapping sets the allowed namespaces/elements for a reader identified by subject.
func (t *ReaderTrustList) SetIntentMapping(subject string, allowedNamespaces []string) {
	t.intentMapping[subject] = allowedNamespaces
}

// GetAllowedNamespaces returns the namespaces a reader is allowed to access.
func (t *ReaderTrustList) GetAllowedNamespaces(cert *x509.Certificate) []string {
	if namespaces, ok := t.intentMapping[cert.Subject.CommonName]; ok {
		return namespaces
	}
	// If no specific mapping, allow all (or could default to none)
	return nil
}

// verifyChain verifies a certificate chain where the root is trusted.
func (t *ReaderTrustList) verifyChain(chain []*x509.Certificate) error {
	if len(chain) < 2 {
		return errors.New("chain too short")
	}

	issuer := chain[len(chain)-1]
	if !t.isTrustedCA(issuer) {
		return errors.New("chain issuer not trusted")
	}

	for i := 0; i < len(chain)-1; i++ {
		if err := chain[i].CheckSignatureFrom(chain[i+1]); err != nil {
			return fmt.Errorf("chain verification failed at position %d: %w", i, err)
		}
	}
	return nil
}

// isTrustedCA checks if a certificate is a trusted CA.
func (t *ReaderTrustList) isTrustedCA(cert *x509.Certificate) bool {
	return slices.ContainsFunc(t.trustedCAs, cert.Equal)
}

// IsTrusted checks if a reader certificate chain is trusted.
func (t *ReaderTrustList) IsTrusted(chain []*x509.Certificate) error {
	if len(chain) == 0 {
		return errors.New("empty certificate chain")
	}

	readerCert := chain[0]

	// Check if directly trusted
	if slices.ContainsFunc(t.trustedCerts, readerCert.Equal) {
		return nil
	}

	// Check if signed by trusted CA
	for _, ca := range t.trustedCAs {
		if err := readerCert.CheckSignatureFrom(ca); err == nil {
			return nil
		}
	}

	// Check chain validation (chain[0] -> chain[1] -> ... -> chain[n-1] where chain[n-1] is the issuer)
	if err := t.verifyChain(chain); err == nil {
		return nil
	}

	return errors.New("reader certificate not trusted")
}

// NewReaderAuthVerifier creates a new ReaderAuthVerifier.
func NewReaderAuthVerifier(sessionTranscript []byte, trustedReaders *ReaderTrustList) *ReaderAuthVerifier {
	return &ReaderAuthVerifier{
		sessionTranscript: sessionTranscript,
		trustedReaders:    trustedReaders,
	}
}

// VerifyReaderAuth verifies reader authentication and returns the verified items request.
func (v *ReaderAuthVerifier) VerifyReaderAuth(readerAuthBytes []byte, itemsRequestBytes []byte) (*ItemsRequest, *x509.Certificate, error) {
	if len(readerAuthBytes) == 0 {
		return nil, nil, errors.New("reader auth is empty")
	}

	encoder, err := NewCBOREncoder()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CBOR encoder: %w", err)
	}

	// Parse the COSE_Sign1
	var sign1 COSESign1
	if err := encoder.Unmarshal(readerAuthBytes, &sign1); err != nil {
		return nil, nil, fmt.Errorf("failed to parse reader auth COSE_Sign1: %w", err)
	}

	// Extract certificate chain
	certChain, err := GetCertificateChainFromSign1(&sign1)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract certificate chain: %w", err)
	}

	if len(certChain) == 0 {
		return nil, nil, errors.New("no certificates in reader auth")
	}

	readerCert := certChain[0]

	// Verify the certificate chain against trusted readers
	if v.trustedReaders != nil {
		if err := v.trustedReaders.IsTrusted(certChain); err != nil {
			return nil, nil, fmt.Errorf("reader not trusted: %w", err)
		}
	}

	// Reconstruct ReaderAuthentication for verification
	readerAuth := []any{
		"ReaderAuthentication",
		v.sessionTranscript,
		itemsRequestBytes,
	}

	readerAuthPayload, err := encoder.Marshal(readerAuth)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode reader auth for verification: %w", err)
	}

	// Verify the signature
	if err := Verify1(&sign1, readerAuthPayload, readerCert.PublicKey, nil); err != nil {
		return nil, nil, fmt.Errorf("reader auth signature verification failed: %w", err)
	}

	// Parse the items request
	var itemsRequest ItemsRequest
	if err := encoder.Unmarshal(itemsRequestBytes, &itemsRequest); err != nil {
		return nil, nil, fmt.Errorf("failed to parse items request: %w", err)
	}

	return &itemsRequest, readerCert, nil
}

// FilterRequestByIntent filters an items request based on reader's allowed intents.
func (v *ReaderAuthVerifier) FilterRequestByIntent(request *ItemsRequest, readerCert *x509.Certificate) *ItemsRequest {
	if v.trustedReaders == nil {
		return request
	}

	allowedNamespaces := v.trustedReaders.GetAllowedNamespaces(readerCert)
	if allowedNamespaces == nil {
		// No restrictions
		return request
	}

	// Create allowed namespace set
	allowedSet := make(map[string]bool)
	for _, ns := range allowedNamespaces {
		allowedSet[ns] = true
	}

	// Filter request
	filteredRequest := &ItemsRequest{
		DocType:     request.DocType,
		NameSpaces:  make(map[string]map[string]bool),
		RequestInfo: request.RequestInfo,
	}

	for ns, elements := range request.NameSpaces {
		if allowedSet[ns] {
			filteredRequest.NameSpaces[ns] = elements
		}
	}

	return filteredRequest
}

// VerifyAndFilterRequest verifies reader auth and filters the request by intent.
func (v *ReaderAuthVerifier) VerifyAndFilterRequest(readerAuthBytes []byte, itemsRequestBytes []byte) (*ItemsRequest, *x509.Certificate, error) {
	request, cert, err := v.VerifyReaderAuth(readerAuthBytes, itemsRequestBytes)
	if err != nil {
		return nil, nil, err
	}

	filtered := v.FilterRequestByIntent(request, cert)
	return filtered, cert, nil
}

// ReaderCertificateProfile defines the expected profile for reader authentication certificates.
// Per ISO 18013-5:2021 Annex B.1.7.
type ReaderCertificateProfile struct {
	// Extended key usage OID for mdoc reader authentication
	ExtKeyUsageOID string
}

// DefaultReaderCertProfile returns the default reader certificate profile.
func DefaultReaderCertProfile() *ReaderCertificateProfile {
	return &ReaderCertificateProfile{
		// OID 1.0.18013.5.1.6 - id-mdl-kp-mdlReaderAuth
		ExtKeyUsageOID: "1.0.18013.5.1.6",
	}
}

// ValidateReaderCertificate validates a reader certificate against the profile.
func ValidateReaderCertificate(cert *x509.Certificate, profile *ReaderCertificateProfile) error {
	if cert == nil {
		return errors.New("certificate is nil")
	}

	// Check basic constraints - should not be a CA
	if cert.IsCA {
		return errors.New("reader certificate should not be a CA")
	}

	// Check key usage - should have digital signature
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("reader certificate must have digital signature key usage")
	}

	// Note: Extended key usage check would require parsing the OID
	// For now, we just verify basic properties

	return nil
}

// HasReaderAuth checks if a DocRequest contains reader authentication.
func HasReaderAuth(docRequest *DocRequest) bool {
	return len(docRequest.ReaderAuth) > 0
}

// ExtractReaderCertificate extracts the reader certificate from a DocRequest.
func ExtractReaderCertificate(docRequest *DocRequest) (*x509.Certificate, error) {
	if !HasReaderAuth(docRequest) {
		return nil, errors.New("no reader auth present")
	}

	encoder, err := NewCBOREncoder()
	if err != nil {
		return nil, err
	}

	var sign1 COSESign1
	if err := encoder.Unmarshal(docRequest.ReaderAuth, &sign1); err != nil {
		return nil, fmt.Errorf("failed to parse reader auth: %w", err)
	}

	certChain, err := GetCertificateChainFromSign1(&sign1)
	if err != nil {
		return nil, err
	}

	if len(certChain) == 0 {
		return nil, errors.New("no certificates in reader auth")
	}

	return certChain[0], nil
}
