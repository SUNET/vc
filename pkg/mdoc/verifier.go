// Package mdoc implements the ISO/IEC 18013-5:2021 Mobile Driving Licence (mDL) data model.
package mdoc

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"vc/pkg/trust"

	"github.com/sirosfoundation/go-trust/pkg/trustapi"
)

// Verifier verifies mDL documents according to ISO/IEC 18013-5:2021.
type Verifier struct {
	trustEvaluator      trust.TrustEvaluator
	skipRevocationCheck bool
	clock               func() time.Time
}

// VerifierConfig contains configuration options for the Verifier.
type VerifierConfig struct {
	// TrustEvaluator is required for validating certificate chains using an external
	// trust framework (e.g., go-trust with mdociaca, ETSI TSL, or OpenID Federation).
	// This replaces the deprecated local TrustList approach - all trust decisions
	// should go through TrustEvaluator for consistent policy enforcement.
	TrustEvaluator trust.TrustEvaluator

	// SkipRevocationCheck skips CRL/OCSP revocation checking if true.
	SkipRevocationCheck bool

	// Clock is an optional function that returns the current time.
	// If nil, time.Now() is used.
	Clock func() time.Time
}

// VerificationResult contains the result of verifying a DeviceResponse.
type VerificationResult struct {
	// Valid indicates whether the overall verification succeeded.
	Valid bool

	// Documents contains the verification results for each document.
	Documents []DocumentVerificationResult

	// Errors contains any errors encountered during verification.
	Errors []error
}

// DocumentVerificationResult contains the verification result for a single document.
type DocumentVerificationResult struct {
	// DocType is the document type identifier.
	DocType string

	// Valid indicates whether this document passed verification.
	Valid bool

	// MSO is the parsed Mobile Security Object.
	MSO *MobileSecurityObject

	// IssuerCertificate is the Document Signer certificate.
	IssuerCertificate *x509.Certificate

	// VerifiedElements contains successfully verified data elements.
	VerifiedElements map[string]map[string]any

	// Errors contains any errors for this document.
	Errors []error
}

// NewVerifier creates a new Verifier with the given configuration.
// TrustEvaluator is required - use go-trust with appropriate registries
// (mdociaca for dynamic IACA, ETSI TSL, OpenID Federation, etc.).
func NewVerifier(config VerifierConfig) (*Verifier, error) {
	if config.TrustEvaluator == nil {
		return nil, errors.New("TrustEvaluator is required")
	}

	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}

	return &Verifier{
		trustEvaluator:      config.TrustEvaluator,
		skipRevocationCheck: config.SkipRevocationCheck,
		clock:               clock,
	}, nil
}

// VerifyDeviceResponse verifies a complete DeviceResponse.
func (v *Verifier) VerifyDeviceResponse(response *DeviceResponse) *VerificationResult {
	return v.VerifyDeviceResponseWithContext(context.Background(), response)
}

// VerifyDeviceResponseWithContext verifies a complete DeviceResponse with a context.
// The context is used for external trust evaluation when TrustEvaluator is configured.
func (v *Verifier) VerifyDeviceResponseWithContext(ctx context.Context, response *DeviceResponse) *VerificationResult {
	result := &VerificationResult{
		Valid:     true,
		Documents: make([]DocumentVerificationResult, 0, len(response.Documents)),
		Errors:    make([]error, 0),
	}

	// Check response version
	if response.Version != "1.0" {
		result.Errors = append(result.Errors, fmt.Errorf("unsupported response version: %s", response.Version))
		result.Valid = false
	}

	// Check response status
	if response.Status != 0 {
		result.Errors = append(result.Errors, fmt.Errorf("response status indicates error: %d", response.Status))
		result.Valid = false
	}

	// Verify each document
	for _, doc := range response.Documents {
		docResult := v.verifyDocumentWithContext(ctx, &doc)
		result.Documents = append(result.Documents, docResult)
		if !docResult.Valid {
			result.Valid = false
		}
	}

	return result
}

// VerifyDocument verifies a single Document.
func (v *Verifier) VerifyDocument(doc *Document) DocumentVerificationResult {
	return v.verifyDocumentWithContext(context.Background(), doc)
}

// verifyDocumentWithContext verifies a single Document with a context for trust evaluation.
func (v *Verifier) verifyDocumentWithContext(ctx context.Context, doc *Document) DocumentVerificationResult {
	result := DocumentVerificationResult{
		DocType:          doc.DocType,
		Valid:            true,
		VerifiedElements: make(map[string]map[string]any),
		Errors:           make([]error, 0),
	}

	// Step 1: Parse the IssuerAuth (COSE_Sign1 containing MSO)
	issuerAuth, err := v.parseIssuerAuth(doc.IssuerSigned.IssuerAuth)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Errorf("failed to parse issuer auth: %w", err))
		result.Valid = false
		return result
	}

	// Step 2: Extract and verify the certificate chain
	certChain, err := GetCertificateChainFromSign1(issuerAuth)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Errorf("failed to extract certificate chain: %w", err))
		result.Valid = false
		return result
	}

	if len(certChain) == 0 {
		result.Errors = append(result.Errors, errors.New("no certificates in issuer auth"))
		result.Valid = false
		return result
	}

	dsCert := certChain[0]
	result.IssuerCertificate = dsCert

	// Step 3: Verify the certificate chain against trusted IACAs
	if err := v.verifyCertificateChainWithContext(ctx, certChain, doc.DocType); err != nil {
		result.Errors = append(result.Errors, fmt.Errorf("certificate chain verification failed: %w", err))
		result.Valid = false
		return result
	}

	// Step 4: Verify the COSE_Sign1 signature
	mso, err := VerifyMSO(issuerAuth, dsCert)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Errorf("MSO signature verification failed: %w", err))
		result.Valid = false
		return result
	}
	result.MSO = mso

	// Step 5: Validate MSO content
	if err := v.validateMSO(mso, doc.DocType); err != nil {
		result.Errors = append(result.Errors, fmt.Errorf("MSO validation failed: %w", err))
		result.Valid = false
		return result
	}

	// Step 6: Verify each IssuerSignedItem against MSO digests
	for namespace, items := range doc.IssuerSigned.NameSpaces {
		result.VerifiedElements[namespace] = make(map[string]any)

		for _, item := range items {
			if err := VerifyDigest(mso, namespace, &item); err != nil {
				result.Errors = append(result.Errors, fmt.Errorf("digest verification failed for %s/%s: %w",
					namespace, item.ElementIdentifier, err))
				result.Valid = false
				continue
			}
			result.VerifiedElements[namespace][item.ElementIdentifier] = item.ElementValue
		}
	}

	return result
}

// parseIssuerAuth parses the IssuerAuth CBOR bytes into a COSESign1 structure.
func (v *Verifier) parseIssuerAuth(data []byte) (*COSESign1, error) {
	if len(data) == 0 {
		return nil, errors.New("empty issuer auth data")
	}

	encoder, err := NewCBOREncoder()
	if err != nil {
		return nil, fmt.Errorf("failed to create CBOR encoder: %w", err)
	}

	var sign1 COSESign1
	if err := encoder.Unmarshal(data, &sign1); err != nil {
		return nil, fmt.Errorf("failed to unmarshal COSE_Sign1: %w", err)
	}

	return &sign1, nil
}

// verifyCertificateChain verifies the DS certificate chain against trusted IACAs.
func (v *Verifier) verifyCertificateChain(chain []*x509.Certificate) error {
	return v.verifyCertificateChainWithContext(context.Background(), chain, "")
}

// verifyCertificateChainWithContext verifies the DS certificate chain via TrustEvaluator.
// This delegates all trust decisions to go-trust which can use mdociaca, ETSI TSL,
// OpenID Federation, or other registries for dynamic trust anchor resolution.
func (v *Verifier) verifyCertificateChainWithContext(ctx context.Context, chain []*x509.Certificate, docType string) error {
	if len(chain) == 0 {
		return errors.New("empty certificate chain")
	}

	dsCert := chain[0]
	now := v.clock()

	// Check certificate validity period
	if now.Before(dsCert.NotBefore) {
		return fmt.Errorf("certificate not yet valid: valid from %s", dsCert.NotBefore)
	}
	if now.After(dsCert.NotAfter) {
		return fmt.Errorf("certificate expired: valid until %s", dsCert.NotAfter)
	}

	// Extract issuer identifier from the DS certificate
	// For mDOC, this is typically the issuing_country or issuing_authority
	issuerID := extractMDocIssuerID(dsCert)

	// Delegate trust decision to TrustEvaluator (go-trust)
	decision, err := v.trustEvaluator.Evaluate(ctx, &trust.EvaluationRequest{
		EvaluationRequest: trustapi.EvaluationRequest{
			SubjectID: issuerID,
			KeyType:   trust.KeyTypeX5C,
			Key:       chain,
			Role:      trust.RoleCredentialIssuer,
			DocType:   docType,
		},
	})

	if err != nil {
		return fmt.Errorf("trust evaluation failed: %w", err)
	}

	if !decision.Trusted {
		return fmt.Errorf("issuer not trusted: %s", decision.Reason)
	}

	// TODO: Check revocation status if not skipped
	if !v.skipRevocationCheck {
		// Revocation checking would go here (CRL/OCSP)
	}

	return nil
}

// extractMDocIssuerID extracts an issuer identifier from an mDOC DS certificate.
// This looks for the issuing country/authority in the certificate.
func extractMDocIssuerID(cert *x509.Certificate) string {
	// Try to get a meaningful issuer identifier:
	// 1. Organization (e.g., "Department of Motor Vehicles")
	// 2. Country code (e.g., "SE" for Sweden)
	// 3. Common Name (CN)

	if len(cert.Subject.Organization) > 0 {
		return cert.Subject.Organization[0]
	}

	if len(cert.Subject.Country) > 0 {
		return cert.Subject.Country[0]
	}

	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}

	// Fallback: use the issuer's Common Name
	return cert.Issuer.CommonName
}

// validateMSO validates the Mobile Security Object content.
func (v *Verifier) validateMSO(mso *MobileSecurityObject, expectedDocType string) error {
	// Check version
	if mso.Version != "1.0" {
		return fmt.Errorf("unsupported MSO version: %s", mso.Version)
	}

	// Check document type
	if mso.DocType != expectedDocType {
		return fmt.Errorf("MSO docType mismatch: got %s, expected %s", mso.DocType, expectedDocType)
	}

	// Check digest algorithm
	if mso.DigestAlgorithm != "SHA-256" && mso.DigestAlgorithm != "SHA-512" {
		return fmt.Errorf("unsupported digest algorithm: %s", mso.DigestAlgorithm)
	}

	// Check validity
	if err := ValidateMSOValidity(mso); err != nil {
		return err
	}

	return nil
}

// VerifyIssuerSigned verifies IssuerSigned data and returns verified elements.
// This is a convenience method for verifying just the issuer-signed portion.
func (v *Verifier) VerifyIssuerSigned(issuerSigned *IssuerSigned, docType string) (*MobileSecurityObject, map[string]map[string]any, error) {
	// Parse the IssuerAuth
	issuerAuth, err := v.parseIssuerAuth(issuerSigned.IssuerAuth)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse issuer auth: %w", err)
	}

	// Extract and verify the certificate chain
	certChain, err := GetCertificateChainFromSign1(issuerAuth)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract certificate chain: %w", err)
	}

	if len(certChain) == 0 {
		return nil, nil, errors.New("no certificates in issuer auth")
	}

	dsCert := certChain[0]

	// Verify the certificate chain
	if err := v.verifyCertificateChain(certChain); err != nil {
		return nil, nil, fmt.Errorf("certificate chain verification failed: %w", err)
	}

	// Verify the MSO signature
	mso, err := VerifyMSO(issuerAuth, dsCert)
	if err != nil {
		return nil, nil, fmt.Errorf("MSO signature verification failed: %w", err)
	}

	// Validate MSO content
	if err := v.validateMSO(mso, docType); err != nil {
		return nil, nil, fmt.Errorf("MSO validation failed: %w", err)
	}

	// Verify each IssuerSignedItem
	verifiedElements := make(map[string]map[string]any)
	for namespace, items := range issuerSigned.NameSpaces {
		verifiedElements[namespace] = make(map[string]any)

		for _, item := range items {
			if err := VerifyDigest(mso, namespace, &item); err != nil {
				return nil, nil, fmt.Errorf("digest verification failed for %s/%s: %w",
					namespace, item.ElementIdentifier, err)
			}
			verifiedElements[namespace][item.ElementIdentifier] = item.ElementValue
		}
	}

	return mso, verifiedElements, nil
}

// ExtractElements extracts data elements from a VerificationResult.
// Returns a map of namespace -> element identifier -> value for all verified elements.
func (r *VerificationResult) ExtractElements() map[string]map[string]any {
	result := make(map[string]map[string]any)

	for _, doc := range r.Documents {
		for namespace, elements := range doc.VerifiedElements {
			if result[namespace] == nil {
				result[namespace] = make(map[string]any)
			}
			for id, value := range elements {
				result[namespace][id] = value
			}
		}
	}

	return result
}

// GetElement retrieves a specific verified element from the result.
func (r *VerificationResult) GetElement(namespace, elementID string) (any, bool) {
	for _, doc := range r.Documents {
		if elements, ok := doc.VerifiedElements[namespace]; ok {
			if value, ok := elements[elementID]; ok {
				return value, true
			}
		}
	}
	return nil, false
}

// GetMDocElements retrieves the standard mDL elements from the result.
func (r *VerificationResult) GetMDocElements() map[string]any {
	elements := make(map[string]any)

	if nsElements, ok := r.ExtractElements()[Namespace]; ok {
		for k, v := range nsElements {
			elements[k] = v
		}
	}

	return elements
}

// VerifyAgeOver checks if the holder is over a specific age.
// Returns (true, true) if verified over age, (false, true) if verified under age,
// and (false, false) if the age attestation is not present.
func (r *VerificationResult) VerifyAgeOver(age uint) (bool, bool) {
	elementID := fmt.Sprintf("age_over_%d", age)
	value, found := r.GetElement(Namespace, elementID)
	if !found {
		return false, false
	}

	if boolVal, ok := value.(bool); ok {
		return boolVal, true
	}

	return false, false
}

// RequestBuilder builds an ItemsRequest for requesting specific data elements.
type RequestBuilder struct {
	docType     string
	namespaces  map[string]map[string]bool
	requestInfo map[string]any
}

// NewRequestBuilder creates a new RequestBuilder for the specified document type.
func NewRequestBuilder(docType string) *RequestBuilder {
	return &RequestBuilder{
		docType:     docType,
		namespaces:  make(map[string]map[string]bool),
		requestInfo: make(map[string]any),
	}
}

// AddElement adds a data element to the request.
// intentToRetain indicates whether the verifier intends to retain the data.
func (b *RequestBuilder) AddElement(namespace, elementID string, intentToRetain bool) *RequestBuilder {
	if b.namespaces[namespace] == nil {
		b.namespaces[namespace] = make(map[string]bool)
	}
	b.namespaces[namespace][elementID] = intentToRetain
	return b
}

// AddMandatoryElements adds all mandatory mDL elements to the request.
func (b *RequestBuilder) AddMandatoryElements(intentToRetain bool) *RequestBuilder {
	mandatoryElements := []string{
		"family_name",
		"given_name",
		"birth_date",
		"issue_date",
		"expiry_date",
		"issuing_country",
		"issuing_authority",
		"document_number",
		"portrait",
		"driving_privileges",
		"un_distinguishing_sign",
	}

	for _, elem := range mandatoryElements {
		b.AddElement(Namespace, elem, intentToRetain)
	}

	return b
}

// AddAgeVerification adds age verification elements to the request.
func (b *RequestBuilder) AddAgeVerification(ages ...uint) *RequestBuilder {
	for _, age := range ages {
		elementID := fmt.Sprintf("age_over_%d", age)
		b.AddElement(Namespace, elementID, false)
	}
	return b
}

// WithRequestInfo adds additional request information.
func (b *RequestBuilder) WithRequestInfo(key string, value any) *RequestBuilder {
	b.requestInfo[key] = value
	return b
}

// Build creates the ItemsRequest.
func (b *RequestBuilder) Build() *ItemsRequest {
	req := &ItemsRequest{
		DocType:    b.docType,
		NameSpaces: b.namespaces,
	}

	if len(b.requestInfo) > 0 {
		req.RequestInfo = b.requestInfo
	}

	return req
}

// BuildEncoded creates the CBOR-encoded ItemsRequest.
func (b *RequestBuilder) BuildEncoded() ([]byte, error) {
	req := b.Build()

	encoder, err := NewCBOREncoder()
	if err != nil {
		return nil, fmt.Errorf("failed to create CBOR encoder: %w", err)
	}

	data, err := encoder.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to encode items request: %w", err)
	}

	return data, nil
}

// BuildDeviceRequest creates a complete DeviceRequest with this items request.
func (b *RequestBuilder) BuildDeviceRequest() (*DeviceRequest, error) {
	encoded, err := b.BuildEncoded()
	if err != nil {
		return nil, err
	}

	return &DeviceRequest{
		Version: "1.0",
		DocRequests: []DocRequest{
			{
				ItemsRequest: encoded,
			},
		},
	}, nil
}
