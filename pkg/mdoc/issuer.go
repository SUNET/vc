// Package mdoc provides mDL issuer logic per ISO/IEC 18013-5:2021.
package mdoc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// Issuer handles the creation and signing of mDL documents.
type Issuer struct {
	// Document Signer private key
	signerKey crypto.Signer
	// Certificate chain (DS cert first, then intermediate, then IACA root)
	certChain []*x509.Certificate
	// Default validity duration for issued credentials
	defaultValidity time.Duration
	// Digest algorithm to use
	digestAlgorithm DigestAlgorithm
	// pseudonymSeed enables attaching a random seed as the pseudonym_seed claim. Default: false.
	pseudonymSeed bool
}

// IssuerConfig contains configuration for creating an Issuer.
type IssuerConfig struct {
	SignerKey        crypto.Signer
	CertificateChain []*x509.Certificate
	DefaultValidity  time.Duration
	DigestAlgorithm  DigestAlgorithm
	PseudonymSeed    bool
}

// NewIssuer creates a new mDL issuer.
func NewIssuer(config IssuerConfig) (*Issuer, error) {
	if config.SignerKey == nil {
		return nil, fmt.Errorf("signer key is required")
	}
	if len(config.CertificateChain) == 0 {
		return nil, fmt.Errorf("at least one certificate is required")
	}

	// Validate that the signer key matches the certificate
	dsCert := config.CertificateChain[0]
	if err := validateKeyPair(config.SignerKey, dsCert); err != nil {
		return nil, fmt.Errorf("signer key does not match certificate: %w", err)
	}

	validity := config.DefaultValidity
	if validity == 0 {
		validity = 365 * 24 * time.Hour // 1 year default
	}

	digestAlg := config.DigestAlgorithm
	if digestAlg == "" {
		digestAlg = DigestAlgorithmSHA256
	}

	issuer := &Issuer{
		signerKey:       config.SignerKey,
		certChain:       config.CertificateChain,
		defaultValidity: validity,
		digestAlgorithm: digestAlg,
		pseudonymSeed:   config.PseudonymSeed,
	}
	return issuer, nil
}

// CertificateChain returns the issuer's certificate chain.
// The DS (leaf) certificate is first, followed by intermediates, then the IACA root.
func (i *Issuer) CertificateChain() []*x509.Certificate {
	return i.certChain
}

// validateKeyPair checks that the private key matches the certificate's public key.
func validateKeyPair(priv crypto.Signer, cert *x509.Certificate) error {
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		ecdsaPriv, ok := priv.(*ecdsa.PrivateKey)
		if !ok {
			return fmt.Errorf("certificate has ECDSA key but signer is not ECDSA")
		}
		if !ecdsaPriv.PublicKey.Equal(pub) {
			return fmt.Errorf("ECDSA public keys do not match")
		}
	case ed25519.PublicKey:
		ed25519Priv, ok := priv.(ed25519.PrivateKey)
		if !ok {
			return fmt.Errorf("certificate has Ed25519 key but signer is not Ed25519")
		}
		derivedPub := ed25519Priv.Public().(ed25519.PublicKey)
		if !derivedPub.Equal(pub) {
			return fmt.Errorf("Ed25519 public keys do not match")
		}
	default:
		return fmt.Errorf("unsupported key type: %T", pub)
	}
	return nil
}

// IssuanceRequest contains the data for issuing an mdoc credential.
type IssuanceRequest struct {
	// Holder's device public key
	DevicePublicKey crypto.PublicKey
	// DocumentData is the credential subject data as raw JSON, keyed by
	// element identifier (e.g. {"family_name": "...", "birth_date": "..."}).
	// Its shape is driven entirely by Schema — the issuer never needs a
	// doctype-specific Go struct.
	DocumentData []byte
	// Schema describes the document type, namespace(s), mandatory/optional
	// claims, and value encoding for this issuance (the mdoc analogue of an
	// SD-JWT VCTM).
	Schema *MDDLSchema
	// Custom validity period (optional)
	ValidFrom  *time.Time
	ValidUntil *time.Time
}

// IssuedDocumentMdoc contains the issued mDL document.
type IssuedDocumentMdoc struct {
	// The complete Document structure ready for transmission
	DocumentMdoc *DeviceResponseMdoc
	// The signed MSO
	SignedMSO *COSESign1
	// Validity information
	ValidFrom  time.Time
	ValidUntil time.Time
}

// Issue creates a signed mdoc document from the request.
func (i *Issuer) Issue(req *IssuanceRequest) (*IssuedDocumentMdoc, error) {
	if req == nil {
		return nil, fmt.Errorf("IssuanceRequest must not be nil")
	}

	// Accumulator for document errors instead of throwing hard Go app errors
	var documentErrors []DocumentError
	var documents []DocumentMdoc
	if req.DevicePublicKey == nil {
		return nil, fmt.Errorf("device public key is required")
	}
	if req.Schema == nil {
		return nil, fmt.Errorf("schema is required")
	}
	if len(req.DocumentData) == 0 {
		return nil, fmt.Errorf("document data is required")
	}

	var doc map[string]any
	if err := json.Unmarshal(req.DocumentData, &doc); err != nil {
		return nil, fmt.Errorf("parse document data: %w", err)
	}

	if err := i.injectPseudonymSeed(req.Schema, doc); err != nil {
		return nil, fmt.Errorf("inject pseudonym seed: %w", err)
	}

	// Convert device public key to COSE key
	deviceKey, err := publicKeyToCOSEKey(req.DevicePublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert device key: %w", err)
	}

	// Determine validity period
	validFrom := time.Now().UTC()
	if req.ValidFrom != nil {
		validFrom = req.ValidFrom.UTC()
	}
	validUntil := validFrom.Add(i.defaultValidity)
	if req.ValidUntil != nil {
		validUntil = req.ValidUntil.UTC()
	}

	// Build the MSO
	builder := NewMSOBuilder(req.Schema.DocType).
		WithDigestAlgorithm(i.digestAlgorithm).
		WithValidity(validFrom, validUntil).
		WithDeviceKey(deviceKey).
		WithSigner(i.signerKey, i.certChain)

	// Add every claim declared by the schema, across all of its namespaces.
	// This one generic pass replaces per-doctype element lists: adding a new
	// mdoc document type requires only a new MDDL schema, never a Go change.
	if err := i.addElements(builder, req.Schema, doc); err != nil {
		return nil, fmt.Errorf("add elements: %w", err)
	}

	// Build and sign the MSO
	signedMSO, issuerNameSpaces, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("build signed MSO: %w", err)
	}

	// Encode the signed MSO elements
	encoder, err := NewCBOREncoder()
	if err != nil {
		// Code 0 = Data Not Available / Generation Failure
		return nil, fmt.Errorf("create CBOR encoder: %w", err)
	}

	emptyMapBytes, err := encoder.Marshal(map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("failed to encode device auth: %w", err)
	}

	issuerSignedNS := make(map[string][]any)
	for ns, items := range issuerNameSpaces {
		anyItems := make([]any, len(items))
		for idx, item := range items {
			anyItems[idx] = item
		}
		issuerSignedNS[ns] = anyItems
	}
	issuerAuthArray := []any{
		signedMSO.Protected,
		signedMSO.Unprotected,
		signedMSO.Payload,
		signedMSO.Signature,
	}
	deviceAlg, err := AlgorithmForKey(req.DevicePublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to determine device key algorithm: %w", err)
	}

	deviceProtectedHeader, err := encoder.Marshal(map[int64]any{HeaderAlgorithm: deviceAlg})
	if err != nil {
		return nil, fmt.Errorf("failed to encode device protected header: %w", err)
	}

	deviceSigArray := []any{
		deviceProtectedHeader, // Protected — alg derived from the actual device key
		map[string]any{},      // Unprotected
		nil,                   // Payload (detached)
		[]byte{},              // Empty signature placeholder
	}
	// Everything encoded successfully: build response containing the document
	innerDoc := DocumentMdoc{
		DocType: req.Schema.DocType,
		IssuerSigned: IssuerSignedMdoc{
			NameSpaces: issuerSignedNS,
			IssuerAuth: issuerAuthArray,
		},
		DeviceSigned: DeviceSignedMdoc{
			NameSpaces: cbor.Tag{Number: 24, Content: emptyMapBytes},
			DeviceAuth: DeviceAuthMdoc{
				DeviceSignature: deviceSigArray, // Dynamic wallet signature placeholder
			},
		},
	}
	documents = append(documents, innerDoc)

	if len(documents) == 0 {
		documentErrors = append(documentErrors, DocumentError{DocType: 0})

		response := &DeviceResponseMdoc{
			Version:        "1.0",
			DocumentErrors: documentErrors,
			Status:         0,
		}

		return &IssuedDocumentMdoc{
			DocumentMdoc: response,
			SignedMSO:    nil,
			ValidFrom:    validFrom,
			ValidUntil:   validUntil,
		}, nil
	}
	response := &DeviceResponseMdoc{
		Version:   "1.0",
		Documents: documents,
		Status:    0,
		// documentErrors remains nil/empty and is cleanly dropped by omitempty tags
	}

	issuedDoc := &IssuedDocumentMdoc{
		DocumentMdoc: response,
		SignedMSO:    signedMSO,
		ValidFrom:    validFrom,
		ValidUntil:   validUntil,
	}
	return issuedDoc, nil
}

// addElements walks every namespace and claim declared by the schema and, for
// each claim present in doc, converts its value per the claim's declared CDDL
// value_type and adds it to the builder. Missing mandatory claims are an
// error; missing optional claims are silently skipped. This single function
// serves every mdoc document type — there is no per-doctype branching here.
func (i *Issuer) addElements(builder *MSOBuilder, schema *MDDLSchema, doc map[string]any) error {
	for namespace, elements := range schema.Claims {
		for elementID, meta := range elements {
			raw, present := doc[elementID]
			if !present || raw == nil {
				if meta.Mandatory {
					return fmt.Errorf("missing mandatory claim %q", elementID)
				}
				continue
			}

			value, err := convertElementValue(meta, raw)
			if err != nil {
				return fmt.Errorf("convert claim %q: %w", elementID, err)
			}
			if err := builder.AddDataElement(namespace, elementID, value); err != nil {
				return fmt.Errorf("failed to add %s: %w", elementID, err)
			}
		}
	}
	return nil
}

// convertElementValue converts a JSON-decoded value into the Go
// representation fxamacker/cbor needs to encode it per ISO 18013-5: full-date
// and tdate values are tagged strings, bstr values are raw bytes (accepted as
// base64 in the source JSON). "array"/"map" claims recurse into meta.Elements
// so nested fields (e.g. driving_privileges[].issue_date declared as
// full-date) get the same conversion applied. Any value_type without
// declared Elements, and any other value_type (tstr, bool, ...), passes
// through unchanged.
func convertElementValue(meta ClaimMetadata, raw any) (any, error) {
	switch meta.ValueType {
	case "array":
		if len(meta.Elements) == 0 {
			return raw, nil
		}
		arr, ok := raw.([]any)
		if !ok {
			return nil, fmt.Errorf("expected array, got %T", raw)
		}
		result := make([]any, len(arr))
		for idx, item := range arr {
			itemMap, ok := item.(map[string]any)
			if !ok {
				result[idx] = item
				continue
			}
			converted, err := convertMapFields(meta.Elements, itemMap)
			if err != nil {
				return nil, fmt.Errorf("array item %d: %w", idx, err)
			}
			result[idx] = converted
		}
		return result, nil
	case "map":
		if len(meta.Elements) == 0 {
			return raw, nil
		}
		m, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("expected map, got %T", raw)
		}
		return convertMapFields(meta.Elements, m)
	case "full-date":
		s, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("expected string for full-date, got %T", raw)
		}
		return FullDate(s), nil
	case "tdate":
		s, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("expected string for tdate, got %T", raw)
		}
		return TDate(s), nil
	case "bstr":
		if b, ok := raw.([]byte); ok {
			return b, nil
		}
		s, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("expected base64 string for bstr, got %T", raw)
		}
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("decode bstr base64: %w", err)
		}
		return b, nil
	case "int":
		f, ok := raw.(float64)
		if !ok {
			return nil, fmt.Errorf("expected number for int, got %T", raw)
		}
		if f != math.Trunc(f) || f < math.MinInt64 || f > math.MaxInt64 {
			return nil, fmt.Errorf("value %v is not a valid int64", raw)
		}
		return int64(f), nil
	case "uint":
		f, ok := raw.(float64)
		if !ok {
			return nil, fmt.Errorf("expected number for uint, got %T", raw)
		}
		if f != math.Trunc(f) || f < 0 || f > math.MaxUint64 {
			return nil, fmt.Errorf("value %v is not a valid uint64", raw)
		}
		return uint64(f), nil
	default:
		// "tstr", "bool", schema-less "array"/"map", and any unrecognized
		// type pass through as-is — CBOR encoding recurses through nested
		// Go maps/slices correctly on its own.
		return raw, nil
	}
}

// convertMapFields converts each field of m per its declared schema in
// elementsSchema, recursing through convertElementValue, and enforces that
// mandatory schema fields (e.g. driving_privileges.elements.vehicle_category_code)
// are present. Fields with no matching schema entry pass through unchanged.
func convertMapFields(elementsSchema map[string]ClaimMetadata, m map[string]any) (map[string]any, error) {
	result := make(map[string]any, len(m))
	for key, fieldMeta := range elementsSchema {
		val, present := m[key]
		if !present || val == nil {
			if fieldMeta.Mandatory {
				return nil, fmt.Errorf("missing mandatory field %q", key)
			}
			continue
		}
		converted, err := convertElementValue(fieldMeta, val)
		if err != nil {
			return nil, fmt.Errorf("field %q: %w", key, err)
		}
		result[key] = converted
	}
	for key, val := range m {
		if _, declared := elementsSchema[key]; !declared {
			result[key] = val
		}
	}
	return result, nil
}

// injectPseudonymSeed generates a fresh pseudonym seed when the issuer is
// configured for it and the schema declares "pseudonym_seed" as a claim in
// some namespace but the caller didn't already supply one. This keeps the
// toggle decoupled from any namespace/doctype: it is driven purely by
// whether the schema opts in to the claim.
func (i *Issuer) injectPseudonymSeed(schema *MDDLSchema, doc map[string]any) error {
	if !i.pseudonymSeed {
		return nil
	}
	if _, present := doc["pseudonym_seed"]; present {
		return nil
	}
	declared := false
	for _, elements := range schema.Claims {
		if _, ok := elements["pseudonym_seed"]; ok {
			declared = true
			break
		}
	}
	if !declared {
		return nil
	}

	// Must stay 32 bytes - zk-cred-longfellow's native PPID witnessing
	// explicitly validates this ("pseudonym_seed value is not a valid
	// 32-byte CBOR byte string"), confirmed live: shrinking it (previously
	// tried at 12 bytes here) is rejected outright by that check, it is not
	// just a hashing-budget question. The item's overall
	// IssuerSignedItemBytes size (separately measured against the V8
	// circuits' ~119-byte per-attribute SHA-256 witnessing ceiling) must be
	// brought down some other way if it still overflows with a full 32-byte
	// seed - see this function's git history/PR discussion for the current
	// state of that investigation.
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return fmt.Errorf("failed to generate pseudonym seed: %w", err)
	}
	doc["pseudonym_seed"] = seed
	return nil
}

// publicKeyToCOSEKey converts a crypto.PublicKey to a COSEKey.
func publicKeyToCOSEKey(pub crypto.PublicKey) (*COSEKey, error) {
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		return NewCOSEKeyFromECDSAPublic(key)
	case ed25519.PublicKey:
		return NewCOSEKeyFromEd25519Public(key)
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", pub)
	}
}

// NewCOSEKeyFromECDSAPublic creates a COSE key from an ECDSA public key.
func NewCOSEKeyFromECDSAPublic(pub *ecdsa.PublicKey) (*COSEKey, error) {
	var crv int64
	switch pub.Curve {
	case elliptic.P256():
		crv = CurveP256
	case elliptic.P384():
		crv = CurveP384
	case elliptic.P521():
		crv = CurveP521
	default:
		return nil, fmt.Errorf("unsupported curve")
	}

	key := &COSEKey{
		Kty: KeyTypeEC2,
		Crv: crv,
		X:   pub.X.Bytes(),
		Y:   pub.Y.Bytes(),
	}
	return key, nil
}

// NewCOSEKeyFromEd25519Public creates a COSE key from an Ed25519 public key.
func NewCOSEKeyFromEd25519Public(pub ed25519.PublicKey) (*COSEKey, error) {
	key := &COSEKey{
		Kty: KeyTypeOKP,
		Crv: CurveEd25519,
		X:   []byte(pub),
	}
	return key, nil
}

// convertToIssuerSignedItems converts IssuerNameSpaces to the format expected by IssuerSigned.
func convertToIssuerSignedItems(ins IssuerNameSpaces, encoder *CBOREncoder) map[string][]IssuerSignedItem {
	reply := make(map[string][]IssuerSignedItem)
	for ns, taggedItems := range ins {
		items := make([]IssuerSignedItem, 0, len(taggedItems))
		for _, tagged := range taggedItems {
			var item MSOIssuerSignedItem
			if err := encoder.Unmarshal(tagged.Data, &item); err != nil {
				continue
			}
			items = append(items, IssuerSignedItem{
				DigestID:          item.DigestID,
				Random:            item.Random,
				ElementIdentifier: item.ElementID,
				ElementValue:      item.ElementValue,
			})
		}
		reply[ns] = items
	}
	return reply
}

// convertNameSpaces converts IssuerNameSpaces to raw bytes format.
func convertNameSpaces(ins IssuerNameSpaces) map[string][][]byte {
	result := make(map[string][][]byte)
	for ns, items := range ins {
		byteItems := make([][]byte, len(items))
		for i, item := range items {
			byteItems[i] = item.Data
		}
		result[ns] = byteItems
	}
	return result
}

// GenerateDeviceKeyPair generates a new device key pair for mDL holder.
func GenerateDeviceKeyPair(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(curve, rand.Reader)
}

// GenerateDeviceKeyPairEd25519 generates a new Ed25519 device key pair.
func GenerateDeviceKeyPairEd25519() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// BatchIssuanceRequest contains multiple mDL issuance requests.
type BatchIssuanceRequest struct {
	Requests []IssuanceRequest
}

// BatchIssuanceResult contains results from batch issuance.
type BatchIssuanceResult struct {
	Issued []IssuedDocumentMdoc
	Errors []error
}

// IssueBatch issues multiple mDL documents.
func (i *Issuer) IssueBatch(batch BatchIssuanceRequest) *BatchIssuanceResult {
	result := &BatchIssuanceResult{
		Issued: make([]IssuedDocumentMdoc, 0, len(batch.Requests)),
		Errors: make([]error, 0),
	}

	for idx, req := range batch.Requests {
		issued, err := i.Issue(&req)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("request %d failed: %w", idx, err))
			continue
		}
		result.Issued = append(result.Issued, *issued)
	}

	return result
}

// RevokeDocument marks a document for revocation (placeholder for status list integration).
func (i *Issuer) RevokeDocument(documentNumber string) error {
	// This would integrate with a token status list or similar mechanism
	// per ISO 18013-5 and related specifications
	return fmt.Errorf("revocation not implemented - integrate with token status list")
}

// GetIssuerInfo returns information about the issuer configuration.
type IssuerInfo struct {
	SubjectDN       string
	IssuerDN        string
	NotBefore       time.Time
	NotAfter        time.Time
	KeyAlgorithm    string
	DigestAlgorithm DigestAlgorithm
	CertChainLength int
}

// GetInfo returns information about the issuer.
func (i *Issuer) GetInfo() IssuerInfo {
	dsCert := i.certChain[0]

	keyAlg := "unknown"
	switch dsCert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		keyAlg = "ECDSA"
	case ed25519.PublicKey:
		keyAlg = "Ed25519"
	}

	return IssuerInfo{
		SubjectDN:       dsCert.Subject.String(),
		IssuerDN:        dsCert.Issuer.String(),
		NotBefore:       dsCert.NotBefore,
		NotAfter:        dsCert.NotAfter,
		KeyAlgorithm:    keyAlg,
		DigestAlgorithm: i.digestAlgorithm,
		CertChainLength: len(i.certChain),
	}
}

// ParseDeviceKey parses a device public key from various formats.
func ParseDeviceKey(data []byte, format string) (crypto.PublicKey, error) {
	switch format {
	case "der", "DER":
		return x509.ParsePKIXPublicKey(data)
	case "cose", "COSE":
		encoder, err := NewCBOREncoder()
		if err != nil {
			return nil, fmt.Errorf("failed to create CBOR encoder: %w", err)
		}
		var coseKey COSEKey
		if err := encoder.Unmarshal(data, &coseKey); err != nil {
			return nil, fmt.Errorf("failed to parse COSE key: %w", err)
		}
		return coseKey.ToPublicKey()
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}
