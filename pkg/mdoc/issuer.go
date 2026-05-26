// Package mdoc provides mDL issuer logic per ISO/IEC 18013-5:2021.
package mdoc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"github.com/fxamacker/cbor/v2"
	"time"
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
}

// IssuerConfig contains configuration for creating an Issuer.
type IssuerConfig struct {
	SignerKey        crypto.Signer
	CertificateChain []*x509.Certificate
	DefaultValidity  time.Duration
	DigestAlgorithm  DigestAlgorithm
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
	}
	return issuer, nil
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

// IssuanceRequest contains the data for issuing an mDL.
type IssuanceRequest struct {
	// Holder's device public key
	DevicePublicKey crypto.PublicKey
	// mDL data elements
	MDoc *MDoc
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

// Issue creates a signed mDL document from the request.
func (i *Issuer) Issue(req *IssuanceRequest) (*IssuedDocumentMdoc, error) {
	if req.DevicePublicKey == nil {
		return nil, fmt.Errorf("device public key is required")
	}
	if req.MDoc == nil {
		return nil, fmt.Errorf("mDL data is required")
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
	builder := NewMSOBuilder(DocType).
		WithDigestAlgorithm(i.digestAlgorithm).
		WithValidity(validFrom, validUntil).
		WithDeviceKey(deviceKey).
		WithSigner(i.signerKey, i.certChain)
	// Add all mandatory data elements
	if err := i.addMandatoryElements(builder, req.MDoc); err != nil {
		return nil, fmt.Errorf("failed to add mandatory elements: %w", err)
	}
	// Add optional data elements
	if err := i.addOptionalElements(builder, req.MDoc); err != nil {
		return nil, fmt.Errorf("failed to add optional elements: %w", err)
	}
	// Add driving privileges
	if err := i.addDrivingPrivileges(builder, req.MDoc); err != nil {
		return nil, fmt.Errorf("failed to add driving privileges: %w", err)
	}
	// Build and sign the MSO
	signedMSO, issuerNameSpaces, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build MSO: %w", err)
	}
	issuerSignedNS := make(map[string][]any)
	for ns, items := range issuerNameSpaces {
		anyItems := make([]any, len(items))
		for i, item := range items {
			anyItems[i] = item
		}
		issuerSignedNS[ns] = anyItems
	}
	issuerAuthArray := []any{
		signedMSO.Protected,
		signedMSO.Unprotected,
		signedMSO.Payload,
		signedMSO.Signature,
	}

	emptySigStructure := []any{
		[]byte{},      // Protected headers (empty)
		map[any]any{}, // Unprotected headers
		nil,           // Payload (nil for detached signature)
		[]byte{},      // The actual signature bytes (empty)
	}

	// Encode the signed MSO
	encoder, err := NewCBOREncoder()
	if err != nil {
		return nil, fmt.Errorf("failed to create CBOR encoder: %w", err)
	}
	emptyMapBytes, err := encoder.Marshal(map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("failed to encode device auth: %w", err)
	}

	emptySigBytes, err := encoder.Marshal(emptySigStructure)
	if err != nil {
		return nil, err
	}
	innerDoc := &DocumentMdoc{
		DocType: DocType,
		IssuerSigned: IssuerSignedMdoc{
			NameSpaces: issuerSignedNS,
			IssuerAuth: issuerAuthArray,
		},
		DeviceSigned: DeviceSignedMdoc{
			NameSpaces: cbor.Tag{Number: 24, Content: emptyMapBytes},
			DeviceAuth: DeviceAuthMdoc{
				DeviceSignature: emptySigBytes,
			},
		},
	}
	response := &DeviceResponseMdoc{
		Version: "1.0",
		Documents: []DocumentMdoc{*innerDoc}, 
		Status:    0,
	}

	issuedDoc := &IssuedDocumentMdoc{
		DocumentMdoc: response,
		SignedMSO:    signedMSO,
		ValidFrom:    validFrom,
		ValidUntil:   validUntil,
	}
	return issuedDoc, nil
}

// addMandatoryElements adds all mandatory data elements to the builder.
func (i *Issuer) addMandatoryElements(builder *MSOBuilder, mdoc *MDoc) error {
	ns := Namespace

	// Per ISO 18013-5 Table 5, mandatory elements
	elements := map[string]any{
		"family_name":            mdoc.FamilyName,
		"given_name":             mdoc.GivenName,
		"birth_date":             mdoc.BirthDate,
		"issue_date":             mdoc.IssueDate,
		"expiry_date":            mdoc.ExpiryDate,
		"issuing_country":        mdoc.IssuingCountry,
		"issuing_authority":      mdoc.IssuingAuthority,
		"document_number":        mdoc.DocumentNumber,
		"portrait":               mdoc.Portrait,
		"driving_privileges":     mdoc.DrivingPrivileges,
		"un_distinguishing_sign": mdoc.UNDistinguishingSign,
	}

	for elementID, value := range elements {
		if err := builder.AddDataElement(ns, elementID, value); err != nil {
			return fmt.Errorf("failed to add %s: %w", elementID, err)
		}
	}

	return nil
}

// addOptionalElements adds optional data elements if present.
func (i *Issuer) addOptionalElements(builder *MSOBuilder, mdoc *MDoc) error {
	ns := Namespace

	// Add optional elements only if they have values
	optionalElements := map[string]any{
		"family_name_national_character": mdoc.FamilyNameNationalCharacter,
		"given_name_national_character":  mdoc.GivenNameNationalCharacter,
		"signature_usual_mark":           mdoc.SignatureUsualMark,
		"sex":                            mdoc.Sex,
		"height":                         mdoc.Height,
		"weight":                         mdoc.Weight,
		"eye_colour":                     mdoc.EyeColour,
		"hair_colour":                    mdoc.HairColour,
		"birth_place":                    mdoc.BirthPlace,
		"resident_address":               mdoc.ResidentAddress,
		"portrait_capture_date":          mdoc.PortraitCaptureDate,
		"age_in_years":                   mdoc.AgeInYears,
		"age_birth_year":                 mdoc.AgeBirthYear,
		"issuing_jurisdiction":           mdoc.IssuingJurisdiction,
		"nationality":                    mdoc.Nationality,
		"resident_city":                  mdoc.ResidentCity,
		"resident_state":                 mdoc.ResidentState,
		"resident_postal_code":           mdoc.ResidentPostalCode,
		"resident_country":               mdoc.ResidentCountry,
		"administrative_number":          mdoc.AdministrativeNumber,
	}

	// Add age_over attestations from the AgeOver struct
	if mdoc.AgeOver != nil {
		if mdoc.AgeOver.Over18 != nil {
			if err := builder.AddDataElement(ns, "age_over_18", *mdoc.AgeOver.Over18); err != nil {
				return fmt.Errorf("failed to add age_over_18: %w", err)
			}
		}
		if mdoc.AgeOver.Over21 != nil {
			if err := builder.AddDataElement(ns, "age_over_21", *mdoc.AgeOver.Over21); err != nil {
				return fmt.Errorf("failed to add age_over_21: %w", err)
			}
		}
		if mdoc.AgeOver.Over25 != nil {
			if err := builder.AddDataElement(ns, "age_over_25", *mdoc.AgeOver.Over25); err != nil {
				return fmt.Errorf("failed to add age_over_25: %w", err)
			}
		}
		if mdoc.AgeOver.Over65 != nil {
			if err := builder.AddDataElement(ns, "age_over_65", *mdoc.AgeOver.Over65); err != nil {
				return fmt.Errorf("failed to add age_over_65: %w", err)
			}
		}
	}

	for elementID, value := range optionalElements {
		if !isZeroValue(value) {
			if err := builder.AddDataElement(ns, elementID, value); err != nil {
				return fmt.Errorf("failed to add %s: %w", elementID, err)
			}
		}
	}

	return nil
}

// addDrivingPrivileges processes and adds driving privileges.
func (i *Issuer) addDrivingPrivileges(builder *MSOBuilder, mdoc *MDoc) error {
	// Driving privileges are already included as a mandatory element
	// This method can be extended for additional privilege processing
	return nil
}

// isZeroValue checks if a value is the zero value for its type.
func isZeroValue(v any) bool {
	if v == nil {
		return true
	}
	switch val := v.(type) {
	case string:
		return val == ""
	case []byte:
		return len(val) == 0
	case int, int8, int16, int32, int64:
		return val == 0
	case uint, uint8, uint16, uint32, uint64:
		return val == 0
	case float32:
		return val == 0
	case float64:
		return val == 0
	case bool:
		return !val
	case *bool:
		return val == nil
	case *uint:
		return val == nil
	case *string:
		return val == nil
	case time.Time:
		return val.IsZero()
	case *time.Time:
		return val == nil
	case FullDate:
		return string(val) == ""
	case TDate:
		return string(val) == ""
	default:
		return false
	}
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
