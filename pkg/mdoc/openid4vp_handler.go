package mdoc

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/fxamacker/cbor/v2"
	"strings"

	"github.com/SUNET/vc/pkg/trust"
)

// MDocHandler handles mdoc format credentials in OpenID4VP flows.
type MDocHandler struct {
	verifier       *Verifier
	trustEvaluator trust.TrustEvaluator
}

// MDocHandlerOption configures an MDocHandler.
type MDocHandlerOption func(*MDocHandler)

// WithMDocTrustEvaluator sets the trust evaluator for mdoc verification.
// This is the preferred way to configure trust - it delegates to go-trust
// which can use mdociaca, ETSI TSL, OpenID Federation, etc.
func WithMDocTrustEvaluator(te trust.TrustEvaluator) MDocHandlerOption {
	return func(h *MDocHandler) {
		h.trustEvaluator = te
	}
}

// WithMDocVerifier sets a pre-configured verifier.
func WithMDocVerifier(v *Verifier) MDocHandlerOption {
	return func(h *MDocHandler) {
		h.verifier = v
	}
}

// NewMDocHandler creates a new mdoc handler for OpenID4VP.
// Either WithMDocTrustEvaluator or WithMDocVerifier must be provided.
func NewMDocHandler(opts ...MDocHandlerOption) (*MDocHandler, error) {
	h := &MDocHandler{}

	for _, opt := range opts {
		opt(h)
	}

	// Create verifier if not provided
	if h.verifier == nil {
		if h.trustEvaluator == nil {
			return nil, errors.New("either TrustEvaluator or pre-configured Verifier is required")
		}
		var err error
		h.verifier, err = NewVerifier(VerifierConfig{
			TrustEvaluator: h.trustEvaluator,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create verifier: %w", err)
		}
	}

	return h, nil
}

// VerifyAndExtract verifies an mdoc VP token and extracts the disclosed claims.
// The vpToken should be the base64url-encoded DeviceResponse.
func (h *MDocHandler) VerifyAndExtract(ctx context.Context, vpToken string) (*MDocVerificationResult, error) {
	// Decode the VP token (base64url-encoded DeviceResponse)
	data, err := base64.RawURLEncoding.DecodeString(vpToken)
	if err != nil {
		// Try standard base64
		data, err = base64.StdEncoding.DecodeString(vpToken)
		if err != nil {
			return nil, fmt.Errorf("failed to decode mdoc VP token: %w", err)
		}
	}

	encoder, err := NewCBOREncoder()
	if err != nil {
		return nil, err
	}

	var deviceResponse *DeviceResponseMdoc
	if err := encoder.Unmarshal(data, &deviceResponse); err != nil {
		return nil, err
	}

	// Verify the device response
	verifyResult := h.verifier.VerifyDeviceResponse(deviceResponse)

	// Check if verification failed
	if !verifyResult.Valid {
		errMsgs := make([]string, 0, len(verifyResult.Errors))
		for _, e := range verifyResult.Errors {
			errMsgs = append(errMsgs, e.Error())
		}
		return nil, fmt.Errorf("mdoc verification failed: %s", strings.Join(errMsgs, "; "))
	}

	// Extract claims from verified documents
	result := &MDocVerificationResult{
		Valid:     true,
		Documents: make(map[string]*MDocDocumentClaims),
	}

	for i := range deviceResponse.Documents {
		doc, ok := deviceResponse.Documents[i].(*DocumentMdoc)
		if !ok {
			return nil, fmt.Errorf("document at index %d is not a valid DocumentMdoc", i)
		}

		claims, err := h.extractDocumentClaims(doc)
		if err != nil {
			return nil, fmt.Errorf("failed to extract claims from %s: %w", doc.DocType, err)
		}

		result.Documents[doc.DocType] = claims
	}
	return result, nil
}

// MDocVerificationResult contains the result of mdoc verification and claim extraction.
type MDocVerificationResult struct {
	Valid     bool
	Documents map[string]*MDocDocumentClaims
}

// MDocDocumentClaims contains the claims from a single mdoc document.
type MDocDocumentClaims struct {
	DocType    string
	Namespaces map[string]map[string]any
}

// GetClaims returns a flat map of all claims from all namespaces.
func (dc *MDocDocumentClaims) GetClaims() map[string]any {
	claims := make(map[string]any)
	for ns, nsItems := range dc.Namespaces {
		for key, value := range nsItems {
			// Use qualified name to avoid collisions across different namespaces.
			qualifiedKey := fmt.Sprintf("%s.%s", ns, key)
			claims[qualifiedKey] = value

			// Also add unqualified name for the primary namespace.
			if ns == Namespace {
				claims[key] = value
			}
		}
	}
	return claims
}

// extractDocumentClaims extracts claims from a verified document.
func (h *MDocHandler) extractDocumentClaims(doc *DocumentMdoc) (*MDocDocumentClaims, error) {
	claims := &MDocDocumentClaims{
		DocType:    doc.DocType,
		Namespaces: make(map[string]map[string]any),
	}

	for ns, items := range doc.IssuerSigned.NameSpaces {
		nsClaims := make(map[string]any)
		for _, anyItem := range items {
			item, ok := anyItem.(IssuerSignedItem)
			if !ok {
				if pItem, ok := anyItem.(*IssuerSignedItem); ok {
					item = *pItem
				} else {
					continue
				}
			}

			nsClaims[item.ElementIdentifier] = item.ElementValue
		}
		claims.Namespaces[ns] = nsClaims
	}

	return claims, nil
}

// IsMDocFormat checks if the VP token appears to be in mdoc format.
// It tries to decode and check for CBOR structure.
func IsMDocFormat(vpToken string) bool {
	// mdoc tokens are base64url-encoded CBOR, not JSON/JWT
	// Quick check: JWT has 3 parts separated by dots
	if strings.Count(vpToken, ".") >= 2 {
		return false // Likely JWT format
	}

	// Try to decode and check first byte for CBOR
	data, err := base64.RawURLEncoding.DecodeString(vpToken)
	if err != nil {
		data, err = base64.StdEncoding.DecodeString(vpToken)
		if err != nil {
			return false
		}
	}

	// Check for CBOR map (0xa0-0xbf) or array (0x80-0x9f) as first byte
	if len(data) > 0 {
		firstByte := data[0]
		return (firstByte >= 0x80 && firstByte <= 0x9f) || // CBOR array
			(firstByte >= 0xa0 && firstByte <= 0xbf) // CBOR map
	}

	return false
}

// ExtractMDocClaims extracts claims from an mdoc VP token without full verification.
func ExtractMDocClaims(vpToken string) (map[string]any, error) {
	// Decode the VP Token
	data, err := base64.RawURLEncoding.DecodeString(vpToken)
	if err != nil {
		return nil, err
	}

	// Parse the device response
	deviceResponse, err := DecodeDeviceResponse(data)
	if err != nil {
		return nil, err
	}

	claims := make(map[string]any)
	for _, anyDoc := range deviceResponse.Documents {
		var doc DocumentMdoc
		switch v := anyDoc.(type) {
		case *DocumentMdoc:
			doc = *v
		case DocumentMdoc:
			doc = v
		case map[any]any:
			b, _ := cbor.Marshal(v)
			cbor.Unmarshal(b, &doc)
		}

		for ns, items := range doc.IssuerSigned.NameSpaces {
			for _, anyItem := range items {
				var item IssuerSignedItem

				if tag, ok := anyItem.(cbor.Tag); ok {
					content, _ := tag.Content.([]byte)
					if err := cbor.Unmarshal(content, &item); err != nil {
						continue
					}
				} else {
					continue
				}

				claims[fmt.Sprintf("%s.%s", ns, item.ElementIdentifier)] = item.ElementValue
				if ns == "org.iso.18013.5.1" {
					claims[item.ElementIdentifier] = item.ElementValue
				}
			}
		}
	}
	return claims, nil
}

// MDocClaimMapping provides standard mappings from mdoc claims to OIDC claims.
var MDocClaimMapping = map[string]string{
	// ISO 18013-5 mDL to OIDC mapping
	"family_name":                    "family_name",
	"given_name":                     "given_name",
	"birth_date":                     "birthdate",
	"portrait":                       "picture",
	"issue_date":                     "iat",
	"expiry_date":                    "exp",
	"issuing_country":                "issuing_country",
	"issuing_authority":              "issuing_authority",
	"document_number":                "document_number",
	"driving_privileges":             "driving_privileges",
	"un_distinguishing_sign":         "un_distinguishing_sign",
	"administrative_number":          "administrative_number",
	"sex":                            "gender",
	"height":                         "height",
	"weight":                         "weight",
	"eye_colour":                     "eye_color",
	"hair_colour":                    "hair_color",
	"birth_place":                    "place_of_birth",
	"resident_address":               "address",
	"resident_city":                  "locality",
	"resident_state":                 "region",
	"resident_postal_code":           "postal_code",
	"resident_country":               "country",
	"age_in_years":                   "age",
	"age_birth_year":                 "birth_year",
	"age_over_18":                    "age_over_18",
	"age_over_21":                    "age_over_21",
	"issuing_jurisdiction":           "issuing_jurisdiction",
	"nationality":                    "nationality",
	"family_name_national_character": "family_name_native",
	"given_name_national_character":  "given_name_native",
}

// MapMDocToOIDC maps mdoc claims to OIDC claims using the standard mapping.
func MapMDocToOIDC(mdocClaims map[string]any) map[string]any {
	oidcClaims := make(map[string]any)

	for mdocKey, value := range mdocClaims {
		// Check if there's a direct mapping
		if oidcKey, ok := MDocClaimMapping[mdocKey]; ok {
			oidcClaims[oidcKey] = value
		} else {
			// Pass through unmapped claims
			oidcClaims[mdocKey] = value
		}
	}

	return oidcClaims
}
