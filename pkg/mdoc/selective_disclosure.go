// Package mdoc implements the ISO/IEC 18013-5:2021 Mobile Driving Licence (mDL) data model.
package mdoc

import (
	"crypto"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// SelectiveDisclosure provides methods for selectively disclosing mDL data elements.
// Per ISO 18013-5:2021 section 8.3.2.1.2.2, the mdoc holder can choose which
// data elements to release from the requested elements.
type SelectiveDisclosure struct {
	// issuerSigned contains the complete issuer-signed data
	issuerSigned *IssuerSignedMdoc
}

// NewSelectiveDisclosure creates a new SelectiveDisclosure handler from issuer-signed data.
func NewSelectiveDisclosure(issuerSigned *IssuerSignedMdoc) (*SelectiveDisclosure, error) {
	if issuerSigned == nil {
		return nil, errors.New("issuer signed data is required")
	}

	return &SelectiveDisclosure{
		issuerSigned: issuerSigned,
	}, nil
}

// iterateItems now returns true if the callback requested an early exit
func iterateItems(items []any, fn func(item IssuerSignedItem, original any) bool) bool {
	for _, anyItem := range items {
		var item IssuerSignedItem
		valid := false

		switch v := anyItem.(type) {
		case IssuerSignedItem:
			item = v
			valid = true
		case *IssuerSignedItem:
			item = *v
			valid = true
		case cbor.Tag:
			if content, ok := v.Content.([]byte); ok {
				if err := cbor.Unmarshal(content, &item); err == nil {
					valid = true
				}
			}
		}

		if valid {
			if !fn(item, anyItem) {
				return true
			}
		}
	}
	return false
}

func (sd *SelectiveDisclosure) Disclose(request map[string][]string) (*IssuerSignedMdoc, error) {
	if request == nil {
		return nil, errors.New("request is required")
	}

	disclosed := &IssuerSignedMdoc{
		NameSpaces: make(map[string][]any),
		IssuerAuth: sd.issuerSigned.IssuerAuth, // Keep the original signature/MSO
	}

	for namespace, requestedElements := range request {
		items, ok := sd.issuerSigned.NameSpaces[namespace]
		if !ok {
			continue
		}

		// Build set for O(1) lookup
		requested := make(map[string]bool)
		for _, elem := range requestedElements {
			requested[elem] = true
		}

		var disclosedItems []any

		iterateItems(items, func(item IssuerSignedItem, original any) bool {
			if requested[item.ElementIdentifier] {
				disclosedItems = append(disclosedItems, original)
			}
			return true
		})

		if len(disclosedItems) > 0 {
			disclosed.NameSpaces[namespace] = disclosedItems
		}
	}

	return disclosed, nil
}

// DiscloseFromItemsRequest creates a new IssuerSigned from an ItemsRequest.
func (sd *SelectiveDisclosure) DiscloseFromItemsRequest(request *ItemsRequest) (*IssuerSignedMdoc, error) {
	if request == nil {
		return nil, errors.New("items request is required")
	}

	// Convert ItemsRequest format to simple map
	elements := make(map[string][]string)
	for namespace, elemMap := range request.NameSpaces {
		var elemList []string
		for elem := range elemMap {
			elemList = append(elemList, elem)
		}
		elements[namespace] = elemList
	}

	return sd.Disclose(elements)
}

// GetAvailableElements returns all available elements grouped by namespace.
func (sd *SelectiveDisclosure) GetAvailableElements() map[string][]string {
	available := make(map[string][]string)

	for namespace, items := range sd.issuerSigned.NameSpaces {
		var elements []string
		iterateItems(items, func(item IssuerSignedItem, _ any) bool {
			elements = append(elements, item.ElementIdentifier)
			return true
		})

		if len(elements) > 0 {
			available[namespace] = elements
		}
	}

	return available
}

// HasElement checks if a specific element is available for disclosure.
func (sd *SelectiveDisclosure) HasElement(namespace, element string) bool {
	items, ok := sd.issuerSigned.NameSpaces[namespace]
	if !ok {
		return false
	}

	found := false
	iterateItems(items, func(item IssuerSignedItem, _ any) bool {
		if item.ElementIdentifier == element {
			found = true
			return false
		}
		return true
	})
	return found
}

// DeviceResponseBuilder builds a DeviceResponse with selective disclosure.
type DeviceResponseBuilder struct {
	docType           string
	issuerSigned      *IssuerSignedMdoc
	deviceKey         crypto.Signer
	sessionTranscript []byte
	request           *ItemsRequest
	useMAC            bool
	macKey            []byte
	errors            map[string]map[string]int
}

// NewDeviceResponseBuilder creates a new DeviceResponseBuilder.
func NewDeviceResponseBuilder(docType string) *DeviceResponseBuilder {
	return &DeviceResponseBuilder{
		docType: docType,
		errors:  make(map[string]map[string]int),
	}
}

// WithIssuerSigned sets the issuer-signed data.
func (b *DeviceResponseBuilder) WithIssuerSigned(issuerSigned *IssuerSignedMdoc) *DeviceResponseBuilder {
	b.issuerSigned = issuerSigned
	return b
}

// WithDeviceKey sets the device key for signing.
func (b *DeviceResponseBuilder) WithDeviceKey(key crypto.Signer) *DeviceResponseBuilder {
	b.deviceKey = key
	b.useMAC = false
	return b
}

// WithMACKey sets the MAC key for device authentication.
func (b *DeviceResponseBuilder) WithMACKey(key []byte) *DeviceResponseBuilder {
	b.macKey = key
	b.useMAC = true
	return b
}

// WithSessionTranscript sets the session transcript for device authentication.
func (b *DeviceResponseBuilder) WithSessionTranscript(transcript []byte) *DeviceResponseBuilder {
	b.sessionTranscript = transcript
	return b
}

// WithRequest sets the items request for selective disclosure.
func (b *DeviceResponseBuilder) WithRequest(request *ItemsRequest) *DeviceResponseBuilder {
	b.request = request
	return b
}

// AddError adds an error for a specific element.
// Error codes per ISO 18013-5:2021:
// 0 = data not returned (general)
// 10 = data element not available
// 11 = data element not releasable by holder
func (b *DeviceResponseBuilder) AddError(namespace, element string, errorCode int) *DeviceResponseBuilder {
	if b.errors[namespace] == nil {
		b.errors[namespace] = make(map[string]int)
	}
	b.errors[namespace][element] = errorCode
	return b
}

// Build creates the DeviceResponse.
func (b *DeviceResponseBuilder) Build() (*DeviceResponseMdoc, error) {
	if b.issuerSigned == nil {
		return nil, errors.New("issuer signed data is required")
	}
	if b.sessionTranscript == nil {
		return nil, errors.New("session transcript is required")
	}

	// Create selective disclosure handler
	sd, err := NewSelectiveDisclosure(b.issuerSigned)
	if err != nil {
		return nil, fmt.Errorf("failed to create selective disclosure: %w", err)
	}

	// Perform selective disclosure if request is provided
	var disclosedIssuerSigned *IssuerSignedMdoc
	if b.request != nil {
		disclosedIssuerSigned, err = sd.DiscloseFromItemsRequest(b.request)
		if err != nil {
			return nil, fmt.Errorf("failed to disclose elements: %w", err)
		}

		// Add errors for requested but unavailable elements
		for namespace, elemMap := range b.request.NameSpaces {
			for elem := range elemMap {
				if !sd.HasElement(namespace, elem) {
					b.AddError(namespace, elem, ErrorDataNotAvailable)
				}
			}
		}
	} else {
		disclosedIssuerSigned = b.issuerSigned
	}

	var deviceAuth DeviceAuthMdoc
	var deviceNameSpaces any

	if b.useMAC && b.macKey != nil {
		// Build MAC authentication
		deviceSigned, err := NewDeviceAuthBuilder(b.docType).
			WithSessionTranscript(b.sessionTranscript).
			WithSessionKey(b.macKey).
			Build()
		if err != nil {
			return nil, fmt.Errorf("failed to build device MAC: %w", err)
		}

		deviceAuth = DeviceAuthMdoc{
			DeviceMac: deviceSigned.DeviceAuth.DeviceMac,
		}
		deviceNameSpaces = deviceSigned.NameSpaces

	} else if b.deviceKey != nil {
		deviceSigned, err := NewDeviceAuthBuilder(b.docType).
			WithSessionTranscript(b.sessionTranscript).
			WithDeviceKey(b.deviceKey).
			Build()
		if err != nil {
			return nil, fmt.Errorf("failed to build device signature: %w", err)
		}

		deviceAuth = DeviceAuthMdoc{
			DeviceSignature: deviceSigned.DeviceAuth.DeviceSignature,
		}
		deviceNameSpaces = deviceSigned.NameSpaces
	} else {
		return nil, errors.New("device key or MAC key is required")
	}

	doc := &DocumentMdoc{
		DocType:      b.docType,
		IssuerSigned: *disclosedIssuerSigned,
		DeviceSigned: DeviceSignedMdoc{
			NameSpaces: deviceNameSpaces,
			DeviceAuth: deviceAuth,
		},
	}
	if len(b.errors) > 0 {
		doc.Errors = b.errors
	}

	return &DeviceResponseMdoc{
		Version:   "1.0",
		Documents: []DocumentMdoc{*doc},
		Status:    0,
	}, nil
}

// Error codes per ISO 18013-5:2021 Table 8
const (
	// ErrorDataNotReturned indicates data was not returned (general).
	ErrorDataNotReturned = 0
	// ErrorDataNotAvailable indicates the data element is not available.
	ErrorDataNotAvailable = 10
	// ErrorDataNotReleasable indicates the holder chose not to release the element.
	ErrorDataNotReleasable = 11
)

// DisclosurePolicy defines rules for automatic element disclosure decisions.
type DisclosurePolicy struct {
	// AlwaysDisclose contains elements that should always be disclosed if requested.
	AlwaysDisclose map[string][]string
	// NeverDisclose contains elements that should never be disclosed.
	NeverDisclose map[string][]string
	// RequireConfirmation contains elements requiring explicit user confirmation.
	RequireConfirmation map[string][]string
}

// NewDisclosurePolicy creates a new DisclosurePolicy.
func NewDisclosurePolicy() *DisclosurePolicy {
	return &DisclosurePolicy{
		AlwaysDisclose:      make(map[string][]string),
		NeverDisclose:       make(map[string][]string),
		RequireConfirmation: make(map[string][]string),
	}
}

// DefaultMDLDisclosurePolicy returns a sensible default policy for mDL.
func DefaultMDLDisclosurePolicy() *DisclosurePolicy {
	policy := NewDisclosurePolicy()

	// Age verification elements can typically be auto-disclosed
	policy.AlwaysDisclose[Namespace] = []string{
		"age_over_18",
		"age_over_21",
		"age_over_25",
		"age_over_65",
	}

	// Biometric data should never be auto-disclosed
	policy.NeverDisclose[Namespace] = []string{
		"biometric_template_face",
		"biometric_template_finger",
		"biometric_template_signature",
	}

	// PII requires confirmation
	policy.RequireConfirmation[Namespace] = []string{
		"family_name",
		"given_name",
		"birth_date",
		"portrait",
		"resident_address",
		"document_number",
	}

	return policy
}

// FilterRequest filters an ItemsRequest based on the disclosure policy.
// Returns the filtered request and elements that were blocked.
func (p *DisclosurePolicy) FilterRequest(request *ItemsRequest) (*ItemsRequest, map[string][]string) {
	filtered := &ItemsRequest{
		DocType:     request.DocType,
		NameSpaces:  make(map[string]map[string]bool),
		RequestInfo: request.RequestInfo,
	}
	blocked := make(map[string][]string)

	for namespace, elemMap := range request.NameSpaces {
		// Build never-disclose set for this namespace
		neverSet := make(map[string]bool)
		for _, elem := range p.NeverDisclose[namespace] {
			neverSet[elem] = true
		}

		filtered.NameSpaces[namespace] = make(map[string]bool)

		for elem, intentToRetain := range elemMap {
			if neverSet[elem] {
				blocked[namespace] = append(blocked[namespace], elem)
				continue
			}
			filtered.NameSpaces[namespace][elem] = intentToRetain
		}

		// Remove empty namespaces
		if len(filtered.NameSpaces[namespace]) == 0 {
			delete(filtered.NameSpaces, namespace)
		}
	}

	return filtered, blocked
}

// RequiresConfirmation returns elements from the request that need user confirmation.
func (p *DisclosurePolicy) RequiresConfirmation(request *ItemsRequest) map[string][]string {
	needsConfirm := make(map[string][]string)

	for namespace, elemMap := range request.NameSpaces {
		// Build confirmation set for this namespace
		confirmSet := make(map[string]bool)
		for _, elem := range p.RequireConfirmation[namespace] {
			confirmSet[elem] = true
		}

		for elem := range elemMap {
			if confirmSet[elem] {
				needsConfirm[namespace] = append(needsConfirm[namespace], elem)
			}
		}
	}

	return needsConfirm
}

// CanAutoDisclose checks if all requested elements can be auto-disclosed.
func (p *DisclosurePolicy) CanAutoDisclose(request *ItemsRequest) bool {
	for namespace, elemMap := range request.NameSpaces {
		// Build always-disclose set
		alwaysSet := make(map[string]bool)
		for _, elem := range p.AlwaysDisclose[namespace] {
			alwaysSet[elem] = true
		}

		for elem := range elemMap {
			if !alwaysSet[elem] {
				return false
			}
		}
	}

	return true
}

// EncodeDeviceResponse encodes a DeviceResponse to CBOR.
func EncodeDeviceResponse(response *DeviceResponseMdoc) ([]byte, error) {
	encoder, err := NewCBOREncoder()
	if err != nil {
		return nil, err
	}
	return encoder.Marshal(response)
}

// DecodeDeviceResponse decodes a DeviceResponse from CBOR.
func DecodeDeviceResponse(data []byte) (*DeviceResponseMdoc, error) {
	encoder, err := NewCBOREncoder()
	if err != nil {
		return nil, err
	}

	var response DeviceResponseMdoc
	if err := encoder.Unmarshal(data, &response); err != nil {
		return nil, err
	}

	return &response, nil
}
