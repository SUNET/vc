// Package etsi119602 implements ETSI TS 119 602-1 Lists of Trusted Entities (LoTE).
//
// The JSON types in this package conform to the official ETSI TS 119 602-1
// JSON schema (1960201_json_schema.json). The XML representation uses
// XSD-generated types from the xmltypes sub-package.
//
// A LoTE document root is wrapped in a {"LoTE": {...}} envelope per the schema.
// A LoTL (List of Trusted Lists) is a LoTE whose LoTEType identifies it as a
// list-of-lists and whose PointersToOtherLoTE is populated instead of
// TrustedEntitiesList.
package etsi119602

import (
	"encoding/json"
	"fmt"
	"os"
)

// --- Root document wrapper ---

// LoTEDocument is the JSON root envelope per ETSI TS 119 602-1 schema.
// The official schema requires: {"LoTE": {"ListAndSchemeInformation": {...}, ...}}.
type LoTEDocument struct {
	LoTE ListOfTrustedEntities `json:"LoTE"`
}

// --- Core types matching ETSI TS 119 602-1 JSON schema ---

// ListOfTrustedEntities is the core LoTE structure per ETSI TS 119 602-1.
// Used for both LoTE and LoTL documents.
type ListOfTrustedEntities struct {
	// LOTETag is the XML LOTETag attribute value. Not part of JSON schema.
	LOTETag string `json:"-"`

	ListAndSchemeInformation ListAndSchemeInformation `json:"ListAndSchemeInformation"`
	TrustedEntitiesList      []TrustedEntity          `json:"TrustedEntitiesList,omitempty"`
}

// ListAndSchemeInformation contains metadata about the trust list and its operator.
type ListAndSchemeInformation struct {
	LoTEVersionIdentifier       int                       `json:"LoTEVersionIdentifier"`
	LoTESequenceNumber          int                       `json:"LoTESequenceNumber"`
	LoTEType                    string                    `json:"LoTEType,omitempty"`
	SchemeOperatorName          NameSet                   `json:"SchemeOperatorName"`
	SchemeOperatorAddress       *SchemeOperatorAddress    `json:"SchemeOperatorAddress,omitempty"`
	SchemeName                  NameSet                   `json:"SchemeName,omitempty"`
	SchemeInformationURI        []NonEmptyMultiLangURI    `json:"SchemeInformationURI,omitempty"`
	StatusDeterminationApproach string                    `json:"StatusDeterminationApproach,omitempty"`
	SchemeTypeCommunityRules    []NonEmptyMultiLangURI    `json:"SchemeTypeCommunityRules,omitempty"`
	SchemeTerritory             string                    `json:"SchemeTerritory,omitempty"`
	PolicyOrLegalNotice         []PolicyOrLegalNoticeItem `json:"PolicyOrLegalNotice,omitempty"`
	HistoricalInformationPeriod *int                      `json:"HistoricalInformationPeriod,omitempty"`
	PointersToOtherLoTE         []OtherLoTEPointer        `json:"PointersToOtherLoTE,omitempty"`
	ListIssueDateTime           string                    `json:"ListIssueDateTime"`
	NextUpdate                  string                    `json:"NextUpdate"`
	DistributionPoints          []string                  `json:"DistributionPoints,omitempty"`
	SchemeExtensions            []json.RawMessage         `json:"SchemeExtensions,omitempty"`
}

// --- Multi-language types ---

// MultiLangString is a string value with a language tag.
type MultiLangString struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// NameSet is an ordered list of names in different languages.
type NameSet []MultiLangString

// Get returns the name for the given language, or the fallback if not found.
func (ns NameSet) Get(lang, fallback string) string {
	for _, n := range ns {
		if n.Lang == lang {
			return n.Value
		}
	}
	if len(ns) > 0 {
		return ns[0].Value
	}
	return fallback
}

// NonEmptyMultiLangURI is a URI with a language tag.
type NonEmptyMultiLangURI struct {
	Lang     string `json:"lang"`
	URIValue string `json:"uriValue"`
}

// --- Address types ---

// SchemeOperatorAddress contains postal and electronic addresses for the scheme operator.
type SchemeOperatorAddress struct {
	SchemeOperatorPostalAddress     []PostalAddress        `json:"SchemeOperatorPostalAddress"`
	SchemeOperatorElectronicAddress []NonEmptyMultiLangURI `json:"SchemeOperatorElectronicAddress"`
}

// PostalAddress represents a physical address.
type PostalAddress struct {
	Lang            string `json:"lang"`
	StreetAddress   string `json:"StreetAddress"`
	Locality        string `json:"Locality,omitempty"`
	StateOrProvince string `json:"StateOrProvince,omitempty"`
	PostalCode      string `json:"PostalCode,omitempty"`
	Country         string `json:"Country"`
}

// TEAddress contains postal and electronic addresses for a trusted entity.
type TEAddress struct {
	TEPostalAddress     []PostalAddress        `json:"TEPostalAddress"`
	TEElectronicAddress []NonEmptyMultiLangURI `json:"TEElectronicAddress"`
}

// --- Policy types ---

// PolicyOrLegalNoticeItem represents a policy URI or legal notice text.
type PolicyOrLegalNoticeItem struct {
	LoTEPolicy      *NonEmptyMultiLangURI `json:"LoTEPolicy,omitempty"`
	LoTELegalNotice string                `json:"LoTELegalNotice,omitempty"`
}

// --- Pointer types ---

// OtherLoTEPointer references another LoTE or LoTL.
type OtherLoTEPointer struct {
	LoTELocation             string                   `json:"LoTELocation"`
	ServiceDigitalIdentities []ServiceDigitalIdentity `json:"ServiceDigitalIdentities"`
	LoTEQualifiers           []LoTEQualifier          `json:"LoTEQualifiers"`
}

// LoTEQualifier qualifies a pointer to another LoTE.
type LoTEQualifier struct {
	LoTEType                 string                 `json:"LoTEType"`
	SchemeOperatorName       NameSet                `json:"SchemeOperatorName"`
	SchemeTypeCommunityRules []NonEmptyMultiLangURI `json:"SchemeTypeCommunityRules,omitempty"`
	SchemeTerritory          string                 `json:"SchemeTerritory,omitempty"`
	MimeType                 string                 `json:"MimeType"`
}

// --- Digital identity types ---

// ServiceDigitalIdentity contains keys/certificates identifying an entity or service.
type ServiceDigitalIdentity struct {
	X509Certificates []PKIOb          `json:"X509Certificates,omitempty"`
	X509SubjectNames []string         `json:"X509SubjectNames,omitempty"`
	PublicKeyValues  []map[string]any `json:"PublicKeyValues,omitempty"`
	X509SKIs         []string         `json:"X509SKIs,omitempty"`
	OtherIds         []string         `json:"OtherIds,omitempty"`
}

// PKIOb represents a PKI object (e.g. X.509 certificate).
type PKIOb struct {
	Encoding string `json:"encoding,omitempty"`
	SpecRef  string `json:"specRef,omitempty"`
	Val      string `json:"val"`
}

// --- Trusted entity types ---

// TrustedEntity represents a single trusted entity in the list.
type TrustedEntity struct {
	TrustedEntityInformation TrustedEntityInformation `json:"TrustedEntityInformation"`
	TrustedEntityServices    []TrustedEntityService   `json:"TrustedEntityServices"`
}

// TrustedEntityInformation contains entity metadata.
type TrustedEntityInformation struct {
	TEName                  NameSet                `json:"TEName"`
	TETradeName             NameSet                `json:"TETradeName,omitempty"`
	TEAddress               *TEAddress             `json:"TEAddress"`
	TEInformationURI        []NonEmptyMultiLangURI `json:"TEInformationURI"`
	TEInformationExtensions []json.RawMessage      `json:"TEInformationExtensions,omitempty"`
}

// TrustedEntityService describes a trust service provided by an entity.
type TrustedEntityService struct {
	ServiceInformation ServiceInformation       `json:"ServiceInformation"`
	ServiceHistory     []ServiceHistoryInstance `json:"ServiceHistory,omitempty"`
}

// ServiceInformation contains service metadata.
type ServiceInformation struct {
	ServiceName                  NameSet                 `json:"ServiceName"`
	ServiceDigitalIdentity       ServiceDigitalIdentity  `json:"ServiceDigitalIdentity"`
	ServiceTypeIdentifier        string                  `json:"ServiceTypeIdentifier,omitempty"`
	ServiceStatus                string                  `json:"ServiceStatus,omitempty"`
	StatusStartingTime           string                  `json:"StatusStartingTime,omitempty"`
	SchemeServiceDefinitionURI   []NonEmptyMultiLangURI  `json:"SchemeServiceDefinitionURI,omitempty"`
	ServiceSupplyPoints          []ServiceSupplyPointURI `json:"ServiceSupplyPoints,omitempty"`
	ServiceDefinitionURI         []NonEmptyMultiLangURI  `json:"ServiceDefinitionURI,omitempty"`
	ServiceInformationExtensions []json.RawMessage       `json:"ServiceInformationExtensions,omitempty"`
}

// ServiceSupplyPointURI is a typed URI for a service supply point.
type ServiceSupplyPointURI struct {
	ServiceType string `json:"ServiceType,omitempty"`
	URIValue    string `json:"uriValue"`
}

// ServiceHistoryInstance captures a previous state of a service.
type ServiceHistoryInstance struct {
	ServiceName                  NameSet                `json:"ServiceName"`
	ServiceDigitalIdentity       ServiceDigitalIdentity `json:"ServiceDigitalIdentity"`
	ServiceStatus                string                 `json:"ServiceStatus"`
	StatusStartingTime           string                 `json:"StatusStartingTime"`
	ServiceTypeIdentifier        string                 `json:"ServiceTypeIdentifier,omitempty"`
	ServiceInformationExtensions []json.RawMessage      `json:"ServiceInformationExtensions,omitempty"`
}

// --- Status constants ---

const (
	// StatusGranted indicates an active, trusted entity.
	StatusGranted = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"

	// StatusWithdrawn indicates a formerly trusted entity whose trust has been revoked.
	StatusWithdrawn = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn"

	// StatusRecognisedAtNationalLevel indicates recognition at national level.
	StatusRecognisedAtNationalLevel = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel"
)

// --- Parse and marshal ---

// ParseLoTE parses a LoTE from JSON bytes, unwrapping the root {"LoTE": ...} envelope.
func ParseLoTE(data []byte) (*ListOfTrustedEntities, error) {
	var doc LoTEDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse LoTE: %w", err)
	}
	// Reject inputs missing the required "LoTE" root key
	if doc.LoTE.ListAndSchemeInformation.SchemeOperatorName == nil &&
		doc.LoTE.ListAndSchemeInformation.LoTEVersionIdentifier == 0 &&
		len(doc.LoTE.TrustedEntitiesList) == 0 {
		return nil, fmt.Errorf("failed to parse LoTE: missing required \"LoTE\" root key")
	}
	return &doc.LoTE, nil
}

// ParseLoTEFromFile loads and parses a LoTE from a JSON file.
func ParseLoTEFromFile(path string) (*ListOfTrustedEntities, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read LoTE file %s: %w", path, err)
	}
	return ParseLoTE(data)
}

// Marshal serializes the LoTE to JSON with the root {"LoTE": ...} envelope.
func (l *ListOfTrustedEntities) Marshal() ([]byte, error) {
	return json.Marshal(LoTEDocument{LoTE: *l})
}

// MarshalIndent serializes the LoTE to indented JSON with the root envelope.
func (l *ListOfTrustedEntities) MarshalIndent() ([]byte, error) {
	return json.MarshalIndent(LoTEDocument{LoTE: *l}, "", "  ")
}

// EncodeToFile writes the LoTE as JSON to a file.
func (l *ListOfTrustedEntities) EncodeToFile(path string) error {
	data, err := l.MarshalIndent()
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0640)
}
