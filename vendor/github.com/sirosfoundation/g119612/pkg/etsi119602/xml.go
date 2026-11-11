// Package etsi119602 — this file implements XML marshaling and unmarshaling
// for LoTE and LoTL documents per ETSI TS 119 602.
//
// The XML representation uses the XSD-generated types from the xmltypes sub-package,
// produced from the official ETSI TS 119 602 XSD schema via xgen.
//
// The XML uses the namespace: http://uri.etsi.org/019602/v1#
package etsi119602

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"strings"

	"github.com/sirosfoundation/g119612/pkg/etsi119602/xmltypes"
)

const (
	// XMLNamespace is the XML namespace for ETSI TS 119 602.
	XMLNamespace = "http://uri.etsi.org/019602/v1#"
	// LOTETagDefault is the default LoTE tag attribute value.
	LOTETagDefault = "http://uri.etsi.org/019602/LOTETag"
)

// --- Marshaling: LoTE → XML ---

// xmlLoTEWrapper is a named wrapper for marshaling with the correct root element and namespace.
type xmlLoTEWrapper struct {
	XMLName xml.Name `xml:"http://uri.etsi.org/019602/v1# ListOfTrustedEntities"`
	xmltypes.ListOfTrustedEntitiesType
}

// EncodeXML serializes the LoTE to XML bytes using XSD-generated types.
func (l *ListOfTrustedEntities) EncodeXML() ([]byte, error) {
	x := toXMLLoTE(l)
	wrapper := xmlLoTEWrapper{
		ListOfTrustedEntitiesType: *x,
	}
	return xml.MarshalIndent(wrapper, "", "  ")
}

// EncodeXMLToFile writes the LoTE as XML to a file.
func (l *ListOfTrustedEntities) EncodeXMLToFile(path string) error {
	data, err := l.EncodeXML()
	if err != nil {
		return err
	}
	header := []byte(xml.Header)
	return os.WriteFile(path, append(header, data...), 0640)
}

// ParseLoTEXML parses a LoTE from XML bytes.
func ParseLoTEXML(data []byte) (*ListOfTrustedEntities, error) {
	if err := checkLoTEXMLRoot(data); err != nil {
		return nil, err
	}
	var x xmltypes.ListOfTrustedEntitiesType
	if err := xml.Unmarshal(data, &x); err != nil {
		return nil, fmt.Errorf("failed to parse LoTE XML: %w", err)
	}
	return fromXMLLoTE(&x)
}

// checkLoTEXMLRoot rejects documents whose root element is not a LoTE or LoTL.
// encoding/xml ignores the root name when unmarshaling into a struct without an
// XMLName field, so a TS 119 612 TrustServiceStatusList would otherwise parse
// as an empty list instead of failing.
func checkLoTEXMLRoot(data []byte) error {
	dec := xml.NewDecoder(bytes.NewReader(data))
	for {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("failed to parse LoTE XML: %w", err)
		}
		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch start.Name.Local {
		case "TrustedEntitiesList", "ListOfTrustedEntities":
			return nil
		case "TrustServiceStatusList":
			return fmt.Errorf("failed to parse LoTE XML: root element is a TS 119 612 TrustServiceStatusList, not a TS 119 602 list")
		default:
			return fmt.Errorf("failed to parse LoTE XML: unexpected root element %q", start.Name.Local)
		}
	}
}

// ParseLoTEXMLFromFile loads and parses a LoTE from an XML file.
func ParseLoTEXMLFromFile(path string) (*ListOfTrustedEntities, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read LoTE XML file %s: %w", path, err)
	}
	return ParseLoTEXML(data)
}

// --- Marshaling: LoTL → XML ---

// EncodeXML serializes the LoTL to XML bytes (same format as LoTE).
// Note: since ListOfTrustedLists is a type alias, this method is already
// available via ListOfTrustedEntities.EncodeXML().

// ParseLoTLXML parses a LoTL from XML bytes.
func ParseLoTLXML(data []byte) (*ListOfTrustedLists, error) {
	return ParseLoTEXML(data)
}

// ParseLoTLXMLFromFile loads and parses a LoTL from an XML file.
func ParseLoTLXMLFromFile(path string) (*ListOfTrustedLists, error) {
	return ParseLoTEXMLFromFile(path)
}

// --- Internal conversion: domain types ↔ XSD-generated types ---

func toXMLLoTE(l *ListOfTrustedEntities) *xmltypes.ListOfTrustedEntitiesType {
	si := &l.ListAndSchemeInformation
	schemeInfo := &xmltypes.LoTEListAndSchemeInformationType{
		LoTEVersionIdentifier:       si.LoTEVersionIdentifier,
		LoTESequenceNumber:          si.LoTESequenceNumber,
		LoteLoTEType:                si.LoTEType,
		LoteSchemeOperatorName:      nameSetToXMLNames(si.SchemeOperatorName),
		StatusDeterminationApproach: si.StatusDeterminationApproach,
		ListIssueDateTime:           si.ListIssueDateTime,
	}

	if si.SchemeTerritory != "" {
		territory := si.SchemeTerritory
		schemeInfo.LoteSchemeTerritory = &territory
	}
	if len(si.SchemeName) > 0 {
		schemeInfo.LoteSchemeName = nameSetToXMLNames(si.SchemeName)
	}
	if len(si.SchemeInformationURI) > 0 {
		schemeInfo.LoteSchemeInformationURI = multiLangURIsToXMLURIList(si.SchemeInformationURI)
	}
	if len(si.PolicyOrLegalNotice) > 0 {
		schemeInfo.LotePolicyOrLegalNotice = policyToXML(si.PolicyOrLegalNotice)
	}
	if si.NextUpdate != "" {
		schemeInfo.LoteNextUpdate = &xmltypes.NextUpdateType{DateTime: &si.NextUpdate}
	}
	if len(si.DistributionPoints) > 0 {
		schemeInfo.LoteDistributionPoints = &xmltypes.NonEmptyURIListType{
			URI: si.DistributionPoints,
		}
	}

	// Pointers
	if len(si.PointersToOtherLoTE) > 0 {
		ptrs := &xmltypes.OtherLoTEPointersType{}
		for _, p := range si.PointersToOtherLoTE {
			ptrs.LoteOtherLoTEPointer = append(ptrs.LoteOtherLoTEPointer, otherLoTEPointerToXML(p))
		}
		schemeInfo.LotePointersToOtherLoTE = ptrs
	}

	loteTag := l.LOTETag
	if loteTag == "" {
		loteTag = LOTETagDefault
	}
	x := &xmltypes.ListOfTrustedEntitiesType{
		LOTETagAttr:                  loteTag,
		LoteListAndSchemeInformation: schemeInfo,
	}

	// Trusted entities
	if len(l.TrustedEntitiesList) > 0 {
		tel := &xmltypes.TrustedEntitiesListType{}
		for _, e := range l.TrustedEntitiesList {
			tel.LoteTrustedEntity = append(tel.LoteTrustedEntity, trustedEntityToXML(e))
		}
		x.LoteTrustedEntitiesList = tel
	}

	return x
}

func fromXMLLoTE(x *xmltypes.ListOfTrustedEntitiesType) (*ListOfTrustedEntities, error) {
	l := &ListOfTrustedEntities{
		LOTETag: x.LOTETagAttr,
	}

	if si := x.LoteListAndSchemeInformation; si != nil {
		l.ListAndSchemeInformation.LoTEVersionIdentifier = si.LoTEVersionIdentifier
		l.ListAndSchemeInformation.LoTESequenceNumber = si.LoTESequenceNumber
		l.ListAndSchemeInformation.LoTEType = si.LoteLoTEType
		l.ListAndSchemeInformation.StatusDeterminationApproach = si.StatusDeterminationApproach
		l.ListAndSchemeInformation.ListIssueDateTime = si.ListIssueDateTime

		if si.LoteSchemeTerritory != nil {
			l.ListAndSchemeInformation.SchemeTerritory = *si.LoteSchemeTerritory
		}
		if si.LoteSchemeOperatorName != nil {
			l.ListAndSchemeInformation.SchemeOperatorName = xmlNamesToNameSet(si.LoteSchemeOperatorName)
		}
		if si.LoteSchemeName != nil {
			l.ListAndSchemeInformation.SchemeName = xmlNamesToNameSet(si.LoteSchemeName)
		}
		if si.LoteSchemeInformationURI != nil {
			l.ListAndSchemeInformation.SchemeInformationURI = xmlURIListToMultiLangURIs(si.LoteSchemeInformationURI)
		}
		if si.LotePolicyOrLegalNotice != nil {
			l.ListAndSchemeInformation.PolicyOrLegalNotice = xmlToPolicy(si.LotePolicyOrLegalNotice)
		}
		if si.LoteNextUpdate != nil && si.LoteNextUpdate.DateTime != nil {
			l.ListAndSchemeInformation.NextUpdate = *si.LoteNextUpdate.DateTime
		}
		if si.LoteDistributionPoints != nil {
			l.ListAndSchemeInformation.DistributionPoints = si.LoteDistributionPoints.URI
		}

		// Pointers
		if si.LotePointersToOtherLoTE != nil {
			for _, xp := range si.LotePointersToOtherLoTE.LoteOtherLoTEPointer {
				l.ListAndSchemeInformation.PointersToOtherLoTE = append(
					l.ListAndSchemeInformation.PointersToOtherLoTE,
					xmlToOtherLoTEPointer(xp),
				)
			}
		}
	}

	// Trusted entities
	if x.LoteTrustedEntitiesList != nil {
		for _, te := range x.LoteTrustedEntitiesList.LoteTrustedEntity {
			l.TrustedEntitiesList = append(l.TrustedEntitiesList, xmlToTrustedEntity(te))
		}
	}

	return l, nil
}

// --- Name/URI helpers ---

func nameSetToXMLNames(ns NameSet) *xmltypes.InternationalNamesType {
	if len(ns) == 0 {
		return nil
	}
	x := &xmltypes.InternationalNamesType{}
	for _, n := range ns {
		lang := xmltypes.Lang(n.Lang)
		value := xmltypes.NonEmptyNormalizedString(n.Value)
		x.Name = append(x.Name, &xmltypes.MultiLangNormStringType{
			XmlLangAttr:              &lang,
			NonEmptyNormalizedString: &value,
		})
	}
	return x
}

func xmlNamesToNameSet(x *xmltypes.InternationalNamesType) NameSet {
	if x == nil {
		return nil
	}
	var ns NameSet
	for _, n := range x.Name {
		ms := MultiLangString{}
		if n.XmlLangAttr != nil {
			ms.Lang = string(*n.XmlLangAttr)
		}
		if n.NonEmptyNormalizedString != nil {
			ms.Value = string(*n.NonEmptyNormalizedString)
		}
		ns = append(ns, ms)
	}
	return ns
}

func multiLangURIsToXMLURIList(uris []NonEmptyMultiLangURI) *xmltypes.NonEmptyMultiLangURIListType {
	if len(uris) == 0 {
		return nil
	}
	x := &xmltypes.NonEmptyMultiLangURIListType{}
	for _, u := range uris {
		lang := xmltypes.Lang(u.Lang)
		x.URI = append(x.URI, &xmltypes.NonEmptyMultiLangURIType{
			XmlLangAttr: &lang,
			Value:       u.URIValue,
		})
	}
	return x
}

func xmlURIListToMultiLangURIs(x *xmltypes.NonEmptyMultiLangURIListType) []NonEmptyMultiLangURI {
	if x == nil {
		return nil
	}
	var uris []NonEmptyMultiLangURI
	for _, u := range x.URI {
		mu := NonEmptyMultiLangURI{URIValue: u.Value}
		if u.XmlLangAttr != nil {
			mu.Lang = string(*u.XmlLangAttr)
		}
		uris = append(uris, mu)
	}
	return uris
}

func policyToXML(items []PolicyOrLegalNoticeItem) *xmltypes.PolicyOrLegalnoticeType {
	if len(items) == 0 {
		return nil
	}
	x := &xmltypes.PolicyOrLegalnoticeType{}
	for _, item := range items {
		if item.LoTEPolicy != nil {
			lang := xmltypes.Lang(item.LoTEPolicy.Lang)
			x.LoTEPolicy = append(x.LoTEPolicy, &xmltypes.NonEmptyMultiLangURIType{
				XmlLangAttr: &lang,
				Value:       item.LoTEPolicy.URIValue,
			})
		} else if item.LoTELegalNotice != "" {
			value := xmltypes.NonEmptyString(item.LoTELegalNotice)
			x.LoTELegalNotice = append(x.LoTELegalNotice, &xmltypes.MultiLangStringType{
				NonEmptyString: &value,
			})
		}
	}
	return x
}

func xmlToPolicy(x *xmltypes.PolicyOrLegalnoticeType) []PolicyOrLegalNoticeItem {
	if x == nil {
		return nil
	}
	var items []PolicyOrLegalNoticeItem
	for _, p := range x.LoTEPolicy {
		mu := NonEmptyMultiLangURI{URIValue: p.Value}
		if p.XmlLangAttr != nil {
			mu.Lang = string(*p.XmlLangAttr)
		}
		items = append(items, PolicyOrLegalNoticeItem{LoTEPolicy: &mu})
	}
	for _, n := range x.LoTELegalNotice {
		val := ""
		if n.NonEmptyString != nil {
			val = string(*n.NonEmptyString)
		}
		items = append(items, PolicyOrLegalNoticeItem{LoTELegalNotice: val})
	}
	return items
}

// --- Pointer conversion ---

func otherLoTEPointerToXML(p OtherLoTEPointer) *xmltypes.OtherLoTEPointerType {
	xp := &xmltypes.OtherLoTEPointerType{
		LoTELocation: p.LoTELocation,
	}

	// Convert ServiceDigitalIdentities
	if len(p.ServiceDigitalIdentities) > 0 {
		sdil := &xmltypes.ServiceDigitalIdentityListType{}
		for _, sdi := range p.ServiceDigitalIdentities {
			sdil.LoteServiceDigitalIdentity = append(sdil.LoteServiceDigitalIdentity,
				serviceDigitalIdentityToXML(sdi))
		}
		xp.LoteServiceDigitalIdentities = sdil
	}

	// Convert LoTEQualifiers
	if len(p.LoTEQualifiers) > 0 {
		for _, q := range p.LoTEQualifiers {
			xq := &xmltypes.AdditionalInformationType{}
			// Store qualifier info as textual information
			if q.LoTEType != "" {
				lang := xmltypes.Lang("en")
				val := xmltypes.NonEmptyString(q.LoTEType)
				xq.TextualInformation = append(xq.TextualInformation, &xmltypes.MultiLangStringType{
					XmlLangAttr:    &lang,
					NonEmptyString: &val,
				})
			}
			xp.LoteAdditionalInformation = xq
		}
	}

	return xp
}

func xmlToOtherLoTEPointer(xp *xmltypes.OtherLoTEPointerType) OtherLoTEPointer {
	p := OtherLoTEPointer{
		LoTELocation: xp.LoTELocation,
	}

	// Convert ServiceDigitalIdentities
	if xp.LoteServiceDigitalIdentities != nil {
		for _, xsdi := range xp.LoteServiceDigitalIdentities.LoteServiceDigitalIdentity {
			if xsdi != nil {
				p.ServiceDigitalIdentities = append(p.ServiceDigitalIdentities, xmlToServiceDigitalIdentity(xsdi))
			}
		}
	}

	// Convert AdditionalInformation → LoTEQualifiers
	if xp.LoteAdditionalInformation != nil && len(xp.LoteAdditionalInformation.TextualInformation) > 0 {
		q := LoTEQualifier{}
		for _, txt := range xp.LoteAdditionalInformation.TextualInformation {
			if txt.NonEmptyString != nil {
				val := string(*txt.NonEmptyString)
				if strings.Contains(val, "://") {
					q.LoTEType = val
				}
			}
		}
		if q.LoTEType != "" {
			p.LoTEQualifiers = append(p.LoTEQualifiers, q)
		}
	}

	return p
}

// --- Trusted entity conversion ---

func trustedEntityToXML(e TrustedEntity) *xmltypes.TEType {
	te := &xmltypes.TEType{
		LoteTrustedEntityInformation: &xmltypes.TrustedEntityInformationType{
			TEName: nameSetToXMLNames(e.TrustedEntityInformation.TEName),
		},
	}

	// TEInformationURI
	if len(e.TrustedEntityInformation.TEInformationURI) > 0 {
		te.LoteTrustedEntityInformation.TEInformationURI = multiLangURIsToXMLURIList(e.TrustedEntityInformation.TEInformationURI)
	}

	// TETradeName
	if len(e.TrustedEntityInformation.TETradeName) > 0 {
		te.LoteTrustedEntityInformation.TETradeName = nameSetToXMLNames(e.TrustedEntityInformation.TETradeName)
	}

	// Build services list
	if len(e.TrustedEntityServices) > 0 {
		svcList := &xmltypes.TrustedEntityServicesListType{}
		for _, s := range e.TrustedEntityServices {
			svcList.LoteTrustedEntityService = append(svcList.LoteTrustedEntityService, entityServiceToXML(s))
		}
		te.LoteTrustedEntityServices = svcList
	}

	return te
}

func xmlToTrustedEntity(te *xmltypes.TEType) TrustedEntity {
	e := TrustedEntity{}

	if te.LoteTrustedEntityInformation != nil {
		e.TrustedEntityInformation.TEName = xmlNamesToNameSet(te.LoteTrustedEntityInformation.TEName)
		e.TrustedEntityInformation.TEInformationURI = xmlURIListToMultiLangURIs(te.LoteTrustedEntityInformation.TEInformationURI)
		e.TrustedEntityInformation.TETradeName = xmlNamesToNameSet(te.LoteTrustedEntityInformation.TETradeName)
	}

	if te.LoteTrustedEntityServices != nil {
		for _, xs := range te.LoteTrustedEntityServices.LoteTrustedEntityService {
			e.TrustedEntityServices = append(e.TrustedEntityServices, xmlToEntityService(xs))
		}
	}

	return e
}

// --- Service conversion ---

func entityServiceToXML(s TrustedEntityService) *xmltypes.TrustedEntityServiceType {
	svc := &xmltypes.TrustedEntityServiceType{
		LoteServiceInformation: &xmltypes.TEServiceInformationType{
			ServiceName: nameSetToXMLNames(s.ServiceInformation.ServiceName),
		},
	}
	si := svc.LoteServiceInformation

	if s.ServiceInformation.ServiceTypeIdentifier != "" {
		si.LoteServiceTypeIdentifier = &s.ServiceInformation.ServiceTypeIdentifier
	}
	if s.ServiceInformation.ServiceStatus != "" {
		si.LoteServiceStatus = &s.ServiceInformation.ServiceStatus
	}
	if s.ServiceInformation.StatusStartingTime != "" {
		si.StatusStartingTime = &s.ServiceInformation.StatusStartingTime
	}
	if !s.ServiceInformation.ServiceDigitalIdentity.isEmpty() {
		si.LoteServiceDigitalIdentity = serviceDigitalIdentityToXMLDigitalIdList(s.ServiceInformation.ServiceDigitalIdentity)
	}
	if len(s.ServiceInformation.ServiceSupplyPoints) > 0 {
		pts := &xmltypes.ServiceSupplyPointsType{}
		for _, p := range s.ServiceInformation.ServiceSupplyPoints {
			pts.ServiceSupplyPoint = append(pts.ServiceSupplyPoint, &xmltypes.AttributedNonEmptyURIType{
				Value: p.URIValue,
			})
		}
		si.LoteServiceSupplyPoints = pts
	}

	return svc
}

func xmlToEntityService(xs *xmltypes.TrustedEntityServiceType) TrustedEntityService {
	s := TrustedEntityService{}
	if xs.LoteServiceInformation == nil {
		return s
	}
	si := xs.LoteServiceInformation

	if si.ServiceName != nil {
		s.ServiceInformation.ServiceName = xmlNamesToNameSet(si.ServiceName)
	}
	if si.LoteServiceTypeIdentifier != nil {
		s.ServiceInformation.ServiceTypeIdentifier = *si.LoteServiceTypeIdentifier
	}
	if si.LoteServiceStatus != nil {
		s.ServiceInformation.ServiceStatus = *si.LoteServiceStatus
	}
	if si.StatusStartingTime != nil {
		s.ServiceInformation.StatusStartingTime = *si.StatusStartingTime
	}
	if si.LoteServiceDigitalIdentity != nil {
		s.ServiceInformation.ServiceDigitalIdentity = xmlDigitalIdListToServiceDigitalIdentity(si.LoteServiceDigitalIdentity)
	}
	if si.LoteServiceSupplyPoints != nil {
		for _, p := range si.LoteServiceSupplyPoints.ServiceSupplyPoint {
			s.ServiceInformation.ServiceSupplyPoints = append(s.ServiceInformation.ServiceSupplyPoints,
				ServiceSupplyPointURI{URIValue: p.Value})
		}
	}

	return s
}

// --- Digital identity conversion ---

func (sdi ServiceDigitalIdentity) isEmpty() bool {
	return len(sdi.X509Certificates) == 0 &&
		len(sdi.X509SubjectNames) == 0 &&
		len(sdi.PublicKeyValues) == 0 &&
		len(sdi.X509SKIs) == 0 &&
		len(sdi.OtherIds) == 0
}

func serviceDigitalIdentityToXML(sdi ServiceDigitalIdentity) *xmltypes.DigitalIdentityListType {
	return serviceDigitalIdentityToXMLDigitalIdList(sdi)
}

func serviceDigitalIdentityToXMLDigitalIdList(sdi ServiceDigitalIdentity) *xmltypes.DigitalIdentityListType {
	x := &xmltypes.DigitalIdentityListType{}

	for _, cert := range sdi.X509Certificates {
		val := cert.Val
		x.DigitalId = append(x.DigitalId, &xmltypes.DigitalIdentityType{
			X509Certificate: &val,
		})
	}
	for _, name := range sdi.X509SubjectNames {
		n := name
		x.DigitalId = append(x.DigitalId, &xmltypes.DigitalIdentityType{
			X509SubjectName: &n,
		})
	}
	for _, jwk := range sdi.PublicKeyValues {
		if jwkBytes, err := json.Marshal(jwk); err == nil {
			content := string(jwkBytes)
			x.DigitalId = append(x.DigitalId, &xmltypes.DigitalIdentityType{
				OtherId: &xmltypes.AnyType{Content: content},
			})
		}
	}
	for _, id := range sdi.OtherIds {
		x.DigitalId = append(x.DigitalId, &xmltypes.DigitalIdentityType{
			OtherId: &xmltypes.AnyType{Content: id},
		})
	}

	return x
}

func xmlToServiceDigitalIdentity(x *xmltypes.DigitalIdentityListType) ServiceDigitalIdentity {
	return xmlDigitalIdListToServiceDigitalIdentity(x)
}

func xmlDigitalIdListToServiceDigitalIdentity(x *xmltypes.DigitalIdentityListType) ServiceDigitalIdentity {
	if x == nil {
		return ServiceDigitalIdentity{}
	}
	sdi := ServiceDigitalIdentity{}
	for _, xid := range x.DigitalId {
		if xid == nil {
			continue
		}
		if xid.X509Certificate != nil {
			sdi.X509Certificates = append(sdi.X509Certificates, PKIOb{Val: *xid.X509Certificate})
		}
		if xid.X509SubjectName != nil {
			sdi.X509SubjectNames = append(sdi.X509SubjectNames, *xid.X509SubjectName)
		}
		if xid.OtherId != nil {
			content := xid.OtherId.Content
			// Try to parse as JWK
			var jwk map[string]any
			if err := json.Unmarshal([]byte(content), &jwk); err == nil {
				if _, hasKty := jwk["kty"]; hasKty {
					sdi.PublicKeyValues = append(sdi.PublicKeyValues, jwk)
					continue
				}
			}
			// Otherwise it's a generic OtherId
			sdi.OtherIds = append(sdi.OtherIds, content)
		}
	}
	return sdi
}
