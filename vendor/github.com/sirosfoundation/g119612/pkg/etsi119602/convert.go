package etsi119602

import (
	"fmt"
	"time"

	"github.com/sirosfoundation/g119612/pkg/etsi119612"
)

// FromTSL converts a TS 119 612 TrustStatusListType to a TS 119 602-1 ListOfTrustedEntities.
// This allows existing XML TSLs to be represented in the LoTE JSON format.
func FromTSL(tsl *etsi119612.TSL) *ListOfTrustedEntities {
	lote := &ListOfTrustedEntities{
		ListAndSchemeInformation: ListAndSchemeInformation{
			LoTEVersionIdentifier: 1,
		},
	}

	if tsl.StatusList.TslSchemeInformation != nil {
		si := tsl.StatusList.TslSchemeInformation
		lote.ListAndSchemeInformation.SchemeTerritory = si.TslSchemeTerritory
		lote.ListAndSchemeInformation.SchemeOperatorName = internationalNamesToNameSet(si.TslSchemeOperatorName)
		lote.ListAndSchemeInformation.SchemeName = internationalNamesToNameSet(si.TslSchemeName)
		lote.ListAndSchemeInformation.LoTEType = si.TslTSLType
		lote.ListAndSchemeInformation.LoTESequenceNumber = si.TSLSequenceNumber
		lote.ListAndSchemeInformation.StatusDeterminationApproach = si.StatusDeterminationApproach

		if si.ListIssueDateTime != "" {
			lote.ListAndSchemeInformation.ListIssueDateTime = si.ListIssueDateTime
		}
		if si.TslNextUpdate != nil && si.TslNextUpdate.DateTime != "" {
			lote.ListAndSchemeInformation.NextUpdate = si.TslNextUpdate.DateTime
		}
		if si.TslSchemeInformationURI != nil {
			for _, uri := range si.TslSchemeInformationURI.URI {
				lang := ""
				if uri.XmlLangAttr != nil {
					lang = string(*uri.XmlLangAttr)
				}
				lote.ListAndSchemeInformation.SchemeInformationURI = append(
					lote.ListAndSchemeInformation.SchemeInformationURI,
					NonEmptyMultiLangURI{Lang: lang, URIValue: uri.Value},
				)
			}
		}
		if si.TslDistributionPoints != nil {
			lote.ListAndSchemeInformation.DistributionPoints = si.TslDistributionPoints.URI
		}
		if si.TslPolicyOrLegalNotice != nil {
			for _, notice := range si.TslPolicyOrLegalNotice.TSLLegalNotice {
				val := ""
				if notice.NonEmptyString != nil {
					val = string(*notice.NonEmptyString)
				}
				lote.ListAndSchemeInformation.PolicyOrLegalNotice = append(
					lote.ListAndSchemeInformation.PolicyOrLegalNotice,
					PolicyOrLegalNoticeItem{LoTELegalNotice: val},
				)
			}
		}

		// Convert pointers to other TSLs
		if si.TslPointersToOtherTSL != nil {
			for _, ptr := range si.TslPointersToOtherTSL.TslOtherTSLPointer {
				lotePtr := OtherLoTEPointer{
					LoTELocation: ptr.TSLLocation,
				}
				// Extract signer identity from pointer
				if ptr.TslServiceDigitalIdentities != nil {
					for _, sdil := range ptr.TslServiceDigitalIdentities.TslServiceDigitalIdentity {
						if sdil == nil {
							continue
						}
						sdi := ServiceDigitalIdentity{}
						for _, did := range sdil.DigitalId {
							if did.X509Certificate != "" {
								sdi.X509Certificates = append(sdi.X509Certificates, PKIOb{Val: did.X509Certificate})
							}
						}
						if len(sdi.X509Certificates) > 0 {
							lotePtr.ServiceDigitalIdentities = append(lotePtr.ServiceDigitalIdentities, sdi)
						}
					}
				}
				lote.ListAndSchemeInformation.PointersToOtherLoTE = append(
					lote.ListAndSchemeInformation.PointersToOtherLoTE, lotePtr,
				)
			}
		}
	}

	// Convert trust service providers to trusted entities
	if tsl.StatusList.TslTrustServiceProviderList != nil {
		tspIndex := 0
		for _, tsp := range tsl.StatusList.TslTrustServiceProviderList.TslTrustServiceProvider {
			if tsp.TslTSPServices == nil {
				continue
			}

			// Extract provider-level metadata
			var providerName NameSet
			var providerURIs []NonEmptyMultiLangURI
			var providerAddress *TEAddress

			if tsp.TslTSPInformation != nil {
				providerName = internationalNamesToNameSet(tsp.TslTSPInformation.TSPName)
				providerURIs = urisFromInternational(tsp.TslTSPInformation.TSPInformationURI)
				providerAddress = convertAddress(tsp.TslTSPInformation.TSPAddress)
			}

			svcIndex := 0
			for _, svc := range tsp.TslTSPServices.TslTSPService {
				if svc.TslServiceInformation == nil {
					continue
				}
				tslSI := svc.TslServiceInformation

				entityID := fmt.Sprintf("%s#tsp%d-svc%d", tslSI.TslServiceTypeIdentifier, tspIndex, svcIndex)

				// Build entity name from service name, falling back to provider name
				entityName := internationalNamesToNameSet(tslSI.ServiceName)
				if len(entityName) == 0 {
					entityName = providerName
				}

				// Build digital identity
				sdi := ServiceDigitalIdentity{}
				if tslSI.TslServiceDigitalIdentity != nil {
					for _, did := range tslSI.TslServiceDigitalIdentity.DigitalId {
						if did.X509Certificate != "" {
							sdi.X509Certificates = append(sdi.X509Certificates, PKIOb{Val: did.X509Certificate})
						}
						if did.X509SubjectName != "" {
							sdi.X509SubjectNames = append(sdi.X509SubjectNames, did.X509SubjectName)
						}
					}
				}

				// Build information URIs
				var infoURIs []NonEmptyMultiLangURI
				infoURIs = append(infoURIs, NonEmptyMultiLangURI{Lang: "en", URIValue: entityID})
				infoURIs = append(infoURIs, providerURIs...)

				entity := TrustedEntity{
					TrustedEntityInformation: TrustedEntityInformation{
						TEName:           entityName,
						TEAddress:        providerAddress,
						TEInformationURI: infoURIs,
					},
					TrustedEntityServices: []TrustedEntityService{{
						ServiceInformation: ServiceInformation{
							ServiceName:            entityName,
							ServiceDigitalIdentity: sdi,
							ServiceTypeIdentifier:  tslSI.TslServiceTypeIdentifier,
							ServiceStatus:          tslSI.TslServiceStatus,
							StatusStartingTime:     tslSI.StatusStartingTime,
						},
					}},
				}

				// Convert service supply points
				if tslSI.TslServiceSupplyPoints != nil && tslSI.TslServiceSupplyPoints.ServiceSupplyPoint != nil {
					entity.TrustedEntityServices[0].ServiceInformation.ServiceSupplyPoints = append(
						entity.TrustedEntityServices[0].ServiceInformation.ServiceSupplyPoints,
						ServiceSupplyPointURI{URIValue: tslSI.TslServiceSupplyPoints.ServiceSupplyPoint.Value},
					)
				}

				// Convert service history
				if svc.TslServiceHistory != nil {
					for _, hist := range svc.TslServiceHistory.TslServiceHistoryInstance {
						histSdi := ServiceDigitalIdentity{}
						if hist.TslServiceDigitalIdentity != nil {
							for _, did := range hist.TslServiceDigitalIdentity.DigitalId {
								if did.X509Certificate != "" {
									histSdi.X509Certificates = append(histSdi.X509Certificates, PKIOb{Val: did.X509Certificate})
								}
							}
						}
						entity.TrustedEntityServices[0].ServiceHistory = append(
							entity.TrustedEntityServices[0].ServiceHistory,
							ServiceHistoryInstance{
								ServiceName:            internationalNamesToNameSet(hist.ServiceName),
								ServiceDigitalIdentity: histSdi,
								ServiceStatus:          hist.TslServiceStatus,
								StatusStartingTime:     hist.StatusStartingTime,
								ServiceTypeIdentifier:  hist.TslServiceTypeIdentifier,
							},
						)
					}
				}

				lote.TrustedEntitiesList = append(lote.TrustedEntitiesList, entity)
				svcIndex++
			}
			tspIndex++
		}
	}

	return lote
}

// convertAddress converts TSL AddressType to a TEAddress.
func convertAddress(addr *etsi119612.AddressType) *TEAddress {
	if addr == nil {
		return nil
	}
	teAddr := &TEAddress{}

	if addr.TslPostalAddresses != nil {
		for _, pa := range addr.TslPostalAddresses.TslPostalAddress {
			postalAddr := PostalAddress{
				StreetAddress: pa.StreetAddress,
				Locality:      pa.Locality,
				Country:       pa.CountryName,
				PostalCode:    pa.PostalCode,
			}
			if pa.StateOrProvince != "" {
				postalAddr.StateOrProvince = pa.StateOrProvince
			}
			if pa.XmlLangAttr != nil {
				postalAddr.Lang = string(*pa.XmlLangAttr)
			}
			teAddr.TEPostalAddress = append(teAddr.TEPostalAddress, postalAddr)
		}
	}

	if addr.TslElectronicAddress != nil {
		for _, u := range addr.TslElectronicAddress.URI {
			lang := ""
			if u.XmlLangAttr != nil {
				lang = string(*u.XmlLangAttr)
			}
			teAddr.TEElectronicAddress = append(teAddr.TEElectronicAddress, NonEmptyMultiLangURI{Lang: lang, URIValue: u.Value})
		}
	}

	return teAddr
}

// internationalNamesToNameSet converts 119 612 InternationalNamesType to a NameSet.
func internationalNamesToNameSet(names *etsi119612.InternationalNamesType) NameSet {
	if names == nil {
		return nil
	}
	var ns NameSet
	for _, name := range names.Name {
		lang := ""
		if name.XmlLangAttr != nil {
			lang = string(*name.XmlLangAttr)
		}
		val := ""
		if name.NonEmptyNormalizedString != nil {
			val = string(*name.NonEmptyNormalizedString)
		}
		ns = append(ns, MultiLangString{Lang: lang, Value: val})
	}
	return ns
}

// urisFromInternational converts NonEmptyMultiLangURIListType to NonEmptyMultiLangURI slice.
func urisFromInternational(uris *etsi119612.NonEmptyMultiLangURIListType) []NonEmptyMultiLangURI {
	if uris == nil {
		return nil
	}
	var result []NonEmptyMultiLangURI
	for _, uri := range uris.URI {
		lang := ""
		if uri.XmlLangAttr != nil {
			lang = string(*uri.XmlLangAttr)
		}
		result = append(result, NonEmptyMultiLangURI{Lang: lang, URIValue: uri.Value})
	}
	return result
}

// timeToString converts a time.Time to RFC3339 string, or empty if zero.
func timeToString(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
