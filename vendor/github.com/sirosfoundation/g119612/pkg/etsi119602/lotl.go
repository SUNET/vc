package etsi119602

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Well-known LoTE/LoTL scheme type URIs per ETSI TS 119 602 implementation profile.
const (
	// LoTLTypeEU is the scheme type for the EU List of Trusted Lists.
	LoTLTypeEU = "http://uri.etsi.org/19602/LoTLType/EUListOfTrustedLists"

	// LoTETypePIDProviders identifies a PID Providers list.
	LoTETypePIDProviders = "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList"

	// LoTETypeWalletProviders identifies a Wallet Providers list.
	LoTETypeWalletProviders = "http://uri.etsi.org/19602/LoTEType/EUWalletProvidersList"

	// LoTETypePubEAAProviders identifies a PuB-EAA Providers list.
	LoTETypePubEAAProviders = "http://uri.etsi.org/19602/LoTEType/EUPubEAAProvidersList"

	// LoTETypeWRPACProviders identifies a WRPAC Providers list.
	LoTETypeWRPACProviders = "http://uri.etsi.org/19602/LoTEType/EUWRPACProvidersList"

	// LoTETypeWRPRCProviders identifies a WRPRC Providers list.
	LoTETypeWRPRCProviders = "http://uri.etsi.org/19602/LoTEType/EUWRPRCProvidersList"

	// LoTETypeRegistrarsAndRegisters identifies a Registrars/Registers list.
	LoTETypeRegistrarsAndRegisters = "http://uri.etsi.org/19602/LoTEType/EURegistrarsAndRegistersList"
)

// ListOfTrustedLists is a type alias for ListOfTrustedEntities.
// A LoTL is semantically a LoTE whose LoTEType is a LoTL scheme type
// and whose PointersToOtherLoTE is populated instead of TrustedEntitiesList.
// The JSON schema is identical for both.
type ListOfTrustedLists = ListOfTrustedEntities

// IsLoTLSchemeType returns true if the given scheme type URI identifies
// a List of Trusted Lists rather than a List of Trusted Entities.
func IsLoTLSchemeType(schemeType string) bool {
	return strings.Contains(schemeType, "/LoTLType/")
}

// IsPubEAASchemeType returns true if the LoTE type is the Pub-EAA Providers profile.
// Per ETSI TS 119 602 Annex H, only the Pub-EAA profile uses explicit ServiceStatus
// (notified/withdrawn). All other profiles use implicit trust (presence = trusted).
func IsPubEAASchemeType(schemeType string) bool {
	return schemeType == LoTETypePubEAAProviders
}

// IsLoTL returns true if this LoTE is semantically a List of Trusted Lists.
func (l *ListOfTrustedEntities) IsLoTL() bool {
	return IsLoTLSchemeType(l.ListAndSchemeInformation.LoTEType)
}

// ParseLoTL parses a LoTL from JSON bytes. Since a LoTL uses the same schema
// as a LoTE, this is identical to ParseLoTE.
func ParseLoTL(data []byte) (*ListOfTrustedLists, error) {
	return ParseLoTE(data)
}

// ParseLoTLFromFile loads and parses a LoTL from a JSON file.
func ParseLoTLFromFile(path string) (*ListOfTrustedLists, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read LoTL file %s: %w", path, err)
	}
	return ParseLoTL(data)
}

// MarshalLoTL serializes the LoTL to JSON. Since it uses the same schema as LoTE,
// this wraps in the standard {"LoTE": ...} envelope.
func (l *ListOfTrustedLists) MarshalLoTL() ([]byte, error) {
	return json.Marshal(LoTEDocument{LoTE: *l})
}

// MarshalLoTLIndent serializes the LoTL to indented JSON.
func (l *ListOfTrustedLists) MarshalLoTLIndent() ([]byte, error) {
	return json.MarshalIndent(LoTEDocument{LoTE: *l}, "", "  ")
}
