// Package mdoc implements the ISO/IEC 18013-5:2021 Mobile Driving Licence (mDL) data model.
package mdoc

import "time"

// Namespace and doc type constants for supported document profiles.
const (
	DocTypeMDL   = "org.iso.18013.5.1.mDL"
	NamespaceMDL = "org.iso.18013.5.1"
	
	Namespace = "org.iso.18013.5.1"
	DocType   = "org.iso.18013.5.1.mDL"

	DocTypePID   = "eu.europa.ec.eudi.pid.1"
	NamespacePID = "eu.europa.ec.eudi.pid.1"
)

// MDoc represents a Mobile Driving Licence document according to ISO/IEC 18013-5:2021.
type MDoc struct {
	// Mandatory elements

	// FamilyName is the last name, surname, or primary identifier of the mDL holder.
	// Maximum 150 characters, Latin1 encoding.
	FamilyName string `json:"family_name" cbor:"family_name" validate:"required,max=150"`

	// GivenName is the first name(s), other name(s), or secondary identifier of the mDL holder.
	// Maximum 150 characters, Latin1 encoding.
	GivenName string `json:"given_name" cbor:"given_name" validate:"required,max=150"`

	// BirthDate is the date of birth of the mDL holder.
	BirthDate string `json:"birth_date" cbor:"birth_date" validate:"required"`

	// IssueDate is the date when the mDL was issued.
	IssueDate string `json:"issue_date" cbor:"issue_date" validate:"required"`

	// ExpiryDate is the date when the mDL expires.
	ExpiryDate string `json:"expiry_date" cbor:"expiry_date" validate:"required"`

	// IssuingCountry is the Alpha-2 country code (ISO 3166-1) of the issuing authority's country.
	IssuingCountry string `json:"issuing_country" cbor:"issuing_country" validate:"required,len=2,iso3166_1_alpha2"`

	// IssuingAuthority is the name of the issuing authority.
	// Maximum 150 characters, Latin1 encoding.
	IssuingAuthority string `json:"issuing_authority" cbor:"issuing_authority" validate:"required,max=150"`

	// DocumentNumber is the licence number assigned by the issuing authority.
	// Maximum 150 characters, Latin1 encoding.
	DocumentNumber string `json:"document_number" cbor:"document_number" validate:"required,max=150"`

	// Portrait is the portrait image of the mDL holder (JPEG or JPEG2000).
	Portrait []byte `json:"portrait" cbor:"portrait" validate:"required"`

	// DrivingPrivileges contains the driving privileges of the mDL holder.
	DrivingPrivileges []DrivingPrivilege `json:"driving_privileges" cbor:"driving_privileges" validate:"required,dive"`

	// UNDistinguishingSign is the distinguishing sign according to ISO/IEC 18013-1:2018, Annex F.
	UNDistinguishingSign string `json:"un_distinguishing_sign" cbor:"un_distinguishing_sign" validate:"required"`

	// Optional elements

	// AdministrativeNumber is an audit control number assigned by the issuing authority.
	// Maximum 150 characters, Latin1 encoding.
	AdministrativeNumber *string `json:"administrative_number,omitempty" cbor:"administrative_number,omitempty" validate:"omitempty,max=150"`

	// Sex is the mDL holder's sex using values as defined in ISO/IEC 5218.
	// 0 = not known, 1 = male, 2 = female, 9 = not applicable
	Sex *uint `json:"sex,omitempty" cbor:"sex,omitempty" validate:"omitempty,oneof=0 1 2 9"`

	// Height is the mDL holder's height in centimetres.
	Height *uint `json:"height,omitempty" cbor:"height,omitempty" validate:"omitempty,min=1,max=300"`

	// Weight is the mDL holder's weight in kilograms.
	Weight *uint `json:"weight,omitempty" cbor:"weight,omitempty" validate:"omitempty,min=1,max=500"`

	// EyeColour is the mDL holder's eye colour.
	EyeColour *string `json:"eye_colour,omitempty" cbor:"eye_colour,omitempty" validate:"omitempty,oneof=black blue brown dichromatic grey green hazel maroon pink unknown"`

	// HairColour is the mDL holder's hair colour.
	HairColour *string `json:"hair_colour,omitempty" cbor:"hair_colour,omitempty" validate:"omitempty,oneof=bald black blond brown grey red auburn sandy white unknown"`

	// BirthPlace is the country and municipality or state/province where the mDL holder was born.
	// Maximum 150 characters, Latin1 encoding.
	BirthPlace *string `json:"birth_place,omitempty" cbor:"birth_place,omitempty" validate:"omitempty,max=150"`

	// ResidentAddress is the place where the mDL holder resides.
	// Maximum 150 characters, Latin1 encoding.
	ResidentAddress *string `json:"resident_address,omitempty" cbor:"resident_address,omitempty" validate:"omitempty,max=150"`

	// PortraitCaptureDate is the date when the portrait was taken.
	PortraitCaptureDate *time.Time `json:"portrait_capture_date,omitempty" cbor:"portrait_capture_date,omitempty"`

	// AgeInYears is the age of the mDL holder in years.
	AgeInYears *uint `json:"age_in_years,omitempty" cbor:"age_in_years,omitempty" validate:"omitempty,min=0,max=150"`

	// AgeBirthYear is the year when the mDL holder was born.
	AgeBirthYear *uint `json:"age_birth_year,omitempty" cbor:"age_birth_year,omitempty" validate:"omitempty,min=1900,max=2100"`

	// AgeOver contains age attestation statements for common thresholds.
	AgeOver *AgeOver `json:"age_over,omitempty" cbor:"age_over,omitempty"`

	// IssuingJurisdiction is the country subdivision code (ISO 3166-2) of the issuing jurisdiction.
	IssuingJurisdiction *string `json:"issuing_jurisdiction,omitempty" cbor:"issuing_jurisdiction,omitempty" validate:"omitempty"`

	// Nationality is the nationality of the mDL holder (ISO 3166-1 alpha-2).
	Nationality *string `json:"nationality,omitempty" cbor:"nationality,omitempty" validate:"omitempty,len=2"`

	// ResidentCity is the city where the mDL holder lives.
	// Maximum 150 characters, Latin1 encoding.
	ResidentCity *string `json:"resident_city,omitempty" cbor:"resident_city,omitempty" validate:"omitempty,max=150"`

	// ResidentState is the state/province/district where the mDL holder lives.
	// Maximum 150 characters, Latin1 encoding.
	ResidentState *string `json:"resident_state,omitempty" cbor:"resident_state,omitempty" validate:"omitempty,max=150"`

	// ResidentPostalCode is the postal code of the mDL holder.
	// Maximum 150 characters, Latin1 encoding.
	ResidentPostalCode *string `json:"resident_postal_code,omitempty" cbor:"resident_postal_code,omitempty" validate:"omitempty,max=150"`

	// ResidentCountry is the country where the mDL holder lives (ISO 3166-1 alpha-2).
	ResidentCountry *string `json:"resident_country,omitempty" cbor:"resident_country,omitempty" validate:"omitempty,len=2"`

	// BiometricTemplateFace is a biometric template for face recognition.
	BiometricTemplateFace []byte `json:"biometric_template_face,omitempty" cbor:"biometric_template_face,omitempty"`

	// BiometricTemplateFingerprint is a biometric template for fingerprint recognition.
	BiometricTemplateFingerprint []byte `json:"biometric_template_finger,omitempty" cbor:"biometric_template_finger,omitempty"`

	// BiometricTemplateSignature is a biometric template for signature recognition.
	BiometricTemplateSignature []byte `json:"biometric_template_signature,omitempty" cbor:"biometric_template_signature,omitempty"`

	// FamilyNameNationalCharacter is the family name using full UTF-8 character set.
	FamilyNameNationalCharacter *string `json:"family_name_national_character,omitempty" cbor:"family_name_national_character,omitempty"`

	// GivenNameNationalCharacter is the given name using full UTF-8 character set.
	GivenNameNationalCharacter *string `json:"given_name_national_character,omitempty" cbor:"given_name_national_character,omitempty"`

	// SignatureUsualMark is an image of the signature or usual mark of the mDL holder.
	SignatureUsualMark []byte `json:"signature_usual_mark,omitempty" cbor:"signature_usual_mark,omitempty"`

	// PseudonymSeed is a fixed-length seed value used to derive holder-specific
	// pseudonyms for pseudonymous authentication schemes. 
	PseudonymSeed []byte `json:"pseudonym_seed,omitempty" cbor:"pseudonym_seed,omitempty" validate:"omitempty,len=32"`
}

// DrivingPrivilege represents a single driving privilege category.
type DrivingPrivilege struct {
	// VehicleCategoryCode is the vehicle category code per ISO 18013-5 / Vienna Convention.
	// Valid values: AM, A1, A2, A, B1, B, BE, C1, C1E, C, CE, D1, D1E, D, DE, T.
	VehicleCategoryCode string `json:"vehicle_category_code" cbor:"vehicle_category_code" validate:"required,oneof=AM A1 A2 A B1 B BE C1 C1E C CE D1 D1E D DE T"`

	// IssueDate is the date when this privilege was issued.
	IssueDate *string `json:"issue_date,omitempty" cbor:"issue_date,omitempty"`

	// ExpiryDate is the date when this privilege expires.
	ExpiryDate *string `json:"expiry_date,omitempty" cbor:"expiry_date,omitempty"`

	// Codes contains additional restriction or condition codes.
	Codes []DrivingPrivilegeCode `json:"codes,omitempty" cbor:"codes,omitempty" validate:"omitempty,dive"`
}

// DrivingPrivilegeCode represents a restriction or condition code for a driving privilege.
type DrivingPrivilegeCode struct {
	// Code is the restriction or condition code.
	Code string `json:"code" cbor:"code" validate:"required"`

	// Sign is the sign of the code (e.g., "=", "<", ">").
	Sign *string `json:"sign,omitempty" cbor:"sign,omitempty"`

	// Value is the value associated with the code.
	Value *string `json:"value,omitempty" cbor:"value,omitempty"`
}

// AgeOver contains age attestation statements for common thresholds.
// These are the standard age thresholds defined in ISO 18013-5.
type AgeOver struct {
	// Over18 indicates whether the holder is 18 years or older.
	Over18 *bool `json:"age_over_18,omitempty" cbor:"age_over_18,omitempty"`

	// Over21 indicates whether the holder is 21 years or older.
	Over21 *bool `json:"age_over_21,omitempty" cbor:"age_over_21,omitempty"`

	// Over25 indicates whether the holder is 25 years or older.
	Over25 *bool `json:"age_over_25,omitempty" cbor:"age_over_25,omitempty"`

	// Over65 indicates whether the holder is 65 years or older.
	Over65 *bool `json:"age_over_65,omitempty" cbor:"age_over_65,omitempty"`
}

// DeviceKeyInfo contains information about the device key used for mdoc authentication.
type DeviceKeyInfo struct {
	// DeviceKey is the public key of the device (COSE_Key format).
	DeviceKey []byte `json:"deviceKey" cbor:"deviceKey" validate:"required"`

	// KeyAuthorizations contains authorized namespaces and data elements.
	KeyAuthorizations *KeyAuthorizations `json:"keyAuthorizations,omitempty" cbor:"keyAuthorizations,omitempty"`

	// KeyInfo contains additional key information.
	KeyInfo map[string]any `json:"keyInfo,omitempty" cbor:"keyInfo,omitempty"`
}

// KeyAuthorizations specifies what namespaces and data elements the device key is authorized to access.
type KeyAuthorizations struct {
	// NameSpaces lists authorized namespaces.
	NameSpaces []string `json:"nameSpaces,omitempty" cbor:"nameSpaces,omitempty"`

	// DataElements maps namespaces to authorized data element identifiers.
	DataElements map[string][]string `json:"dataElements,omitempty" cbor:"dataElements,omitempty"`
}

// ValidityInfo contains validity information for the mDL.
type ValidityInfo struct {
	// Signed is the timestamp when the MSO was signed.
	Signed time.Time `json:"signed" cbor:"signed" validate:"required"`

	// ValidFrom is the timestamp from which the MSO is valid.
	ValidFrom time.Time `json:"validFrom" cbor:"validFrom" validate:"required"`

	// ValidUntil is the timestamp until which the MSO is valid.
	ValidUntil time.Time `json:"validUntil" cbor:"validUntil" validate:"required"`

	// ExpectedUpdate is the expected timestamp for the next update (optional).
	ExpectedUpdate *time.Time `json:"expectedUpdate,omitempty" cbor:"expectedUpdate,omitempty"`
}

// MobileSecurityObject (MSO) contains the signed digest values and metadata.
type MobileSecurityObject struct {
	// Version is the MSO version (e.g., "1.0").
	Version string `json:"version" cbor:"version" validate:"required"`

	// DigestAlgorithm is the algorithm used for digests (e.g., "SHA-256", "SHA-512").
	DigestAlgorithm string `json:"digestAlgorithm" cbor:"digestAlgorithm" validate:"required,oneof=SHA-256 SHA-512"`

	// ValueDigests maps namespaces to digest ID → digest value mappings.
	ValueDigests map[string]map[uint][]byte `json:"valueDigests" cbor:"valueDigests" validate:"required"`

	// DeviceKeyInfo contains the device key information.
	DeviceKeyInfo DeviceKeyInfo `json:"deviceKeyInfo" cbor:"deviceKeyInfo" validate:"required"`

	// DocType is the document type (e.g., "org.iso.18013.5.1.mDL").
	DocType string `json:"docType" cbor:"docType" validate:"required"`

	// ValidityInfo contains validity timestamps.
	ValidityInfo ValidityInfo `json:"validityInfo" cbor:"validityInfo" validate:"required"`
}

// IssuerSignedItem represents a single signed data element.
type IssuerSignedItem struct {
	// DigestID is the digest identifier matching the MSO.
	DigestID uint `json:"digestID" cbor:"digestID" validate:"required"`

	// Random is random bytes for digest computation.
	Random []byte `json:"random" cbor:"random" validate:"required,min=16"`

	// ElementIdentifier is the data element identifier.
	ElementIdentifier string `json:"elementIdentifier" cbor:"elementIdentifier" validate:"required"`

	// ElementValue is the data element value.
	ElementValue any `json:"elementValue" cbor:"elementValue" validate:"required"`
}

// DeviceRequest represents a request for mdoc data.
type DeviceRequest struct {
	// Version is the request version (e.g., "1.0").
	Version string `json:"version" cbor:"version" validate:"required"`

	// DocRequests contains the document requests.
	DocRequests []DocRequest `json:"docRequests" cbor:"docRequests" validate:"required,dive"`
}

// DocRequest represents a request for a specific document type.
type DocRequest struct {
	// ItemsRequest is the CBOR-encoded items request.
	ItemsRequest []byte `json:"itemsRequest" cbor:"itemsRequest" validate:"required"`

	// ReaderAuth is the optional COSE_Sign1 reader authentication.
	ReaderAuth []byte `json:"readerAuth,omitempty" cbor:"readerAuth,omitempty"`
}

// ItemsRequest represents the decoded items request.
type ItemsRequest struct {
	// DocType is the requested document type.
	DocType string `json:"docType" cbor:"docType" validate:"required"`

	// NameSpaces maps namespaces to requested data elements with intent to retain.
	NameSpaces map[string]map[string]bool `json:"nameSpaces" cbor:"nameSpaces" validate:"required"`

	// RequestInfo contains optional additional request information.
	RequestInfo map[string]any `json:"requestInfo,omitempty" cbor:"requestInfo,omitempty"`
}

type DeviceResponseMdoc struct {
	Version        string          `cbor:"version"`
	Documents      []DocumentMdoc  `cbor:"documents,omitempty"`
	DocumentErrors []DocumentError `json:"documentErrors,omitempty" cbor:"documentErrors,omitempty"`
	Status         uint64          `cbor:"status"`
}

type DocumentError map[string]int

// Document represents the top-level mDL document structure.
type DocumentMdoc struct {
	DocType      string                    `json:"docType" cbor:"docType" validate:"required"`
	IssuerSigned IssuerSignedMdoc          `json:"issuerSigned" cbor:"issuerSigned" validate:"required"`
	DeviceSigned DeviceSignedMdoc          `json:"deviceSigned" cbor:"deviceSigned" validate:"required"`
	Errors       map[string]map[string]int `json:"errors,omitempty" cbor:"errors,omitempty"`
}

// IssuerSignedMdoc aligns with the nested COSE_Sign1 array format.
type IssuerSignedMdoc struct {
	NameSpaces map[string][]any `json:"nameSpaces" cbor:"nameSpaces"`

	// IssuerAuth is changed to 'any' to allow the 4-element COSE_Sign1
	// array to be encoded as a nested structure rather than a byte slice.
	IssuerAuth any `json:"issuerAuth" cbor:"issuerAuth" validate:"required"`
}

// DeviceSignedMdoc handles the DeviceNameSpaces Tag and DeviceAuth structure.
type DeviceSignedMdoc struct {
	// NameSpaces is changed to 'any' to allow for cbor.Tag{Number: 24}.
	NameSpaces any `json:"nameSpaces" cbor:"nameSpaces"`

	DeviceAuth DeviceAuthMdoc `json:"deviceAuth" cbor:"deviceAuth" validate:"required"`
}

// DeviceAuth ensures the signature is treated as a nested COSE signature.
type DeviceAuthMdoc struct {
	// DeviceSignature is an array: [protected, unprotected, payload, signature]
	DeviceSignature any `json:"deviceSignature,omitempty" cbor:"deviceSignature,omitempty"`

	// DeviceMac is the COSE_Mac0 device MAC (mutually exclusive with DeviceSignature).
	DeviceMac []any `json:"deviceMac,omitempty" cbor:"deviceMac,omitempty"`
}

// PID represents Person Identification Data attributes per the
// EU Digital Identity Wallet Architecture Reference Framework (ARF),
// PID Rulebook, namespace "eu.europa.ec.eudi.pid.1".
type PIDMDOC struct {
	// Mandatory elements

	// FamilyName is the current last name(s) or surname(s) of the PID holder.
	FamilyName string `json:"family_name" cbor:"family_name" validate:"required"`

	// GivenName is the current first name(s), including middle name(s) where applicable.
	GivenName string `json:"given_name" cbor:"given_name" validate:"required"`

	// BirthDate is the day, month, and year on which the PID holder was born.
	BirthDate string `json:"birth_date" cbor:"birth_date" validate:"required"`

	// AgeOver18 attests whether the PID holder is currently an adult (18+).
	AgeOver18 bool `json:"age_over_18" cbor:"age_over_18"`

	// IssuanceDate is the date when the PID was issued.
	IssuanceDate string `json:"issuance_date" cbor:"issuance_date" validate:"required"`

	// ExpiryDate is the date when the PID expires.
	ExpiryDate string `json:"expiry_date" cbor:"expiry_date" validate:"required"`

	// IssuingAuthority is the name of the administrative authority that issued the PID,
	// or the ISO 3166 Alpha-2/Alpha-3 country code of the member state if no authority is available.
	IssuingAuthority string `json:"issuing_authority" cbor:"issuing_authority" validate:"required"`

	// IssuingCountry is the country code (ISO 3166-1) of the country or organization
	// issuing the PID.
	IssuingCountry string `json:"issuing_country" cbor:"issuing_country" validate:"required,len=2,iso3166_1_alpha2"`

	// Optional elements

	// AgeInYears is the age of the PID holder in years.
	AgeInYears *uint `json:"age_in_years,omitempty" cbor:"age_in_years,omitempty" validate:"omitempty,min=0,max=150"`

	// AgeBirthYear is the year when the PID holder was born.
	AgeBirthYear *uint `json:"age_birth_year,omitempty" cbor:"age_birth_year,omitempty" validate:"omitempty,min=1900,max=2100"`

	// AgeOver contains additional age attestation statements for common thresholds
	// (e.g. 13, 16, 21, 60, 65, 68), beyond the mandatory age_over_18.
	AgeOver *AgeOver `json:"age_over,omitempty" cbor:"age_over,omitempty"`

	// FamilyNameBirth is the family name(s) of the PID holder at birth.
	FamilyNameBirth *string `json:"family_name_birth,omitempty" cbor:"family_name_birth,omitempty"`

	// GivenNameBirth is the first name(s) of the PID holder at birth.
	GivenNameBirth *string `json:"given_name_birth,omitempty" cbor:"given_name_birth,omitempty"`

	// BirthPlace is the country, state, and city where the PID holder was born.
	BirthPlace *string `json:"birth_place,omitempty" cbor:"birth_place,omitempty"`

	// BirthCountry is the country where the PID holder was born, as an Alpha-2 country code.
	BirthCountry *string `json:"birth_country,omitempty" cbor:"birth_country,omitempty" validate:"omitempty,len=2"`

	// BirthState is the state, province, district, or local area where the PID holder was born.
	BirthState *string `json:"birth_state,omitempty" cbor:"birth_state,omitempty"`

	// BirthCity is the municipality, city, town, or village where the PID holder was born.
	BirthCity *string `json:"birth_city,omitempty" cbor:"birth_city,omitempty"`

	// ResidentAddress is the full address of the PID holder's place of residence.
	ResidentAddress *string `json:"resident_address,omitempty" cbor:"resident_address,omitempty"`

	// ResidentCountry is the country where the PID holder currently resides (Alpha-2).
	ResidentCountry *string `json:"resident_country,omitempty" cbor:"resident_country,omitempty" validate:"omitempty,len=2"`

	// ResidentState is the state, province, district, or local area where the PID holder resides.
	ResidentState *string `json:"resident_state,omitempty" cbor:"resident_state,omitempty"`

	// ResidentCity is the municipality, city, town, or village where the PID holder resides.
	ResidentCity *string `json:"resident_city,omitempty" cbor:"resident_city,omitempty"`

	// ResidentPostalCode is the postal code of the PID holder's place of residence.
	ResidentPostalCode *string `json:"resident_postal_code,omitempty" cbor:"resident_postal_code,omitempty"`

	// ResidentStreet is the name of the street where the PID holder resides.
	ResidentStreet *string `json:"resident_street,omitempty" cbor:"resident_street,omitempty"`

	// ResidentHouseNumber is the house number, including any affix or suffix,
	// of the PID holder's place of residence.
	ResidentHouseNumber *string `json:"resident_house_number,omitempty" cbor:"resident_house_number,omitempty"`

	// Gender is the PID holder's gender using values as defined in ISO/IEC 5218.
	// 0 = not known, 1 = male, 2 = female, 9 = not applicable
	Gender *uint `json:"gender,omitempty" cbor:"gender,omitempty" validate:"omitempty,oneof=0 1 2 9"`

	// Nationality is one or more nationalities of the PID holder (Alpha-2 country codes).
	Nationality *string `json:"nationality,omitempty" cbor:"nationality,omitempty" validate:"omitempty,len=2"`

	// DocumentNumber is a number for the PID, assigned by the PID Provider.
	DocumentNumber *string `json:"document_number,omitempty" cbor:"document_number,omitempty"`

	// AdministrativeNumber is a number assigned by the PID Provider for audit control
	// or other purposes.
	AdministrativeNumber *string `json:"administrative_number,omitempty" cbor:"administrative_number,omitempty"`

	// IssuingJurisdiction is the country subdivision code (ISO 3166-2) of the
	// jurisdiction that issued the PID.
	IssuingJurisdiction *string `json:"issuing_jurisdiction,omitempty" cbor:"issuing_jurisdiction,omitempty"`

	// Portrait is a facial image of the PID holder.
	Portrait []byte `json:"portrait,omitempty" cbor:"portrait,omitempty"`

	// PortraitCaptureDate is the date when the portrait was taken.
	PortraitCaptureDate *time.Time `json:"portrait_capture_date,omitempty" cbor:"portrait_capture_date,omitempty"`

	// EmailAddress is the email address of the PID holder.
	EmailAddress *string `json:"email_address,omitempty" cbor:"email_address,omitempty" validate:"omitempty,email"`

	// MobilePhoneNumber is the mobile phone number of the PID holder, in E.164 format.
	MobilePhoneNumber *string `json:"mobile_phone_number,omitempty" cbor:"mobile_phone_number,omitempty"`

	// TrustAnchor is a URI pointing to the resolvable trust anchor used to
	// validate the PID's issuer.
	TrustAnchor *string `json:"trust_anchor,omitempty" cbor:"trust_anchor,omitempty" validate:"omitempty,uri"`

	// PseudonymSeed is a fixed-length seed value used to derive holder-specific
	// pseudonyms for pseudonymous authentication schemes. 
	PseudonymSeed []byte `json:"pseudonym_seed,omitempty" cbor:"pseudonym_seed,omitempty" validate:"omitempty,len=32"`

}