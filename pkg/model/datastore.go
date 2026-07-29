package model

import (
	"encoding/json"
	"time"
)

// CompleteDocument is a generic type for upload
type CompleteDocument struct {
	Meta               *MetaData      `json:"meta,omitempty" bson:"meta" validate:"required"`
	IdentityMappingIDs []string       `json:"identity_mapping_ids,omitempty" bson:"identity_mapping_ids" validate:"required,min=1"`
	DocumentData       map[string]any `json:"document_data,omitempty" bson:"document_data" validate:"required"`
}

// DocumentList is a generic type for document list
type DocumentList struct {
	Meta *MetaData `json:"meta,omitempty" bson:"meta" validate:"required"`
}

// Document is a generic type for get document
type Document struct {
	Meta         *MetaData `json:"meta,omitempty" bson:"meta" validate:"required"`
	DocumentData any       `json:"document_data" bson:"document_data" validate:"required"`
}

// MetaData is a generic type for metadata
type MetaData struct {
	// required: true
	// example: SUNET
	AuthenticSource string `json:"authentic_source,omitempty" bson:"authentic_source" validate:"required,max=128,printascii"`

	// Scope is the credential configuration ID scope
	// required: false
	// example: "ehic", "pda1"
	Scope string `json:"scope,omitempty" bson:"scope" validate:"required,max=128,printascii"`

	// required: false
	// example: 5e7a981c-c03f-11ee-b116-9b12c59362b9
	DocumentID string `json:"document_id,omitempty" bson:"document_id" validate:"omitempty,max=128,printascii"`

	// required: false
	// example: file://path/to/schema.json or http://example.com/schema.json
	// format: string
	DocumentDataValidationRef string `json:"document_data_validation,omitempty" bson:"document_data_validation" validate:"omitempty,max=128,printascii"`

	// CreatedAt is the timestamp when the document was created
	CreatedAt time.Time `json:"created_at" bson:"created_at"`

	// ValidNotAfter is an optional expiration timestamp for administrative purposes.
	// Documents past this time should not be used.
	ValidNotAfter *time.Time `json:"valid_not_after,omitempty" bson:"valid_not_after,omitempty"`
}

// Identity identifies a person
type Identity struct {
	// required: true
	// example: 65636cbc-c03f-11ee-8dc4-67135cc9bd8a
	AuthenticSourcePersonID string `json:"authentic_source_person_id,omitempty" bson:"authentic_source_person_id" validate:"required,max=128,printascii"`

	// required: true
	// example: Svensson
	FamilyName string `json:"family_name" bson:"family_name" validate:"required,min=1,max=100,printascii"`

	// required: true
	// example: Magnus
	GivenName string `json:"given_name" bson:"given_name" validate:"required,min=1,max=100,printascii"`

	// required: true
	// example: 1970-01-01 TODO: Day, month, and year?
	BirthDate string `json:"birth_date" bson:"birth_date" validate:"required,datetime=2006-01-02,printascii"`

	// required: true
	// example: Stockholm
	BirthPlace string `json:"birth_place,omitempty" bson:"birth_place,omitempty" validate:"omitempty,min=2,max=100,printascii"`

	// required: true
	// example: SE
	Nationality []string `json:"nationality,omitempty" bson:"nationality,omitempty" validate:"omitempty,dive,iso3166_1_alpha2"`

	// required: false
	// example: <personnummer>
	PersonalAdministrativeNumber string `json:"personal_administrative_number,omitempty" bson:"personal_administrative_number,omitempty" validate:"omitempty,min=4,max=50,printascii"`

	// required: false
	// example: facial image compliant with ISO 19794-5 or ISO 39794 specifications
	Picture string `json:"picture,omitempty" bson:"picture,omitempty"`

	BirthFamilyName string `json:"birth_family_name,omitempty" bson:"birth_family_name,omitempty" validate:"omitempty,min=1,max=100,printascii"`

	BirthGivenName string `json:"birth_given_name,omitempty" bson:"birth_given_name,omitempty" validate:"omitempty,min=1,max=100,printascii"`

	// required: false
	// example: 0 = not known, 1 = male, 2 = female, ...
	Sex string `json:"sex,omitempty" bson:"sex,omitempty" validate:"omitempty,oneof=0 1 2 3 4 5 6 7 8 9"`

	// required: false
	// example: <email-address>
	EmailAddress string `json:"email_address,omitempty" bson:"email_address,omitempty" validate:"omitempty,email"`

	// required: false
	// example: <+mobile-phone-number>
	MobilePhoneNumber string `json:"mobile_phone_number,omitempty" bson:"mobile_phone_number,omitempty" validate:"omitempty,e164"`

	// required: false
	// example: 221b Baker street
	ResidentAddress string `json:"resident_address,omitempty" bson:"resident_address,omitempty" validate:"omitempty,printascii"`

	// required: false
	// example: Baker street
	ResidentStreetAddress string `json:"resident_street_address,omitempty" bson:"resident_street_address,omitempty" validate:"omitempty,min=1,max=100,printascii"`

	// required: false
	// example: 221b
	ResidentHouseNumber string `json:"resident_house_number,omitempty" bson:"resident_house_number,omitempty" validate:"omitempty,printascii"`

	// required: false
	// example: W1U 6SG
	ResidentPostalCode string `json:"resident_postal_code,omitempty" bson:"resident_postal_code,omitempty" validate:"omitempty,printascii"`

	// required: false
	// example: London
	ResidentCity string `json:"resident_city,omitempty" bson:"resident_city,omitempty" validate:"omitempty,printascii"`
	// required: false
	// example: england
	ResidentState string `json:"resident_state,omitempty" bson:"resident_state,omitempty" validate:"omitempty,printascii"`
	// required: false
	// example: England
	ResidentCountry string `json:"resident_country,omitempty" bson:"resident_country,omitempty" validate:"omitempty,iso3166_1_alpha2"`

	AgeOver14 string `json:"age_over_14,omitempty" bson:"age_over_14,omitempty"`

	AgeOver16 bool `json:"age_over_16,omitempty" bson:"age_over_16,omitempty"`

	AgeOver18 bool `json:"age_over_18,omitempty" bson:"age_over_18,omitempty"`

	AgeOver21 bool `json:"age_over_21,omitempty" bson:"age_over_21,omitempty"`

	AgeOver65 bool `json:"age_over_65,omitempty" bson:"age_over_65,omitempty"`

	AgeInYears int `json:"age_in_years,omitempty" bson:"age_in_years,omitempty"`

	AgeBirthYear int `json:"age_birth_year,omitempty" bson:"age_birth_year,omitempty"`

	// required: false
	// example:
	IssuingAuthority string `json:"issuing_authority,omitempty" bson:"issuing_authority,omitempty" validate:"omitempty,printascii"`
	// required: false
	// example:
	IssuingCountry string `json:"issuing_country,omitempty" bson:"issuing_country,omitempty" validate:"omitempty,iso3166_1_alpha2"`

	// required: false
	// example: Date (and if possible time)
	ExpiryDate string `json:"expiry_date,omitempty" bson:"expiry_date,omitempty" validate:"omitempty,datetime=2006-01-02"`

	IssuanceDate string `json:"issuance_date,omitempty" bson:"issuance_date,omitempty"`

	// required: false
	// example:
	DocumentNumber string `json:"document_number,omitempty" bson:"document_number,omitempty" validate:"omitempty,max=128,printascii"`

	// required: false
	// example:
	IssuingJurisdiction string `json:"issuing_jurisdiction,omitempty" bson:"issuing_jurisdiction,omitempty" validate:"omitempty,max=128,printascii"`
}

// isLeapYear checks if a year is a leap year
func isLeapYear(year int) bool {
	return year%4 == 0 && (year%100 != 0 || year%400 == 0)
}

// ageThresholdDate calculates the date when someone reaches a certain age.
// For leap year birthdays (Feb 29), the threshold falls on Feb 28 in non-leap years.
// This is the convention used in most EU member states and is the safer default for
// age-gating (treats the person as having reached the age one day earlier rather than later).
// Without this, Go's AddDate normalizes Feb 29 → Mar 1, which would delay the threshold.
func ageThresholdDate(birthDate time.Time, years int) time.Time {
	targetYear := birthDate.Year() + years
	month := birthDate.Month()
	day := birthDate.Day()

	// Handle leap year birthday (Feb 29) in non-leap target year
	if month == 2 && day == 29 && !isLeapYear(targetYear) {
		// Use Feb 28 instead of letting Go normalize to March 1
		return time.Date(targetYear, 2, 28, 0, 0, 0, 0, birthDate.Location())
	}

	return birthDate.AddDate(years, 0, 0)
}

func (i *Identity) GetOver14() (bool, error) {
	birthDay, err := time.Parse("2006-01-02", i.BirthDate)
	if err != nil {
		return false, err
	}
	threshold := ageThresholdDate(birthDay, 14)
	return !time.Now().UTC().Before(threshold), nil
}

func (i *Identity) GetOver16() (bool, error) {
	birthDay, err := time.Parse("2006-01-02", i.BirthDate)
	if err != nil {
		return false, err
	}
	threshold := ageThresholdDate(birthDay, 16)
	return !time.Now().UTC().Before(threshold), nil
}

func (i *Identity) GetOver18() (bool, error) {
	birthDay, err := time.Parse("2006-01-02", i.BirthDate)
	if err != nil {
		return false, err
	}
	threshold := ageThresholdDate(birthDay, 18)
	return !time.Now().UTC().Before(threshold), nil
}

func (i *Identity) GetOver21() (bool, error) {
	birthDay, err := time.Parse("2006-01-02", i.BirthDate)
	if err != nil {
		return false, err
	}
	threshold := ageThresholdDate(birthDay, 21)
	return !time.Now().UTC().Before(threshold), nil
}

func (i *Identity) GetOver65() (bool, error) {
	birthDay, err := time.Parse("2006-01-02", i.BirthDate)
	if err != nil {
		return false, err
	}
	threshold := ageThresholdDate(birthDay, 65)
	return !time.Now().UTC().Before(threshold), nil
}

func (i *Identity) GetAgeInYears() (int, error) {
	birthDay, err := time.Parse("2006-01-02", i.BirthDate)
	if err != nil {
		return 0, err
	}
	now := time.Now().UTC()
	age := now.Year() - birthDay.Year()
	threshold := ageThresholdDate(birthDay, age)
	if now.Before(threshold) {
		age--
	}
	return age, nil
}

// Marshal marshals the document to a map
func (i *Identity) Marshal() (map[string]any, error) {
	data, err := json.Marshal(i)
	if err != nil {
		return nil, err
	}

	var doc map[string]any
	err = json.Unmarshal(data, &doc)
	if err != nil {
		return nil, err
	}

	return doc, nil
}

// SearchDocumentsReply the reply from search documents
type SearchDocumentsReply struct {
	Documents      []*CompleteDocument `json:"documents"`
	HasMoreResults bool                `json:"has_more_results"`
}

// SearchDocumentsRequest the request to search for documents
type SearchDocumentsRequest struct {
	AuthenticSource string `json:"authentic_source,omitempty" validate:"omitempty,max=1000,excludesall=${}[]"`
	Scope           string `json:"scope,omitempty" validate:"omitempty,max=1000,excludesall=${}[]"`
	DocumentID      string `json:"document_id,omitempty" validate:"omitempty,max=1000,excludesall=${}[]"`
	CollectID       string `json:"collect_id,omitempty" validate:"omitempty,max=1000,excludesall=${}[]"`

	AuthenticSourcePersonID string `json:"authentic_source_person_id,omitempty" validate:"omitempty,max=1000,excludesall=${}[]"`

	Limit      int64          `json:"limit,omitempty" validate:"omitempty,min=0,max=1000"`
	Fields     []string       `json:"fields,omitempty" validate:"omitempty,dive,max=100,excludesall=${}[]"`
	SortFields map[string]int `json:"sort_fields,omitempty" validate:"omitempty,dive,keys,max=100,endkeys,oneof=1 -1"`
}
