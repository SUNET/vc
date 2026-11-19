// Package eduapi provides an HTTP client for the 1EdTech Edu-API v1.0 Final specification.
// Edu-API is a REST/JSON API for accessing student information from Student Information
// Systems (SIS) such as Ladok.
//
// Field names follow the OpenAPI 3 schema at
// https://purl.imsglobal.org/spec/eduapi/v1p0/schema/openapi/eduapi_v1p0_openapi3.json.
// Responses are bare JSON objects and arrays; references between records are sourcedIds.
package eduapi

// Person represents an Edu-API Person entity.
type Person struct {
	SourcedID        string                `json:"sourcedId"`
	RecordLanguage   string                `json:"recordLanguage,omitempty"`
	RecordStatus     string                `json:"recordStatus,omitempty"`
	DateLastModified string                `json:"dateLastModified,omitempty"`
	LegalName        *PersonName           `json:"legalName,omitempty"`
	FormattedName    string                `json:"formattedName,omitempty"`
	DateOfBirth      string                `json:"dateOfBirth,omitempty"`
	Gender           string                `json:"gender,omitempty"`
	PrimaryEmail     *OptionallyTypedEmail `json:"primaryEmail,omitempty"`
	OtherEmails      []TypedEmail          `json:"otherEmails,omitempty"`
	PrimaryPhone     *OptionallyTypedPhone `json:"primaryPhone,omitempty"`
	OtherPhones      []TypedPhone          `json:"otherPhones,omitempty"`
	OtherIdentifiers []IdentifierEntry     `json:"otherIdentifiers,omitempty"`
}

// PersonName holds the parts of a person's name.
type PersonName struct {
	GivenName      string `json:"givenName,omitempty"`
	FamilyName     string `json:"familyName,omitempty"`
	AdditionalName string `json:"additionalName,omitempty"`
}

// OptionallyTypedEmail is a primary email address with an optional type.
type OptionallyTypedEmail struct {
	Email     string `json:"email"`
	EmailType string `json:"emailType,omitempty"`
}

// TypedEmail is an email address with a type.
type TypedEmail struct {
	Email     string `json:"email"`
	EmailType string `json:"emailType,omitempty"`
}

// OptionallyTypedPhone is a primary phone number with an optional type.
type OptionallyTypedPhone struct {
	Phone     string `json:"phone"`
	PhoneType string `json:"phoneType,omitempty"`
}

// TypedPhone is a phone number with a type.
type TypedPhone struct {
	Phone     string `json:"phone"`
	PhoneType string `json:"phoneType,omitempty"`
}

// IdentifierEntry is a typed identifier, e.g. a national identity number.
type IdentifierEntry struct {
	IdentifierType string `json:"identifierType"`
	Identifier     string `json:"identifier"`
}

// LanguageTypedString is a string with a language tag.
type LanguageTypedString struct {
	RecordLanguage string `json:"recordLanguage"`
	Value          string `json:"value"`
}

// Enrollment joins a person to an education offering.
type Enrollment struct {
	SourcedID         string `json:"sourcedId"`
	RecordLanguage    string `json:"recordLanguage,omitempty"`
	RecordStatus      string `json:"recordStatus,omitempty"`
	DateLastModified  string `json:"dateLastModified,omitempty"`
	Person            string `json:"person"`
	EducationOffering string `json:"educationOffering"`
	OfferingType      string `json:"offeringType"`
	Role              string `json:"role"`
	EnrollmentStatus  string `json:"enrollmentStatus,omitempty"`
	IsActive          bool   `json:"isActive"`
	StartDate         string `json:"startDate,omitempty"`
	EndDate           string `json:"endDate,omitempty"`
}

// CourseOffering is an instance of a course in an academic session.
type CourseOffering struct {
	SourcedID          string                `json:"sourcedId"`
	RecordLanguage     string                `json:"recordLanguage,omitempty"`
	RecordStatus       string                `json:"recordStatus,omitempty"`
	DateLastModified   string                `json:"dateLastModified,omitempty"`
	Title              []LanguageTypedString `json:"title,omitempty"`
	Description        []LanguageTypedString `json:"description,omitempty"`
	PrimaryCode        *IdentifierEntry      `json:"primaryCode,omitempty"`
	OfferingType       string                `json:"offeringType,omitempty"`
	OfferingFormat     string                `json:"offeringFormat,omitempty"`
	RegistrationStatus string                `json:"registrationStatus,omitempty"`
	Course             string                `json:"course,omitempty"`
	Organization       string                `json:"organization,omitempty"`
	AcademicSession    string                `json:"academicSession,omitempty"`
	Parent             []string              `json:"parent,omitempty"`
	StartDate          string                `json:"startDate,omitempty"`
	EndDate            string                `json:"endDate,omitempty"`
}

// Organization is an educational institution or unit.
type Organization struct {
	SourcedID        string                `json:"sourcedId"`
	RecordLanguage   string                `json:"recordLanguage,omitempty"`
	RecordStatus     string                `json:"recordStatus,omitempty"`
	DateLastModified string                `json:"dateLastModified,omitempty"`
	Name             []LanguageTypedString `json:"name,omitempty"`
	Description      []LanguageTypedString `json:"description,omitempty"`
	OrganizationType string                `json:"organizationType,omitempty"`
	PrimaryCode      *IdentifierEntry      `json:"primaryCode,omitempty"`
	Parent           string                `json:"parent,omitempty"`
}

// AcademicSession is a term, semester or academic year.
type AcademicSession struct {
	SourcedID        string                `json:"sourcedId"`
	RecordLanguage   string                `json:"recordLanguage,omitempty"`
	RecordStatus     string                `json:"recordStatus,omitempty"`
	DateLastModified string                `json:"dateLastModified,omitempty"`
	Title            []LanguageTypedString `json:"title,omitempty"`
	SessionType      string                `json:"sessionType,omitempty"`
	PrimaryCode      *IdentifierEntry      `json:"primaryCode,omitempty"`
	Parent           string                `json:"parent,omitempty"`
	StartDate        string                `json:"startDate,omitempty"`
	EndDate          string                `json:"endDate,omitempty"`
}
