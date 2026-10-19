// Package oeapi provides an HTTP client for the Open Education API (OEAPI) v6.0
// specification. OEAPI is a REST/JSON API for accessing educational data (persons,
// offerings, enrolments and results) from Student Information Systems.
package oeapi

// CodeRef is an OEAPI identifier pair (codeType + code), used for primaryCode and otherCodes.
type CodeRef struct {
	CodeType string `json:"codeType,omitempty"`
	Code     string `json:"code,omitempty"`
}

// Country holds ISO 3166 country codes.
type Country struct {
	Alpha2 string `json:"iso3166-1-alpha2,omitempty"`
	Alpha3 string `json:"iso3166-1-alpha3,omitempty"`
}

// LanguageTypedString is an OEAPI multilingual value ({language, value}).
type LanguageTypedString struct {
	Language string `json:"language,omitempty"`
	Value    string `json:"value,omitempty"`
}

// Page is a generic OEAPI paginated collection response.
type Page[T any] struct {
	PageSize        int  `json:"pageSize"`
	PageNumber      int  `json:"pageNumber"`
	HasPreviousPage bool `json:"hasPreviousPage"`
	HasNextPage     bool `json:"hasNextPage"`
	TotalPages      *int `json:"totalPages,omitempty"`
	Items           []T  `json:"items"`
}

// Person represents an OEAPI Person entity (GET /persons/{personId}).
type Person struct {
	PersonID          string         `json:"personId"`
	PrimaryCode       *CodeRef       `json:"primaryCode,omitempty"`
	GivenName         string         `json:"givenName,omitempty"`
	AlternateName     string         `json:"alternateName,omitempty"`
	PreferredName     string         `json:"preferredName,omitempty"`
	SurnamePrefix     string         `json:"surnamePrefix,omitempty"`
	Surname           string         `json:"surname,omitempty"`
	DisplayName       string         `json:"displayName,omitempty"`
	Initials          string         `json:"initials,omitempty"`
	IDCheckName       string         `json:"idCheckName,omitempty"`
	ActiveEnrolment   bool           `json:"activeEnrolment,omitempty"`
	DateOfBirth       string         `json:"dateOfBirth,omitempty"`
	CityOfBirth       string         `json:"cityOfBirth,omitempty"`
	CountryOfBirth    *Country       `json:"countryOfBirth,omitempty"`
	Nationality       *Country       `json:"nationality,omitempty"`
	DateOfNationality string         `json:"dateOfNationality,omitempty"`
	Affiliations      []string       `json:"affiliations,omitempty"`
	Email             string         `json:"email,omitempty"`
	SecondaryEmail    string         `json:"secondaryEmail,omitempty"`
	TelephoneNumber   string         `json:"telephoneNumber,omitempty"`
	MobileNumber      string         `json:"mobileNumber,omitempty"`
	Gender            string         `json:"gender,omitempty"`
	TitlePrefix       string         `json:"titlePrefix,omitempty"`
	TitleSuffix       string         `json:"titleSuffix,omitempty"`
	OtherCodes        []CodeRef      `json:"otherCodes,omitempty"`
	Ext               map[string]any `json:"ext,omitempty"`
}

// Result represents the embedded result of an association (grade/outcome).
type Result struct {
	State          string     `json:"state,omitempty"`
	Pass           string     `json:"pass,omitempty"`
	Comment        string     `json:"comment,omitempty"`
	Score          string     `json:"score,omitempty"`
	RawScore       *float64   `json:"rawScore,omitempty"`
	MaxRawScore    *float64   `json:"maxRawScore,omitempty"`
	Final          bool       `json:"final,omitempty"`
	ResultDateTime string     `json:"resultDateTime,omitempty"`
	StudyLoad      *StudyLoad `json:"studyLoad,omitempty"`
}

// StudyLoad represents a study load value (e.g. ECTS credits).
type StudyLoad struct {
	StudyLoadUnit string  `json:"studyLoadUnit,omitempty"`
	Value         float64 `json:"value,omitempty"`
}

// Programme represents an OEAPI programme of study.
type Programme struct {
	ProgrammeID          string                `json:"programmeId,omitempty"`
	PrimaryCode          *CodeRef              `json:"primaryCode,omitempty"`
	ProgrammeType        string                `json:"programmeType,omitempty"`
	Name                 []LanguageTypedString `json:"name,omitempty"`
	Abbreviation         string                `json:"abbreviation,omitempty"`
	QualificationAwarded string                `json:"qualificationAwarded,omitempty"`
	LevelOfQualification string                `json:"levelOfQualification,omitempty"`
	Level                string                `json:"level,omitempty"`
	FieldsOfStudy        string                `json:"fieldsOfStudy,omitempty"`
}

// Course represents an OEAPI course.
type Course struct {
	CourseID     string                `json:"courseId,omitempty"`
	PrimaryCode  *CodeRef              `json:"primaryCode,omitempty"`
	Name         []LanguageTypedString `json:"name,omitempty"`
	Abbreviation string                `json:"abbreviation,omitempty"`
}

// Organisation represents an OEAPI organisation (institution or unit).
type Organisation struct {
	OrganisationID   string                `json:"organisationId,omitempty"`
	PrimaryCode      *CodeRef              `json:"primaryCode,omitempty"`
	OrganisationType string                `json:"organisationType,omitempty"`
	Name             []LanguageTypedString `json:"name,omitempty"`
	ShortName        string                `json:"shortName,omitempty"`
}

// AcademicSession represents an OEAPI academic session (term, semester, year).
type AcademicSession struct {
	AcademicSessionID   string                `json:"academicSessionId,omitempty"`
	AcademicSessionType string                `json:"academicSessionType,omitempty"`
	PrimaryCode         *CodeRef              `json:"primaryCode,omitempty"`
	Name                []LanguageTypedString `json:"name,omitempty"`
	Abbreviation        string                `json:"abbreviation,omitempty"`
	StartDateTime       string                `json:"startDateTime,omitempty"`
	EndDateTime         string                `json:"endDateTime,omitempty"`
}

// ProgrammeOffering represents an OEAPI programme offering.
type ProgrammeOffering struct {
	ProgrammeOfferingID string                `json:"programmeOfferingId,omitempty"`
	PrimaryCode         *CodeRef              `json:"primaryCode,omitempty"`
	Name                []LanguageTypedString `json:"name,omitempty"`
	Abbreviation        string                `json:"abbreviation,omitempty"`
	Programme           *Programme            `json:"programme,omitempty"`
	Organisation        *Organisation         `json:"organisation,omitempty"`
	AcademicSession     *AcademicSession      `json:"academicSession,omitempty"`
}

// CourseOffering represents an OEAPI course offering.
type CourseOffering struct {
	CourseOfferingID string                `json:"courseOfferingId,omitempty"`
	PrimaryCode      *CodeRef              `json:"primaryCode,omitempty"`
	Name             []LanguageTypedString `json:"name,omitempty"`
	Abbreviation     string                `json:"abbreviation,omitempty"`
	Course           *Course               `json:"course,omitempty"`
	Organisation     *Organisation         `json:"organisation,omitempty"`
	AcademicSession  *AcademicSession      `json:"academicSession,omitempty"`
}

// ProgrammeOfferingAssociation represents a person's enrolment in a programme offering.
type ProgrammeOfferingAssociation struct {
	AssociationID       string             `json:"associationId"`
	Role                string             `json:"role,omitempty"`
	State               string             `json:"state,omitempty"`
	StartDateTime       string             `json:"startDateTime,omitempty"`
	ExpectedEndDateTime string             `json:"expectedEndDateTime,omitempty"`
	ActualEndDateTime   string             `json:"actualEndDateTime,omitempty"`
	Result              *Result            `json:"result,omitempty"`
	ProgrammeOfferingID string             `json:"programmeOfferingId,omitempty"`
	ProgrammeOffering   *ProgrammeOffering `json:"programmeOffering,omitempty"`
}

// CourseOfferingAssociation represents a person's enrolment in a course offering.
type CourseOfferingAssociation struct {
	AssociationID       string          `json:"associationId"`
	Role                string          `json:"role,omitempty"`
	State               string          `json:"state,omitempty"`
	StartDateTime       string          `json:"startDateTime,omitempty"`
	ExpectedEndDateTime string          `json:"expectedEndDateTime,omitempty"`
	ActualEndDateTime   string          `json:"actualEndDateTime,omitempty"`
	Result              *Result         `json:"result,omitempty"`
	CourseOfferingID    string          `json:"courseOfferingId,omitempty"`
	CourseOffering      *CourseOffering `json:"courseOffering,omitempty"`
}
