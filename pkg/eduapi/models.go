// Package eduapi provides an HTTP client for the 1EdTech Edu-API v1.0 specification.
// Edu-API is a REST/JSON API for accessing student information from Student Information
// Systems (SIS) such as Ladok.
package eduapi

// PersonResponse represents the Edu-API GET /persons/{personId} response.
type PersonResponse struct {
	Person Person `json:"person"`
}

// PersonsResponse represents the Edu-API GET /persons (collection) response.
type PersonsResponse struct {
	Persons []Person `json:"persons"`
}

// Person represents an Edu-API Person entity (1EdTech Edu-API §4.2).
type Person struct {
	SourcedID    string            `json:"sourcedId"`
	Status       string            `json:"status,omitempty"`
	DateLastMod  string            `json:"dateLastModified,omitempty"`
	Name         PersonName        `json:"name"`
	Identifiers  []IdentifierEntry `json:"identifiers,omitempty"`
	Email        []TypedContact    `json:"email,omitempty"`
	Phone        []TypedContact    `json:"phone,omitempty"`
	Address      []Address         `json:"address,omitempty"`
	Demographics *Demographics     `json:"demographics,omitempty"`
	Roles        []Role            `json:"roles,omitempty"`
	Agents       []AgentRef        `json:"agents,omitempty"`
	Extensions   map[string]any    `json:"extensions,omitempty"`
}

// PersonName represents name fields for a Person.
type PersonName struct {
	FamilyName    string              `json:"familyName"`
	GivenName     string              `json:"givenName"`
	MiddleName    string              `json:"middleName,omitempty"`
	PreferredName *LanguageTypedValue `json:"preferredName,omitempty"`
	FormattedName *LanguageTypedValue `json:"formattedName,omitempty"`
}

// LanguageTypedValue represents a value with an associated language tag.
type LanguageTypedValue struct {
	Value    string `json:"value"`
	Language string `json:"language,omitempty"`
	Type     string `json:"type,omitempty"`
}

// IdentifierEntry represents an external identifier for a Person.
type IdentifierEntry struct {
	IdentifierType string `json:"identifierType"`
	Identifier     string `json:"identifier"`
}

// TypedContact represents a typed contact entry (email/phone).
type TypedContact struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Address represents a postal address.
type Address struct {
	Type          string `json:"type,omitempty"`
	StreetAddress string `json:"streetAddress,omitempty"`
	Locality      string `json:"locality,omitempty"`
	Region        string `json:"region,omitempty"`
	PostalCode    string `json:"postalCode,omitempty"`
	Country       string `json:"country,omitempty"`
}

// Demographics holds demographic information for a Person.
type Demographics struct {
	BirthDate string `json:"birthDate,omitempty"`
	Sex       string `json:"sex,omitempty"`
}

// Role represents a role a person holds within an organization.
type Role struct {
	RoleType string  `json:"roleType"`
	Role     string  `json:"role"`
	OrgRef   GUIDRef `json:"org,omitempty"`
}

// AgentRef represents a reference to an agent (advisor, parent, etc.).
type AgentRef struct {
	AgentType string  `json:"agentType"`
	PersonRef GUIDRef `json:"person"`
}

// GUIDRef is a reference by sourcedId and optionally href/type.
type GUIDRef struct {
	SourcedID string `json:"sourcedId"`
	Href      string `json:"href,omitempty"`
	Type      string `json:"type,omitempty"`
}

// EnrollmentsResponse represents the Edu-API enrollments collection response.
type EnrollmentsResponse struct {
	Enrollments []Enrollment `json:"enrollments"`
}

// Enrollment represents a student enrollment in a class or course section.
type Enrollment struct {
	SourcedID   string         `json:"sourcedId"`
	Status      string         `json:"status,omitempty"`
	DateLastMod string         `json:"dateLastModified,omitempty"`
	PersonRef   GUIDRef        `json:"user"`
	ClassRef    GUIDRef        `json:"class"`
	Role        string         `json:"role"`
	Primary     bool           `json:"primary,omitempty"`
	BeginDate   string         `json:"beginDate,omitempty"`
	EndDate     string         `json:"endDate,omitempty"`
	Extensions  map[string]any `json:"extensions,omitempty"`
}

// CourseOfferingsResponse represents the Edu-API course offerings collection response.
type CourseOfferingsResponse struct {
	CourseOfferings []CourseOffering `json:"courseOfferings"`
}

// CourseOffering represents a course offering (class/section) in the Edu-API.
type CourseOffering struct {
	SourcedID    string         `json:"sourcedId"`
	Status       string         `json:"status,omitempty"`
	DateLastMod  string         `json:"dateLastModified,omitempty"`
	Title        string         `json:"title"`
	CourseCode   string         `json:"courseCode,omitempty"`
	ClassType    string         `json:"classType,omitempty"`
	SchoolRef    GUIDRef        `json:"school,omitempty"`
	TermRefs     []GUIDRef      `json:"terms,omitempty"`
	CourseRef    GUIDRef        `json:"course,omitempty"`
	Periods      []string       `json:"periods,omitempty"`
	SubjectCodes []string       `json:"subjectCodes,omitempty"`
	Grades       []string       `json:"grades,omitempty"`
	Extensions   map[string]any `json:"extensions,omitempty"`
}

// CollectionOfferingsResponse represents the Edu-API collection offerings (programs) response.
type CollectionOfferingsResponse struct {
	CollectionOfferings []CollectionOffering `json:"collectionOfferings"`
}

// CollectionOffering represents a programme of study (e.g. a degree programme).
type CollectionOffering struct {
	SourcedID    string         `json:"sourcedId"`
	Status       string         `json:"status,omitempty"`
	DateLastMod  string         `json:"dateLastModified,omitempty"`
	Title        string         `json:"title"`
	OfferingType string         `json:"collectionType,omitempty"`
	SchoolRef    GUIDRef        `json:"school,omitempty"`
	CourseRefs   []GUIDRef      `json:"courses,omitempty"`
	Extensions   map[string]any `json:"extensions,omitempty"`
}

// OrganizationsResponse represents the Edu-API organizations collection response.
type OrganizationsResponse struct {
	Organizations []Organization `json:"orgs"`
}

// Organization represents an educational institution or unit.
type Organization struct {
	SourcedID    string         `json:"sourcedId"`
	Status       string         `json:"status,omitempty"`
	DateLastMod  string         `json:"dateLastModified,omitempty"`
	Name         string         `json:"name"`
	Type         string         `json:"type,omitempty"`
	Identifier   string         `json:"identifier,omitempty"`
	ParentRef    *GUIDRef       `json:"parent,omitempty"`
	ChildrenRefs []GUIDRef      `json:"children,omitempty"`
	Extensions   map[string]any `json:"extensions,omitempty"`
}

// AcademicSessionsResponse represents the Edu-API academic sessions collection response.
type AcademicSessionsResponse struct {
	AcademicSessions []AcademicSession `json:"academicSessions"`
}

// AcademicSession represents a term, semester, or academic year.
type AcademicSession struct {
	SourcedID    string         `json:"sourcedId"`
	Status       string         `json:"status,omitempty"`
	DateLastMod  string         `json:"dateLastModified,omitempty"`
	Title        string         `json:"title"`
	Type         string         `json:"type"`
	StartDate    string         `json:"startDate"`
	EndDate      string         `json:"endDate"`
	ParentRef    *GUIDRef       `json:"parent,omitempty"`
	ChildrenRefs []GUIDRef      `json:"children,omitempty"`
	SchoolYear   string         `json:"schoolYear,omitempty"`
	Extensions   map[string]any `json:"extensions,omitempty"`
}

// ResultsResponse represents the Edu-API results collection response.
type ResultsResponse struct {
	Results []Result `json:"results"`
}

// Result represents a grade or score for an enrollment.
type Result struct {
	SourcedID   string         `json:"sourcedId"`
	Status      string         `json:"status,omitempty"`
	DateLastMod string         `json:"dateLastModified,omitempty"`
	PersonRef   GUIDRef        `json:"student"`
	ClassRef    GUIDRef        `json:"lineItem"`
	Score       string         `json:"score,omitempty"`
	ScoreStatus string         `json:"scoreStatus,omitempty"`
	ScoreDate   string         `json:"scoreDate,omitempty"`
	Comment     string         `json:"comment,omitempty"`
	Extensions  map[string]any `json:"extensions,omitempty"`
}
