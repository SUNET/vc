# Edu-API Integration Plan

## Overview

This document describes how to integrate [1EdTech Edu-API v1.0](https://www.imsglobal.org/spec/eduapi/v1p0) as an outbound data source for credential issuance in the VC system. Edu-API is a REST/JSON specification for exchanging education data — courses, enrollments, persons, organizations, and academic sessions — between a Student Information System (SIS) and downstream consumers.

In the VC context, the **issuer** acts as an **Edu-API Consumer**: it makes outbound HTTP GET calls to the institution's SIS (the Edu-API Provider) to fetch authoritative data about students, enrollments, and programs, then maps that data into verifiable credential claims.

### Architectural Decision

1. Edu-API is a **read-only pull model** (all 49 endpoints are GET). This makes it an outbound data source, similar to OIDC discovery or MDQ metadata fetching.
2. Edu-API uses **OAuth 2.0 Client Credentials Grant** for authentication, which aligns with existing patterns in the codebase (`http.Client` with token management).
3. The data model maps cleanly to education credential types already supported (diploma, ELM, micro-credential, eduID).
4. Edu-API also defines a **Pub/Sub binding** for async event-driven data, which could map to the existing Kafka inbound handler in a future phase.

---

## User Story: Lisa Gets a Program Enrollment Credential

Lisa is a 24-year-old student enrolled in the Master's programme in Computer Science at Stockholm University. She wants a verifiable credential that proves she is an active student on this specific programme — something she can present digitally to get student discounts, access academic services at partner institutions, or include in a job application.

### The Swedish Higher Education Landscape

In Sweden, **Ladok** is the national student information system used by all universities and higher education institutions. Ladok is the authoritative source for student registrations, course enrolments, credits, and degrees. It is operated by the Ladok consortium and used by ~40 universities including Stockholm University, Uppsala University, KTH, Lund University, and others.

Ladok has implemented the Edu-API specification, making it the central Edu-API Provider for Swedish higher education. This means the VC Issuer can connect to a single system (Ladok) to fetch enrolment data for students at any Swedish university.

```
┌──────────────────────────────────────────────────────────────┐
│                    Swedish Higher Education                   │
│                                                              │
│  Stockholm Uni ──┐                                           │
│  Uppsala Uni ────┤                                           │
│  KTH ────────────┼──▶  Ladok (National SIS)                 │
│  Lund Uni ───────┤     ├── Student registrations             │
│  Gothenburg Uni ─┘     ├── Course enrolments                 │
│                        ├── Credits & degrees                 │
│                        └── Edu-API REST interface            │
│                              │                               │
│                              │ OAuth 2.0 + Edu-API           │
│                              ▼                               │
│                        VC Issuer (this system)               │
│                              │                               │
│                              │ OpenID4VCI                    │
│                              ▼                               │
│                        Lisa's EUDI Wallet                    │
└──────────────────────────────────────────────────────────────┘
```

### Systems Involved

| System | Role | Description |
|--------|------|-------------|
| **Ladok** | Edu-API Provider (SIS) | Sweden's national student register. Holds authoritative data on all student enrolments, courses, and degrees across Swedish universities. Exposes the Edu-API REST interface for machine-to-machine data access. |
| **VC Issuer (SUNET)** | Edu-API Consumer + Credential Issuer | Operated by SUNET (Swedish University Computer Network). Authenticates with Ladok via OAuth 2.0 CCG, fetches student data via Edu-API, transforms it into credential claims, and issues SD-JWT credentials via OpenID4VCI. |
| **EUDI Wallet** | Credential holder | Lisa's mobile wallet app (compliant with the EU Digital Identity framework). Stores her PID and education credentials. Supports OpenID4VCI for receiving credentials and OpenID4VP for presenting them. |
| **Sweden Connect / BankID** | Identity Provider | Used to issue Lisa's PID credential. Provides the national identity number (personnummer) that links her wallet identity to her Ladok student record. |
| **Verifier** | Relying party | Any service that accepts Lisa's credential — bookstores, partner universities, employers, housing companies, etc. |

### How Lisa Gets Her Credential

#### Step 0: What Lisa already has

Lisa has a smartphone with an EUDI wallet installed. She previously identified herself using BankID (via Sweden Connect) and received a **PID credential** containing:
- Given name: Lisa
- Family name: Andersson
- Date of birth: 1992-05-15
- National identity number (personnummer): 199205154321

Meanwhile, Lisa is registered in **Ladok** as a student at Stockholm University, enrolled in the Master's Programme in Computer Science since August 2025. This registration happened through the normal university admission process (antagning.se → admitted → registered in Ladok).

#### Step 1: Lisa requests the credential

Lisa opens her wallet and browses available credential issuers. She finds "Stockholm University — Programme Enrolment" (published via the issuer's OpenID4VCI credential issuer metadata). She taps "Request credential".

#### Step 2: Identity verification via PID

The issuer needs to know *who* Lisa is so it can look her up in Ladok. The wallet presents Lisa's PID credential via OpenID4VP. The issuer validates the PID and extracts her personnummer (`199205154321`).

#### Step 3: The issuer queries Ladok

The VC Issuer (running at SUNET) makes the following Edu-API calls to Ladok:

**a) Authenticate with Ladok:**
```
POST https://api.ladok.se/oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id=sunet-vc-issuer
&client_secret=<from secret store>
&scope=http://purl.1edtech.org/spec/eduapi/v1p0/scope/core.readonly
       http://purl.1edtech.org/spec/eduapi/v1p0/scope/core.readonly.privacy
```

**b) Find Lisa in Ladok by personnummer:**
```
GET https://api.ladok.se/ims/eduapi/base/v1p0/persons?filter=nationalIdentityNumber eq "199205154321"
Authorization: Bearer <access_token>
```
→ Returns Lisa's Edu-API Person record with `sourcedId: "ladok-person-7f3a2b"`.

**c) Fetch her programme enrolments:**
```
GET https://api.ladok.se/ims/eduapi/base/v1p0/students/ladok-person-7f3a2b/collectionOfferings
Authorization: Bearer <access_token>
```
→ Returns her active programme enrolments:
```json
[
  {
    "sourcedId": "ladok-co-4e8d1a",
    "offeringType": "program",
    "collection": "ladok-ct-master-cs",
    "title": [
      {"recordLanguage": "sv", "value": "Masterprogram i datavetenskap"},
      {"recordLanguage": "en", "value": "Master's Programme in Computer Science"}
    ],
    "primaryCode": {"identifier": "SU-CS-MSC-2025", "identifierType": "systemId"},
    "organization": "ladok-org-su",
    "academicSession": "ladok-as-ht2025",
    "startDate": "2025-08-25T00:00:00Z",
    "endDate": "2027-06-15T00:00:00Z",
    "registrationStatus": "open",
    "recordStatus": "active"
  }
]
```

**d) Fetch Stockholm University details:**
```
GET https://api.ladok.se/ims/eduapi/base/v1p0/organizations/ladok-org-su
Authorization: Bearer <access_token>
```
→ Returns:
```json
{
  "sourcedId": "ladok-org-su",
  "name": [
    {"recordLanguage": "sv", "value": "Stockholms universitet"},
    {"recordLanguage": "en", "value": "Stockholm University"}
  ],
  "organizationType": "university",
  "primaryCode": {"identifier": "SU", "identifierType": "systemId"},
  "recordStatus": "active"
}
```

#### Step 4: Claim transformation

The issuer maps the Edu-API data into credential claims using the configured `credential_mapping`:

```json
{
  "given_name": "Lisa",
  "family_name": "Andersson",
  "birth_date": "1992-05-15",
  "programme_name": "Master's Programme in Computer Science",
  "programme_code": "SU-CS-MSC-2025",
  "programme_type": "program",
  "institution_name": "Stockholm University",
  "institution_code": "SU",
  "enrolment_start": "2025-08-25",
  "enrolment_end": "2027-06-15",
  "enrolment_status": "active"
}
```

#### Step 5: Credential issued

The issuer signs an SD-JWT credential and returns it to Lisa's wallet via OpenID4VCI. Lisa sees a new credential card in her wallet: **"Programme Enrolment — Stockholm University"**.

### What Lisa can do with this credential

- **Student discount**: Present `institution_name` + `enrolment_status` at a bookstore — no need to reveal her name or programme
- **Partner university access**: Present the full credential to access library or lab resources at Uppsala University or KTH
- **Job application**: Selectively disclose `programme_name` and `institution_name` to prove current studies without revealing her personnummer
- **Student housing (SGS/SSSB)**: Present `enrolment_status` + `enrolment_end` to prove she will remain a student for the lease period
- **Erasmus exchange**: Present the credential to a partner university abroad as proof of home institution enrolment

---

## Architecture

```
┌─────────────────────────────────────┐
│         Institution SIS             │
│       (Edu-API Provider)            │
│                                     │
│  /persons  /enrollments  /courses   │
│  /organizations  /academicSessions  │
└──────────────┬──────────────────────┘
               │  OAuth 2.0 CCG
               │  REST/JSON (GET)
               ▼
┌──────────────────────────────────────┐
│          apigw (VC System)           │
│                                      │
│  ┌────────────────────────────┐      │
│  │   eduapi.Client            │      │
│  │   (pkg/eduapi/)            │      │
│  │                            │      │
│  │  - OAuth2 token mgmt      │      │
│  │  - GetPerson()             │      │
│  │  - GetEnrollments()        │      │
│  │  - GetCourseOffering()     │      │
│  │  - GetOrganization()       │      │
│  │  - GetCollectionOffering() │      │
│  └────────────┬───────────────┘      │
│               │                      │
│               ▼                      │
│  ┌────────────────────────────┐      │
│  │   eduapi.Transformer       │      │
│  │                            │      │
│  │  Maps Edu-API entities     │      │
│  │  to credential claims      │      │
│  │  using CredentialMapping   │      │
│  └────────────┬───────────────┘      │
│               │                      │
│               ▼                      │
│  ┌────────────────────────────┐      │
│  │  apiv1 credential handler  │      │
│  │  (existing issuance flow)  │      │
│  └────────────────────────────┘      │
└──────────────────────────────────────┘
```

---

## Relationship to Existing Patterns

The VC system already integrates external data sources through three mechanisms:

| Mechanism | Direction | Auth | Data |
|-----------|-----------|------|------|
| OIDC RP | Outbound | OIDC AuthZ Code | User claims from IdP |
| SAML SP | Outbound | SAML AuthN | User attributes from IdP |
| Kafka inbound | Inbound | N/A (message bus) | UploadRequest payloads |
| **Edu-API (new)** | **Outbound** | **OAuth 2.0 CCG** | **SIS education data** |

Edu-API is closest to the **OIDC RP** pattern but simpler: no user-interactive login is required. The system authenticates directly with the SIS using client credentials and pulls data for a specific person/enrollment.

---

## Edu-API Data Model Summary

The Edu-API specification defines these core entities:

```
Organization
    │
    ├── AcademicSession (semester, term, year)
    │
    ├── Education Templates (canonical definitions)
    │   ├── CollectionTemplate (program/degree)
    │   ├── CourseTemplate
    │   └── ComponentTemplate (lab, lecture, exam)
    │
    ├── Education Offerings (instantiated, time-bound)
    │   ├── CollectionOffering (program offering)
    │   ├── CourseOffering
    │   └── ComponentOffering
    │
    ├── Person
    │   ├── PersonName (typed, multilingual)
    │   ├── Agents (parents/guardians)
    │   └── Contact details (email, phone, address)
    │
    ├── Enrollment (person + offering + role + dates)
    │
    └── Affiliation (person + organization + role)
```

### Key Edu-API Endpoints for Credential Issuance

| Endpoint | Use Case |
|----------|----------|
| `GET /persons/{id}` | Student identity (name, DOB, email) |
| `GET /enrollments?personId={id}` | All enrollments for a student |
| `GET /courseOfferings/{id}` | Course details for diploma claims |
| `GET /collectionOfferings/{id}` | Program/degree info |
| `GET /organizations/{id}` | Issuing institution details |
| `GET /academicSessions/{id}` | Term/semester context |
| `GET /affiliations?personId={id}` | Organizational roles |
| `GET /collectionTemplates/{id}` | Canonical program definition |
| `GET /students/{id}/collectionOfferings` | Programs for a student |
| `GET /students/{id}/componentOfferings` | Components for a student |

All endpoints support pagination (`limit`, `offset`), sorting (`sort`, `orderBy`), and filtering (`filter`).

---

## Mapping Edu-API to Credential Types

### Diploma Credential

```
Edu-API Source                    →  Credential Claim
──────────────────────────────────────────────────────
Person.primaryName.givenName      →  given_name
Person.primaryName.familyName     →  family_name
Person.dateOfBirth                →  birth_date
CollectionTemplate.title[0].value →  degree_name
CollectionTemplate.collectionType →  degree_type (program, major...)
CollectionOffering.endDate        →  graduation_date
Organization.name[0].value        →  issuing_authority
Organization.primaryCode          →  institution_code
CourseOffering.title[0].value     →  course_name (per course)
Enrollment.role                   →  student_role
```

### ELM (European Learning Model) Credential

```
Edu-API Source                         →  ELM Claim
──────────────────────────────────────────────────────
Person.*                               →  credentialSubject.learner
CollectionTemplate.*                   →  learningAchievement
CollectionOffering.startDate/endDate   →  temporal context
Organization.*                         →  awardingBody
CourseOffering.creditType/credits      →  creditPoints
AcademicSession.*                      →  learningActivity period
```

### eduID / Micro-credential

```
Edu-API Source                    →  Credential Claim
──────────────────────────────────────────────────────
Person.primaryEmail.email         →  email
Person.primaryAddress             →  address
Affiliation.role                  →  affiliation_type
Affiliation.affiliationStatus     →  affiliation_status
Organization.name                 →  institution_name
Enrollment (filtered by scope)    →  specific enrollment data
```

---

## Configuration

### Edu-API Client Configuration

```yaml
apigw:
  inbound:
    eduapi:
      # Base URL of the institution's Edu-API provider
      base_url: "https://sis.university.example.org/ims/eduapi/base/v1p0"

      # OAuth 2.0 Client Credentials
      oauth2:
        token_url: "https://sis.university.example.org/oauth2/token"
        client_id: "vc-issuer-client"
        client_secret_env: "EDUAPI_CLIENT_SECRET"
        scopes:
          - "http://purl.1edtech.org/spec/eduapi/v1p0/scope/core.readonly"
          - "http://purl.1edtech.org/spec/eduapi/v1p0/scope/core.readonly.privacy"

      # Connection settings
      timeout: 30s
      cache_ttl: 3600  # seconds

      # Credential mappings for each credential type
      credential_mappings:
        diploma:
          attributes:
            "primaryName.givenName":
              claim: "given_name"
              required: true
            "primaryName.familyName":
              claim: "family_name"
              required: true
            "dateOfBirth":
              claim: "birth_date"
              required: true
            "primaryEmail.email":
              claim: "email"
              required: false

        eduid:
          attributes:
            "primaryName.givenName":
              claim: "given_name"
              required: true
            "primaryName.familyName":
              claim: "family_name"
              required: true
            "primaryEmail.email":
              claim: "email"
              required: true
```

---

## Implementation Structure

```
pkg/
└── eduapi/
    ├── client.go          # HTTP client, OAuth2 token mgmt, API calls
    ├── client_test.go
    ├── models.go          # Go types for Edu-API entities
    ├── models_test.go
    ├── transformer.go     # Maps Edu-API data to credential claims
    └── transformer_test.go

internal/
└── apigw/
    └── eduapi/
        ├── service.go     # Business logic, session integration
        └── handlers.go    # HTTP handlers for triggering Edu-API flows
```

---

## Phase 1: Core Client and Models

### 1.1 Edu-API Go Types

Define Go structs matching the Edu-API JSON schema. Key types:

```go
package eduapi

// Person represents an Edu-API person entity
type Person struct {
    SourcedID       string              `json:"sourcedId"`
    RecordLanguage  string              `json:"recordLanguage"`
    PrimaryName     PersonName          `json:"primaryName"`
    OtherNames      []PersonName        `json:"otherNames,omitempty"`
    DateOfBirth     string              `json:"dateOfBirth,omitempty"`
    PlaceOfBirth    string              `json:"placeOfBirth,omitempty"`
    CountryOfBirth  string              `json:"countryOfBirth,omitempty"`
    Gender          string              `json:"gender,omitempty"`
    PrimaryEmail    *OptionallyTypedEmail `json:"primaryEmail,omitempty"`
    PrimaryPhone    *OptionallyTypedPhone `json:"primaryPhone,omitempty"`
    PrimaryAddress  *OptionallyTypedAddress `json:"primaryAddress,omitempty"`
    RecordStatus    string              `json:"recordStatus"`
}

// PersonName holds the parts of a person's name
type PersonName struct {
    NameType         string              `json:"nameType,omitempty"`
    GivenName        string              `json:"givenName"`
    FamilyName       string              `json:"familyName"`
    MiddleName       string              `json:"middleName,omitempty"`
    HonorificPrefix  string              `json:"honorificPrefix,omitempty"`
    HonorificSuffix  string              `json:"honorificSuffix,omitempty"`
    FamilyNamePrefix string              `json:"familyNamePrefix,omitempty"`
    FormattedName    string              `json:"formattedName,omitempty"`
}

// Enrollment represents the joining of a person and an offering
type Enrollment struct {
    SourcedID         string   `json:"sourcedId"`
    Person            string   `json:"person"`
    EducationOffering string   `json:"educationOffering"`
    OfferingType      string   `json:"offeringType"`
    Role              string   `json:"role"`
    EnrollmentStatus  string   `json:"enrollmentStatus"`
    StartDate         string   `json:"startDate,omitempty"`
    EndDate           string   `json:"endDate,omitempty"`
    RecordStatus      string   `json:"recordStatus"`
}

// CourseOffering represents an instantiated course
type CourseOffering struct {
    SourcedID       string               `json:"sourcedId"`
    OfferingType    string               `json:"offeringType"`
    Course          string               `json:"course"`
    Title           []LanguageTypedString `json:"title"`
    Description     []LanguageTypedString `json:"description"`
    PrimaryCode     IdentifierEntry       `json:"primaryCode"`
    Organization    string               `json:"organization"`
    AcademicSession string               `json:"academicSession"`
    StartDate       string               `json:"startDate"`
    EndDate         string               `json:"endDate"`
    RecordStatus    string               `json:"recordStatus"`
}

// CollectionOffering represents a program/degree offering
type CollectionOffering struct {
    SourcedID       string               `json:"sourcedId"`
    OfferingType    string               `json:"offeringType"`
    Collection      string               `json:"collection"`
    Title           []LanguageTypedString `json:"title"`
    Description     []LanguageTypedString `json:"description"`
    PrimaryCode     IdentifierEntry       `json:"primaryCode"`
    Organization    string               `json:"organization"`
    AcademicSession string               `json:"academicSession"`
    RecordStatus    string               `json:"recordStatus"`
}

// Organization represents an administrative unit
type Organization struct {
    SourcedID        string               `json:"sourcedId"`
    Name             []LanguageTypedString `json:"name"`
    OrganizationType string               `json:"organizationType"`
    PrimaryCode      *IdentifierEntry      `json:"primaryCode,omitempty"`
    RecordStatus     string               `json:"recordStatus"`
}

// AcademicSession represents a time period (semester, term, year)
type AcademicSession struct {
    SourcedID    string               `json:"sourcedId"`
    Title        []LanguageTypedString `json:"title,omitempty"`
    SessionType  string               `json:"sessionType,omitempty"`
    StartDate    string               `json:"startDate,omitempty"`
    EndDate      string               `json:"endDate,omitempty"`
    RecordStatus string               `json:"recordStatus"`
}

// LanguageTypedString is a string with an associated language code
type LanguageTypedString struct {
    RecordLanguage string `json:"recordLanguage"`
    Value          string `json:"value"`
}

// IdentifierEntry is a container for human-readable identifiers
type IdentifierEntry struct {
    Identifier     string `json:"identifier"`
    IdentifierType string `json:"identifierType"`
}
```

### 1.2 HTTP Client

```go
package eduapi

// Client is an Edu-API consumer client
type Client struct {
    baseURL    string
    httpClient *http.Client
    tokenSrc   oauth2.TokenSource
    cache      *cache.Cache
    log        *logger.Log
}

// NewClient creates a new Edu-API client with OAuth2 CCG authentication
func NewClient(cfg *Config, log *logger.Log) (*Client, error)

// Person operations
func (c *Client) GetPerson(ctx context.Context, id string) (*Person, error)
func (c *Client) GetAllPersons(ctx context.Context, opts ...QueryOption) ([]Person, error)
func (c *Client) GetAllStudents(ctx context.Context, opts ...QueryOption) ([]Person, error)

// Enrollment operations
func (c *Client) GetEnrollment(ctx context.Context, id string) (*Enrollment, error)
func (c *Client) GetAllEnrollments(ctx context.Context, opts ...QueryOption) ([]Enrollment, error)
func (c *Client) GetEnrollmentsForCourseOffering(ctx context.Context, offeringID string, opts ...QueryOption) ([]Enrollment, error)

// Offering operations
func (c *Client) GetCourseOffering(ctx context.Context, id string) (*CourseOffering, error)
func (c *Client) GetCollectionOffering(ctx context.Context, id string) (*CollectionOffering, error)
func (c *Client) GetStudentCollectionOfferings(ctx context.Context, studentID string, opts ...QueryOption) ([]CollectionOffering, error)

// Organization operations
func (c *Client) GetOrganization(ctx context.Context, id string) (*Organization, error)

// Academic session operations
func (c *Client) GetAcademicSession(ctx context.Context, id string) (*AcademicSession, error)

// QueryOption supports pagination, sorting, and filtering
type QueryOption func(*queryParams)

func WithLimit(n int) QueryOption
func WithOffset(n int) QueryOption
func WithSort(field string) QueryOption
func WithOrderBy(dir string) QueryOption  // "asc" or "desc"
func WithFilter(expr string) QueryOption
```

---

## Phase 2: Transformer and Credential Mapping

### 2.1 Edu-API Transformer

The transformer reuses the existing `credential.ClaimTransformer` pattern. Edu-API data is first flattened into a `map[string]any` keyed by dot-notation paths, then fed through the standard `TransformClaims()` pipeline.

```go
package eduapi

// Transformer maps Edu-API entities to credential claims
type Transformer struct {
    claimTransformer *credential.ClaimTransformer
}

// FlattenPerson converts a Person struct to a flat attribute map
// Example output:
//   "primaryName.givenName" → "Alice"
//   "primaryName.familyName" → "Smith"
//   "dateOfBirth" → "1995-03-15"
//   "primaryEmail.email" → "alice@example.org"
func FlattenPerson(p *Person) map[string]any

// FlattenEnrollment converts an Enrollment to a flat attribute map
func FlattenEnrollment(e *Enrollment) map[string]any

// FlattenCourseOffering converts a CourseOffering to a flat attribute map
func FlattenCourseOffering(co *CourseOffering, lang string) map[string]any

// FlattenCollectionOffering converts a CollectionOffering to a flat attribute map
func FlattenCollectionOffering(co *CollectionOffering, lang string) map[string]any

// TransformToCredentialClaims takes Edu-API entities and produces
// credential claims according to the configured CredentialMapping
func (t *Transformer) TransformToCredentialClaims(
    credentialType string,
    person *Person,
    enrollment *Enrollment,
    offering any, // CourseOffering or CollectionOffering
    org *Organization,
) (map[string]any, error)
```

### 2.2 Integration with Existing Issuance Flow

The Edu-API flow plugs into the existing `matchScope()` mechanism in the API gateway. A new auth method `eduapi` is introduced:

```go
// In matchScope(), add:
case "eduapi":
    // 1. Identify the student (e.g., from a prior OIDC/SAML session or API key)
    // 2. Call eduapi.Client to fetch person + enrollments + offerings
    // 3. Transform via eduapi.Transformer
    // 4. Store document_data in session cache
    // 5. Proceed to credential issuance
```

---

## Phase 3: Configuration and Integration

### 3.1 Config Types

```go
// EduAPIConfig holds configuration for the Edu-API client
type EduAPIConfig struct {
    BaseURL  string       `yaml:"base_url" validate:"required,url"`
    OAuth2   OAuth2CCG    `yaml:"oauth2" validate:"required"`
    Timeout  string       `yaml:"timeout" default:"30s"`
    CacheTTL int          `yaml:"cache_ttl" default:"3600"`

    // Credential mappings per credential type
    CredentialMappings map[string]CredentialMapping `yaml:"credential_mappings"`
}

// OAuth2CCG holds OAuth 2.0 Client Credentials Grant config
type OAuth2CCG struct {
    TokenURL        string   `yaml:"token_url" validate:"required,url"`
    ClientID        string   `yaml:"client_id" validate:"required"`
    ClientSecretEnv string   `yaml:"client_secret_env" validate:"required"`
    Scopes          []string `yaml:"scopes"`
}
```

### 3.2 Edu-API Scopes

Edu-API defines two OAuth 2.0 scopes:

| Scope | Access |
|-------|--------|
| `core.readonly` | All GET endpoints except PersonManagement |
| `core.readonly.privacy` | PersonManagement endpoints (contains PII) |

Both scopes are needed for credential issuance since we need person data (PII) and education data.

---

## Phase 4: Pub/Sub Binding (Future)

Edu-API v1.0 also specifies a Pub/Sub binding for event-driven data exchange. This maps to the existing Kafka inbound handler pattern:

```
SIS publishes enrollment events
        │
        ▼
  Kafka / Message Broker
        │
        ▼
  inbound/kafka_message_handler.go
        │  (new message type: EduAPIEvent)
        ▼
  eduapi.Transformer → credential issuance
```

This would enable real-time credential issuance when a student graduates or completes a course, without polling the REST API.

---

## Security Considerations

1. **OAuth 2.0 Client Credentials**: The client secret MUST be loaded from an environment variable or secret store, never from config files directly.
2. **PII Handling**: Edu-API Person data contains PII (name, DOB, email, address). The `core.readonly.privacy` scope gates access. Data must follow the existing PII handling patterns in the codebase.
3. **TLS**: All communication with the Edu-API Provider MUST use HTTPS.
4. **Rate Limiting**: Edu-API providers return `429 Too Many Requests`. The client must implement exponential backoff.
5. **Data Minimization**: Only fetch the attributes needed for the specific credential type being issued. Use Edu-API's `filter` parameter to limit response data.
6. **Cache Invalidation**: Cached Edu-API responses should have a configurable TTL. Stale education data could lead to incorrect credentials.

---

## Open Questions

1. **Student identification**: How does the system identify which Edu-API `Person.sourcedId` corresponds to the credential requester? Options:
   - Prior OIDC/SAML session provides a `nationalIdentityNumber` or `sisSourcedId` that maps to the Edu-API person
   - The wallet presents an existing PID credential containing identifiers
   - The institution provides a lookup endpoint or mapping table

2. **Multi-institution support**: Should the system support multiple Edu-API providers (one per institution), or a single federated endpoint?

3. **Credential freshness**: Should credentials be issued from cached Edu-API data, or should a fresh fetch always be performed at issuance time?

4. **Partial data**: How to handle cases where the SIS does not expose all fields needed for a credential type (e.g., missing `dateOfBirth`)?
