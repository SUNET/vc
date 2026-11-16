package eduapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFlattenPerson(t *testing.T) {
	have := &Person{
		SourcedID:     "p-123",
		RecordStatus:  "active",
		LegalName:     &PersonName{GivenName: "Lisa", FamilyName: "Andersson", AdditionalName: "Maria"},
		FormattedName: "Lisa Maria Andersson",
		DateOfBirth:   "1990-01-01",
		PrimaryEmail:  &OptionallyTypedEmail{Email: "lisa@university.se", EmailType: "workEmail"},
		PrimaryPhone:  &OptionallyTypedPhone{Phone: "+46701234567"},
		OtherIdentifiers: []IdentifierEntry{
			{IdentifierType: "nationalIdentityNumber", Identifier: "199001011234"},
			{IdentifierType: "ext:org.eppn", Identifier: "lisa@uni.se"},
		},
	}

	got := have.Flatten()

	expected := map[string]any{
		"sourcedId":                         "p-123",
		"recordStatus":                      "active",
		"givenName":                         "Lisa",
		"familyName":                        "Andersson",
		"additionalName":                    "Maria",
		"formattedName":                     "Lisa Maria Andersson",
		"dateOfBirth":                       "1990-01-01",
		"email":                             "lisa@university.se",
		"phone":                             "+46701234567",
		"identifier.nationalIdentityNumber": "199001011234",
		"identifier.ext:org_eppn":           "lisa@uni.se",
	}
	for key, want := range expected {
		assert.Equal(t, want, got[key], "key %q", key)
	}
}

func TestFlattenPersonMinimal(t *testing.T) {
	got := (&Person{SourcedID: "p-min"}).Flatten()

	assert.Equal(t, map[string]any{"sourcedId": "p-min"}, got)
}

func TestFlattenEnrollment(t *testing.T) {
	e := &Enrollment{
		SourcedID:         "e-456",
		Person:            "p-123",
		EducationOffering: "co-789",
		OfferingType:      "course",
		Role:              "student",
		EnrollmentStatus:  "enrolled",
		IsActive:          true,
		StartDate:         "2024-01-15T00:00:00Z",
	}

	got := e.Flatten()

	assert.Equal(t, "e-456", got["sourcedId"])
	assert.Equal(t, "student", got["role"])
	assert.Equal(t, "p-123", got["person"])
	assert.Equal(t, "co-789", got["educationOffering"])
	assert.Equal(t, "course", got["offeringType"])
	assert.Equal(t, true, got["isActive"])
	assert.Equal(t, "enrolled", got["enrollmentStatus"])
	assert.Equal(t, "2024-01-15T00:00:00Z", got["startDate"])
	assert.NotContains(t, got, "endDate")
}

func TestFlattenCourseOffering(t *testing.T) {
	co := &CourseOffering{
		SourcedID:      "co-789",
		RecordLanguage: "sv",
		Title: []LanguageTypedString{
			{RecordLanguage: "en", Value: "Advanced Mathematics"},
			{RecordLanguage: "sv", Value: "Avancerad matematik"},
		},
		PrimaryCode:  &IdentifierEntry{IdentifierType: "systemId", Identifier: "MATH301"},
		Organization: "org-1",
		StartDate:    "2024-08-26T00:00:00Z",
	}

	got := co.Flatten()

	assert.Equal(t, "Avancerad matematik", got["title"], "record language wins")
	assert.Equal(t, "MATH301", got["primaryCode"])
	assert.Equal(t, "org-1", got["organization"])
	assert.NotContains(t, got, "description")
}

func TestFlattenOrganization(t *testing.T) {
	org := &Organization{
		SourcedID:        "org-1",
		RecordLanguage:   "de",
		Name:             []LanguageTypedString{{RecordLanguage: "en", Value: "Stockholm University"}},
		OrganizationType: "university",
		PrimaryCode:      &IdentifierEntry{IdentifierType: "systemId", Identifier: "SU"},
	}

	got := org.Flatten()

	assert.Equal(t, "Stockholm University", got["name"], "falls back to first entry")
	assert.Equal(t, "university", got["organizationType"])
	assert.Equal(t, "SU", got["primaryCode"])
}

func TestMergeMaps(t *testing.T) {
	t.Run("two maps", func(t *testing.T) {
		a := map[string]any{"key1": "val1", "key2": "val2"}
		b := map[string]any{"key2": "override", "key3": "val3"}

		got := MergeMaps(a, b)

		assert.Equal(t, "val1", got["key1"])
		assert.Equal(t, "override", got["key2"], "later map should win")
		assert.Equal(t, "val3", got["key3"])
	})

	t.Run("no maps", func(t *testing.T) {
		assert.Empty(t, MergeMaps())
	})
}
