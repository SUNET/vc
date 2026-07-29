package eduapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFlattenPerson(t *testing.T) {
	have := &Person{
		SourcedID: "p-123",
		Status:    "active",
		Name: PersonName{
			FamilyName: "Andersson",
			GivenName:  "Lisa",
			MiddleName: "Maria",
		},
		Email: []TypedContact{
			{Type: "institutional", Value: "lisa@university.se"},
		},
		Phone: []TypedContact{
			{Type: "mobile", Value: "+46701234567"},
		},
		Identifiers: []IdentifierEntry{
			{IdentifierType: "personnummer", Identifier: "199001011234"},
			{IdentifierType: "org.eppn", Identifier: "lisa@uni.se"},
		},
		Demographics: &Demographics{
			BirthDate: "1990-01-01",
		},
	}

	got := have.Flatten()

	expected := map[string]any{
		"sourcedId":               "p-123",
		"familyName":              "Andersson",
		"givenName":               "Lisa",
		"middleName":              "Maria",
		"email":                   "lisa@university.se",
		"phone":                   "+46701234567",
		"birthDate":               "1990-01-01",
		"identifier.personnummer": "199001011234",
		"identifier.org_eppn":     "lisa@uni.se",
	}

	for key, want := range expected {
		assert.Equal(t, want, got[key], "key %q", key)
	}
}

func TestFlattenEnrollment(t *testing.T) {
	e := &Enrollment{
		SourcedID: "e-456",
		Status:    "active",
		Role:      "student",
		PersonRef: GUIDRef{SourcedID: "p-123"},
		ClassRef:  GUIDRef{SourcedID: "c-789"},
		BeginDate: "2024-01-15",
		EndDate:   "2024-06-15",
		Primary:   true,
	}

	got := e.Flatten()

	assert.Equal(t, "e-456", got["sourcedId"])
	assert.Equal(t, "student", got["role"])
	assert.Equal(t, "p-123", got["user.sourcedId"])
	assert.Equal(t, true, got["primary"])
}

func TestFlattenCourseOffering(t *testing.T) {
	co := &CourseOffering{
		SourcedID:    "c-789",
		Title:        "Advanced Mathematics",
		CourseCode:   "MATH301",
		ClassType:    "scheduled",
		SchoolRef:    GUIDRef{SourcedID: "org-1"},
		SubjectCodes: []string{"MAT"},
	}

	got := co.Flatten()

	assert.Equal(t, "Advanced Mathematics", got["title"])
	assert.Equal(t, "MATH301", got["courseCode"])
	assert.Equal(t, "org-1", got["school.sourcedId"])
}

func TestFlattenOrganization(t *testing.T) {
	org := &Organization{
		SourcedID:  "org-1",
		Name:       "Stockholm University",
		Type:       "school",
		Identifier: "SE-202100-3062",
	}

	got := org.Flatten()

	assert.Equal(t, "Stockholm University", got["name"])
	assert.Equal(t, "SE-202100-3062", got["identifier"])
}

func TestFlattenResult(t *testing.T) {
	r := &Result{
		SourcedID:   "r-001",
		PersonRef:   GUIDRef{SourcedID: "p-123"},
		ClassRef:    GUIDRef{SourcedID: "li-001"},
		Score:       "VG",
		ScoreStatus: "fully graded",
		ScoreDate:   "2024-06-20",
	}

	got := r.Flatten()

	assert.Equal(t, "VG", got["score"])
	assert.Equal(t, "fully graded", got["scoreStatus"])
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

	t.Run("three maps", func(t *testing.T) {
		a := map[string]any{"key1": "a", "shared": "a"}
		b := map[string]any{"key2": "b", "shared": "b"}
		c := map[string]any{"key3": "c", "shared": "c"}

		got := MergeMaps(a, b, c)

		assert.Equal(t, "a", got["key1"])
		assert.Equal(t, "b", got["key2"])
		assert.Equal(t, "c", got["key3"])
		assert.Equal(t, "c", got["shared"], "last map should win")
	})

	t.Run("single map", func(t *testing.T) {
		a := map[string]any{"key1": "val1"}

		got := MergeMaps(a)

		assert.Equal(t, "val1", got["key1"])
		assert.Len(t, got, 1)
	})

	t.Run("no maps", func(t *testing.T) {
		got := MergeMaps()

		assert.Empty(t, got)
	})
}

func TestFlattenPersonMinimal(t *testing.T) {
	have := &Person{
		SourcedID: "p-min",
		Name: PersonName{
			FamilyName: "Smith",
			GivenName:  "John",
		},
	}

	got := have.Flatten()

	assert.Len(t, got, 3) // sourcedId, familyName, givenName
	assert.NotContains(t, got, "email")
	assert.NotContains(t, got, "birthDate")
}
