package eduapi

import (
	"maps"
	"strings"
)

// localized picks the text in the record's own language, else the first entry.
func localized(values []LanguageTypedString, recordLanguage string) string {
	for _, v := range values {
		if v.RecordLanguage == recordLanguage {
			return v.Value
		}
	}
	if len(values) > 0 {
		return values[0].Value
	}
	return ""
}

// Flatten converts a Person into a flat map suitable for attribute_mapping.
func (p *Person) Flatten() map[string]any {
	m := map[string]any{"sourcedId": p.SourcedID}
	set := func(k, v string) {
		if v != "" {
			m[k] = v
		}
	}
	set("recordStatus", p.RecordStatus)
	set("formattedName", p.FormattedName)
	set("dateOfBirth", p.DateOfBirth)
	set("gender", p.Gender)
	if p.LegalName != nil {
		set("givenName", p.LegalName.GivenName)
		set("familyName", p.LegalName.FamilyName)
		set("additionalName", p.LegalName.AdditionalName)
	}
	if p.PrimaryEmail != nil {
		set("email", p.PrimaryEmail.Email)
	}
	if p.PrimaryPhone != nil {
		set("phone", p.PrimaryPhone.Phone)
	}
	for _, id := range p.OtherIdentifiers {
		// Dots in the type would read as nested key paths.
		safeType := strings.ReplaceAll(id.IdentifierType, ".", "_")
		m["identifier."+safeType] = id.Identifier
	}
	return m
}

// Flatten converts an Enrollment into a flat map.
func (e *Enrollment) Flatten() map[string]any {
	m := map[string]any{
		"sourcedId":         e.SourcedID,
		"role":              e.Role,
		"person":            e.Person,
		"educationOffering": e.EducationOffering,
		"offeringType":      e.OfferingType,
		"isActive":          e.IsActive,
	}
	set := func(k, v string) {
		if v != "" {
			m[k] = v
		}
	}
	set("enrollmentStatus", e.EnrollmentStatus)
	set("startDate", e.StartDate)
	set("endDate", e.EndDate)
	return m
}

// Flatten converts a CourseOffering into a flat map.
func (co *CourseOffering) Flatten() map[string]any {
	m := map[string]any{"sourcedId": co.SourcedID}
	set := func(k, v string) {
		if v != "" {
			m[k] = v
		}
	}
	set("title", localized(co.Title, co.RecordLanguage))
	set("description", localized(co.Description, co.RecordLanguage))
	set("offeringType", co.OfferingType)
	set("offeringFormat", co.OfferingFormat)
	set("registrationStatus", co.RegistrationStatus)
	set("course", co.Course)
	set("organization", co.Organization)
	set("academicSession", co.AcademicSession)
	set("startDate", co.StartDate)
	set("endDate", co.EndDate)
	if co.PrimaryCode != nil {
		set("primaryCode", co.PrimaryCode.Identifier)
	}
	return m
}

// Flatten converts an Organization into a flat map.
func (org *Organization) Flatten() map[string]any {
	m := map[string]any{"sourcedId": org.SourcedID}
	set := func(k, v string) {
		if v != "" {
			m[k] = v
		}
	}
	set("name", localized(org.Name, org.RecordLanguage))
	set("organizationType", org.OrganizationType)
	set("parent", org.Parent)
	if org.PrimaryCode != nil {
		set("primaryCode", org.PrimaryCode.Identifier)
	}
	return m
}

// MergeMaps merges multiple flat maps into one. Later maps override earlier ones.
func MergeMaps(sources ...map[string]any) map[string]any {
	result := make(map[string]any)
	for _, src := range sources {
		maps.Copy(result, src)
	}
	return result
}
