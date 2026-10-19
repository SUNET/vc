package oeapi

import (
	"maps"
	"strings"
)

// localizedValue returns the English ("en"...) value from a multilingual list,
// falling back to the first entry. Returns "" if the list is empty.
func localizedValue(values []LanguageTypedString) string {
	if len(values) == 0 {
		return ""
	}
	for _, v := range values {
		if strings.HasPrefix(strings.ToLower(v.Language), "en") {
			return v.Value
		}
	}
	return values[0].Value
}

// Flatten converts a Person into a flat map suitable for attribute_mapping.
func (p *Person) Flatten() map[string]any {
	m := map[string]any{
		"personId": p.PersonID,
	}
	if p.PrimaryCode != nil {
		if p.PrimaryCode.CodeType != "" {
			m["primaryCode.codeType"] = p.PrimaryCode.CodeType
		}
		if p.PrimaryCode.Code != "" {
			m["primaryCode.code"] = p.PrimaryCode.Code
		}
	}
	if p.GivenName != "" {
		m["givenName"] = p.GivenName
	}
	if p.PreferredName != "" {
		m["preferredName"] = p.PreferredName
	}
	if p.SurnamePrefix != "" {
		m["surnamePrefix"] = p.SurnamePrefix
	}
	if p.Surname != "" {
		m["surname"] = p.Surname
	}
	if p.DisplayName != "" {
		m["displayName"] = p.DisplayName
	}
	if p.Initials != "" {
		m["initials"] = p.Initials
	}
	m["activeEnrolment"] = p.ActiveEnrolment
	if p.DateOfBirth != "" {
		m["dateOfBirth"] = p.DateOfBirth
	}
	if p.CityOfBirth != "" {
		m["cityOfBirth"] = p.CityOfBirth
	}
	if p.CountryOfBirth != nil && p.CountryOfBirth.Alpha2 != "" {
		m["countryOfBirth"] = p.CountryOfBirth.Alpha2
	}
	if p.Nationality != nil && p.Nationality.Alpha2 != "" {
		m["nationality"] = p.Nationality.Alpha2
	}
	if p.Email != "" {
		m["email"] = p.Email
	}
	if len(p.Affiliations) > 0 {
		m["affiliations"] = p.Affiliations
	}
	if p.Gender != "" {
		m["gender"] = p.Gender
	}
	// Flatten additional identifiers by their codeType.
	for _, code := range p.OtherCodes {
		if code.CodeType == "" {
			continue
		}
		// Replace dots in codeType to avoid ambiguous nested key paths.
		safeType := strings.ReplaceAll(code.CodeType, ".", "_")
		m["otherCode."+safeType] = code.Code
	}
	return m
}

// Flatten converts a ProgrammeOfferingAssociation into a flat map.
func (a *ProgrammeOfferingAssociation) Flatten() map[string]any {
	m := map[string]any{
		"associationId": a.AssociationID,
	}
	if a.Role != "" {
		m["role"] = a.Role
	}
	if a.State != "" {
		m["state"] = a.State
	}
	if a.StartDateTime != "" {
		m["startDateTime"] = a.StartDateTime
	}
	if a.ActualEndDateTime != "" {
		m["actualEndDateTime"] = a.ActualEndDateTime
	}
	if a.ProgrammeOffering != nil {
		for k, v := range a.ProgrammeOffering.Flatten() {
			m["offering."+k] = v
		}
	}
	if a.Result != nil {
		for k, v := range a.Result.Flatten() {
			m["result."+k] = v
		}
	}
	return m
}

// Flatten converts a CourseOfferingAssociation into a flat map.
func (a *CourseOfferingAssociation) Flatten() map[string]any {
	m := map[string]any{
		"associationId": a.AssociationID,
	}
	if a.Role != "" {
		m["role"] = a.Role
	}
	if a.State != "" {
		m["state"] = a.State
	}
	if a.StartDateTime != "" {
		m["startDateTime"] = a.StartDateTime
	}
	if a.ActualEndDateTime != "" {
		m["actualEndDateTime"] = a.ActualEndDateTime
	}
	if a.CourseOffering != nil {
		for k, v := range a.CourseOffering.Flatten() {
			m["offering."+k] = v
		}
	}
	if a.Result != nil {
		for k, v := range a.Result.Flatten() {
			m["result."+k] = v
		}
	}
	return m
}

// Flatten converts a ProgrammeOffering into a flat map.
func (o *ProgrammeOffering) Flatten() map[string]any {
	m := map[string]any{}
	if name := localizedValue(o.Name); name != "" {
		m["name"] = name
	}
	if o.Abbreviation != "" {
		m["abbreviation"] = o.Abbreviation
	}
	if o.PrimaryCode != nil && o.PrimaryCode.Code != "" {
		m["code"] = o.PrimaryCode.Code
	}
	if o.Programme != nil {
		for k, v := range o.Programme.Flatten() {
			m["programme."+k] = v
		}
	}
	if o.Organisation != nil {
		for k, v := range o.Organisation.Flatten() {
			m["organisation."+k] = v
		}
	}
	if o.AcademicSession != nil {
		for k, v := range o.AcademicSession.Flatten() {
			m["academicSession."+k] = v
		}
	}
	return m
}

// Flatten converts a CourseOffering into a flat map.
func (o *CourseOffering) Flatten() map[string]any {
	m := map[string]any{}
	if name := localizedValue(o.Name); name != "" {
		m["name"] = name
	}
	if o.Abbreviation != "" {
		m["abbreviation"] = o.Abbreviation
	}
	if o.PrimaryCode != nil && o.PrimaryCode.Code != "" {
		m["code"] = o.PrimaryCode.Code
	}
	if o.Course != nil {
		for k, v := range o.Course.Flatten() {
			m["course."+k] = v
		}
	}
	if o.Organisation != nil {
		for k, v := range o.Organisation.Flatten() {
			m["organisation."+k] = v
		}
	}
	if o.AcademicSession != nil {
		for k, v := range o.AcademicSession.Flatten() {
			m["academicSession."+k] = v
		}
	}
	return m
}

// Flatten converts a Programme into a flat map.
func (p *Programme) Flatten() map[string]any {
	m := map[string]any{}
	if name := localizedValue(p.Name); name != "" {
		m["name"] = name
	}
	if p.Abbreviation != "" {
		m["abbreviation"] = p.Abbreviation
	}
	if p.PrimaryCode != nil && p.PrimaryCode.Code != "" {
		m["code"] = p.PrimaryCode.Code
	}
	if p.ProgrammeType != "" {
		m["programmeType"] = p.ProgrammeType
	}
	if p.QualificationAwarded != "" {
		m["qualificationAwarded"] = p.QualificationAwarded
	}
	if p.LevelOfQualification != "" {
		m["levelOfQualification"] = p.LevelOfQualification
	}
	if p.Level != "" {
		m["level"] = p.Level
	}
	if p.FieldsOfStudy != "" {
		m["fieldsOfStudy"] = p.FieldsOfStudy
	}
	return m
}

// Flatten converts a Course into a flat map.
func (c *Course) Flatten() map[string]any {
	m := map[string]any{}
	if name := localizedValue(c.Name); name != "" {
		m["name"] = name
	}
	if c.Abbreviation != "" {
		m["abbreviation"] = c.Abbreviation
	}
	if c.PrimaryCode != nil && c.PrimaryCode.Code != "" {
		m["code"] = c.PrimaryCode.Code
	}
	return m
}

// Flatten converts an Organisation into a flat map.
func (o *Organisation) Flatten() map[string]any {
	m := map[string]any{}
	if name := localizedValue(o.Name); name != "" {
		m["name"] = name
	}
	if o.ShortName != "" {
		m["shortName"] = o.ShortName
	}
	if o.OrganisationType != "" {
		m["organisationType"] = o.OrganisationType
	}
	if o.PrimaryCode != nil && o.PrimaryCode.Code != "" {
		m["code"] = o.PrimaryCode.Code
	}
	return m
}

// Flatten converts an AcademicSession into a flat map.
func (s *AcademicSession) Flatten() map[string]any {
	m := map[string]any{}
	if name := localizedValue(s.Name); name != "" {
		m["name"] = name
	}
	if s.Abbreviation != "" {
		m["abbreviation"] = s.Abbreviation
	}
	if s.AcademicSessionType != "" {
		m["type"] = s.AcademicSessionType
	}
	if s.StartDateTime != "" {
		m["startDateTime"] = s.StartDateTime
	}
	if s.EndDateTime != "" {
		m["endDateTime"] = s.EndDateTime
	}
	return m
}

// Flatten converts a Result into a flat map.
func (r *Result) Flatten() map[string]any {
	m := map[string]any{}
	if r.State != "" {
		m["state"] = r.State
	}
	if r.Pass != "" {
		m["pass"] = r.Pass
	}
	if r.Score != "" {
		m["score"] = r.Score
	}
	m["final"] = r.Final
	if r.ResultDateTime != "" {
		m["resultDateTime"] = r.ResultDateTime
	}
	if r.StudyLoad != nil {
		if r.StudyLoad.StudyLoadUnit != "" {
			m["studyLoad.unit"] = r.StudyLoad.StudyLoadUnit
		}
		m["studyLoad.value"] = r.StudyLoad.Value
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
