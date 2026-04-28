package eduapi

// Flatten converts a Person into a flat map suitable for claim transformation.
func (p *Person) Flatten() map[string]any {
	m := map[string]any{
		"sourcedId":  p.SourcedID,
		"familyName": p.Name.FamilyName,
		"givenName":  p.Name.GivenName,
	}
	if p.Status != "" {
		m["status"] = p.Status
	}
	if p.Name.MiddleName != "" {
		m["middleName"] = p.Name.MiddleName
	}
	if p.Name.PreferredName != nil {
		m["preferredName"] = p.Name.PreferredName.Value
	}
	if p.Name.FormattedName != nil {
		m["formattedName"] = p.Name.FormattedName.Value
	}
	if p.Demographics != nil {
		if p.Demographics.BirthDate != "" {
			m["birthDate"] = p.Demographics.BirthDate
		}
		if p.Demographics.Sex != "" {
			m["sex"] = p.Demographics.Sex
		}
	}
	// Flatten first email
	if len(p.Email) > 0 {
		m["email"] = p.Email[0].Value
	}
	// Flatten first phone
	if len(p.Phone) > 0 {
		m["phone"] = p.Phone[0].Value
	}
	// Flatten identifiers by type
	for _, id := range p.Identifiers {
		m["identifier."+id.IdentifierType] = id.Identifier
	}
	return m
}

// Flatten converts an Enrollment into a flat map.
func (e *Enrollment) Flatten() map[string]any {
	m := map[string]any{
		"sourcedId":       e.SourcedID,
		"role":            e.Role,
		"user.sourcedId":  e.PersonRef.SourcedID,
		"class.sourcedId": e.ClassRef.SourcedID,
	}
	if e.Status != "" {
		m["status"] = e.Status
	}
	if e.BeginDate != "" {
		m["beginDate"] = e.BeginDate
	}
	if e.EndDate != "" {
		m["endDate"] = e.EndDate
	}
	m["primary"] = e.Primary
	return m
}

// Flatten converts a CourseOffering into a flat map.
func (co *CourseOffering) Flatten() map[string]any {
	m := map[string]any{
		"sourcedId": co.SourcedID,
		"title":     co.Title,
	}
	if co.Status != "" {
		m["status"] = co.Status
	}
	if co.CourseCode != "" {
		m["courseCode"] = co.CourseCode
	}
	if co.ClassType != "" {
		m["classType"] = co.ClassType
	}
	if co.SchoolRef.SourcedID != "" {
		m["school.sourcedId"] = co.SchoolRef.SourcedID
	}
	if len(co.SubjectCodes) > 0 {
		m["subjectCodes"] = co.SubjectCodes
	}
	return m
}

// Flatten converts an Organization into a flat map.
func (org *Organization) Flatten() map[string]any {
	m := map[string]any{
		"sourcedId": org.SourcedID,
		"name":      org.Name,
	}
	if org.Type != "" {
		m["type"] = org.Type
	}
	if org.Identifier != "" {
		m["identifier"] = org.Identifier
	}
	if org.ParentRef != nil && org.ParentRef.SourcedID != "" {
		m["parent.sourcedId"] = org.ParentRef.SourcedID
	}
	return m
}

// Flatten converts a Result into a flat map.
func (r *Result) Flatten() map[string]any {
	m := map[string]any{
		"sourcedId":          r.SourcedID,
		"student.sourcedId":  r.PersonRef.SourcedID,
		"lineItem.sourcedId": r.ClassRef.SourcedID,
	}
	if r.Score != "" {
		m["score"] = r.Score
	}
	if r.ScoreStatus != "" {
		m["scoreStatus"] = r.ScoreStatus
	}
	if r.ScoreDate != "" {
		m["scoreDate"] = r.ScoreDate
	}
	return m
}

// MergeMaps merges multiple flat maps into one. Later maps override earlier ones.
func MergeMaps(maps ...map[string]any) map[string]any {
	result := make(map[string]any)
	for _, m := range maps {
		for k, v := range m {
			result[k] = v
		}
	}
	return result
}
