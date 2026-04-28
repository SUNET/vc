package eduapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

// GetPerson retrieves a person by their sourcedId.
func (c *Client) GetPerson(ctx context.Context, personID string) (*Person, error) {
	data, err := c.doGet(ctx, "/ims/oneroster/rostering/v1p2/persons/"+url.PathEscape(personID), nil)
	if err != nil {
		return nil, err
	}
	var resp PersonResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("eduapi: decode person: %w", err)
	}
	return &resp.Person, nil
}

// GetStudents retrieves all persons with a student role.
func (c *Client) GetStudents(ctx context.Context, opts ...QueryOption) ([]Person, error) {
	q := buildQuery(opts)
	data, err := c.doGet(ctx, "/ims/oneroster/rostering/v1p2/students", q)
	if err != nil {
		return nil, err
	}
	var resp PersonsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("eduapi: decode students: %w", err)
	}
	return resp.Persons, nil
}

// GetEnrollmentsForPerson retrieves all enrollments for a person.
func (c *Client) GetEnrollmentsForPerson(ctx context.Context, personID string, opts ...QueryOption) ([]Enrollment, error) {
	q := buildQuery(opts)
	data, err := c.doGet(ctx, "/ims/oneroster/rostering/v1p2/persons/"+url.PathEscape(personID)+"/enrollments", q)
	if err != nil {
		return nil, err
	}
	var resp EnrollmentsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("eduapi: decode enrollments: %w", err)
	}
	return resp.Enrollments, nil
}

// GetCourseOffering retrieves a single course offering by sourcedId.
func (c *Client) GetCourseOffering(ctx context.Context, classID string) (*CourseOffering, error) {
	data, err := c.doGet(ctx, "/ims/oneroster/rostering/v1p2/classes/"+url.PathEscape(classID), nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Class CourseOffering `json:"class"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("eduapi: decode course offering: %w", err)
	}
	return &resp.Class, nil
}

// GetOrganization retrieves an organization (school) by sourcedId.
func (c *Client) GetOrganization(ctx context.Context, orgID string) (*Organization, error) {
	data, err := c.doGet(ctx, "/ims/oneroster/rostering/v1p2/orgs/"+url.PathEscape(orgID), nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Org Organization `json:"org"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("eduapi: decode organization: %w", err)
	}
	return &resp.Org, nil
}

// GetAcademicSession retrieves an academic session by sourcedId.
func (c *Client) GetAcademicSession(ctx context.Context, sessionID string) (*AcademicSession, error) {
	data, err := c.doGet(ctx, "/ims/oneroster/rostering/v1p2/academicSessions/"+url.PathEscape(sessionID), nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		AcademicSession AcademicSession `json:"academicSession"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("eduapi: decode academic session: %w", err)
	}
	return &resp.AcademicSession, nil
}

// GetResultsForPerson retrieves all results (grades) for a person.
func (c *Client) GetResultsForPerson(ctx context.Context, personID string, opts ...QueryOption) ([]Result, error) {
	q := buildQuery(opts)
	data, err := c.doGet(ctx, "/ims/oneroster/gradebook/v1p2/students/"+url.PathEscape(personID)+"/results", q)
	if err != nil {
		return nil, err
	}
	var resp ResultsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("eduapi: decode results: %w", err)
	}
	return resp.Results, nil
}
