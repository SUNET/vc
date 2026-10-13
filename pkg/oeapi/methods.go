package oeapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

// OEAPI v6.0 version base path, appended to the configured BaseURL host.
const basePath = "/v6"

// GetPerson retrieves a single person by their OEAPI personId.
func (c *Client) GetPerson(ctx context.Context, personID string) (*Person, error) {
	data, err := c.doGet(ctx, basePath+"/persons/"+url.PathEscape(personID), nil)
	if err != nil {
		return nil, err
	}
	var person Person
	if err := json.Unmarshal(data, &person); err != nil {
		return nil, fmt.Errorf("oeapi: decode person: %w", err)
	}
	return &person, nil
}

// GetProgrammeOfferingAssociationsForPerson retrieves a person's programme offering
// associations (enrolments). Results are embedded in each association.
func (c *Client) GetProgrammeOfferingAssociationsForPerson(ctx context.Context, personID string, opts ...QueryOption) ([]ProgrammeOfferingAssociation, error) {
	q := buildQuery(opts)
	data, err := c.doGet(ctx, basePath+"/persons/"+url.PathEscape(personID)+"/programme-offering-associations", q)
	if err != nil {
		return nil, err
	}
	var page Page[ProgrammeOfferingAssociation]
	if err := json.Unmarshal(data, &page); err != nil {
		return nil, fmt.Errorf("oeapi: decode programme offering associations: %w", err)
	}
	return page.Items, nil
}

// GetCourseOfferingAssociationsForPerson retrieves a person's course offering
// associations (enrolments). Results are embedded in each association.
func (c *Client) GetCourseOfferingAssociationsForPerson(ctx context.Context, personID string, opts ...QueryOption) ([]CourseOfferingAssociation, error) {
	q := buildQuery(opts)
	data, err := c.doGet(ctx, basePath+"/persons/"+url.PathEscape(personID)+"/course-offering-associations", q)
	if err != nil {
		return nil, err
	}
	var page Page[CourseOfferingAssociation]
	if err := json.Unmarshal(data, &page); err != nil {
		return nil, fmt.Errorf("oeapi: decode course offering associations: %w", err)
	}
	return page.Items, nil
}
