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
// associations (enrolments). Results are embedded in each association. All pages
// are fetched so an active association on a later page is not missed.
func (c *Client) GetProgrammeOfferingAssociationsForPerson(ctx context.Context, personID string, opts ...QueryOption) ([]ProgrammeOfferingAssociation, error) {
	path := basePath + "/persons/" + url.PathEscape(personID) + "/programme-offering-associations"
	return getAllPages[ProgrammeOfferingAssociation](ctx, c, path, opts)
}

// GetCourseOfferingAssociationsForPerson retrieves a person's course offering
// associations (enrolments). Results are embedded in each association. All pages
// are fetched so an active association on a later page is not missed.
func (c *Client) GetCourseOfferingAssociationsForPerson(ctx context.Context, personID string, opts ...QueryOption) ([]CourseOfferingAssociation, error) {
	path := basePath + "/persons/" + url.PathEscape(personID) + "/course-offering-associations"
	return getAllPages[CourseOfferingAssociation](ctx, c, path, opts)
}

// GetProgrammeOfferingAssociation retrieves a single programme offering
// association by ID. Unlike the person collection, this endpoint supports
// expanding the embedded programme offering.
func (c *Client) GetProgrammeOfferingAssociation(ctx context.Context, associationID string, opts ...QueryOption) (*ProgrammeOfferingAssociation, error) {
	q := buildQuery(opts)
	data, err := c.doGet(ctx, basePath+"/programme-offering-associations/"+url.PathEscape(associationID), q)
	if err != nil {
		return nil, err
	}
	var a ProgrammeOfferingAssociation
	if err := json.Unmarshal(data, &a); err != nil {
		return nil, fmt.Errorf("oeapi: decode programme offering association: %w", err)
	}
	return &a, nil
}

// maxPages bounds pagination to avoid an unbounded loop against a server that
// always reports hasNextPage.
const maxPages = 100

// getAllPages walks every page of a paginated OEAPI collection and returns the
// concatenated items. A large page size is requested unless the caller set one.
// It returns an error rather than a truncated result if the page bound is hit.
func getAllPages[T any](ctx context.Context, c *Client, path string, opts []QueryOption) ([]T, error) {
	var all []T
	for pageNumber := 1; pageNumber <= maxPages; pageNumber++ {
		q := buildQuery(opts)
		if q.Get("pageSize") == "" {
			q.Set("pageSize", "250")
		}
		q.Set("pageNumber", fmt.Sprintf("%d", pageNumber))

		data, err := c.doGet(ctx, path, q)
		if err != nil {
			return nil, err
		}
		var page Page[T]
		if err := json.Unmarshal(data, &page); err != nil {
			return nil, fmt.Errorf("oeapi: decode %s: %w", path, err)
		}
		all = append(all, page.Items...)
		if !page.HasNextPage {
			return all, nil
		}
	}
	return nil, fmt.Errorf("oeapi: %s exceeded %d pages; refusing to return truncated results", path, maxPages)
}
