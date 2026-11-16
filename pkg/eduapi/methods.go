package eduapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// maxEnrollmentPages bounds how many pages ListActiveEnrollments follows.
const maxEnrollmentPages = 100

// getJSON GETs path (relative to the base URL) and decodes the bare JSON body into out.
func (c *Client) getJSON(ctx context.Context, path string, out any) error {
	data, err := c.doGet(ctx, path, nil)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("eduapi: decode %s: %w", path, err)
	}
	return nil
}

// GetPerson retrieves a person by sourcedId.
func (c *Client) GetPerson(ctx context.Context, personID string) (*Person, error) {
	var p Person
	if err := c.getJSON(ctx, "/persons/"+url.PathEscape(personID), &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// ListActiveEnrollments returns the active enrollments of a person using the
// spec's generic filter on /enrollments, following rel="next" links until none is left.
func (c *Client) ListActiveEnrollments(ctx context.Context, personID string) ([]Enrollment, error) {
	if strings.ContainsAny(personID, "'\\") {
		return nil, errors.New("eduapi: person id contains a quote or backslash")
	}

	q := url.Values{"filter": {"person='" + personID + "'"}}
	pageURL := c.http.URL("/enrollments", q)
	data, header, err := c.http.GetWithHeaders(ctx, "/enrollments", q)

	var active []Enrollment
	for page := 1; ; page++ {
		if err != nil {
			return nil, err
		}
		var enrollments []Enrollment
		if err := json.Unmarshal(data, &enrollments); err != nil {
			return nil, fmt.Errorf("eduapi: decode enrollments: %w", err)
		}
		for _, e := range enrollments {
			if e.IsActive {
				active = append(active, e)
			}
		}

		next := nextLink(header)
		if next == "" {
			return active, nil
		}
		if page >= maxEnrollmentPages {
			return nil, fmt.Errorf("eduapi: enrollments exceed %d pages", maxEnrollmentPages)
		}
		// A relative link is relative to the page that carried it, not to the base URL.
		pageURL, err = c.http.Resolve(pageURL, next)
		if err != nil {
			return nil, err
		}
		data, header, err = c.http.GetURL(ctx, pageURL)
	}
}

// GetCourseOffering retrieves a course offering by sourcedId.
func (c *Client) GetCourseOffering(ctx context.Context, id string) (*CourseOffering, error) {
	var co CourseOffering
	if err := c.getJSON(ctx, "/courseOfferings/"+url.PathEscape(id), &co); err != nil {
		return nil, err
	}
	return &co, nil
}

// GetOrganization retrieves an organization by sourcedId.
func (c *Client) GetOrganization(ctx context.Context, id string) (*Organization, error) {
	var org Organization
	if err := c.getJSON(ctx, "/organizations/"+url.PathEscape(id), &org); err != nil {
		return nil, err
	}
	return &org, nil
}

// GetAcademicSession retrieves an academic session by sourcedId.
func (c *Client) GetAcademicSession(ctx context.Context, id string) (*AcademicSession, error) {
	var as AcademicSession
	if err := c.getJSON(ctx, "/academicSessions/"+url.PathEscape(id), &as); err != nil {
		return nil, err
	}
	return &as, nil
}

// nextLink returns the target of the rel="next" link in the Link headers (RFC 8288), or "".
func nextLink(h http.Header) string {
	for _, v := range h.Values("Link") {
		for v != "" {
			start := strings.IndexByte(v, '<')
			if start < 0 {
				break
			}
			end := strings.IndexByte(v[start:], '>')
			if end < 0 {
				break
			}
			target := v[start+1 : start+end]
			params, rest := cutOutsideQuotes(v[start+end+1:], ',')
			v = rest
			if hasRelNext(params) {
				return target
			}
		}
	}
	return ""
}

// hasRelNext reports whether the link parameters carry rel=next.
func hasRelNext(params string) bool {
	for params != "" {
		var p string
		p, params = cutOutsideQuotes(params, ';')
		k, val, ok := strings.Cut(strings.TrimSpace(p), "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), "rel") {
			continue
		}
		for rel := range strings.FieldsSeq(strings.Trim(strings.TrimSpace(val), `"`)) {
			if strings.EqualFold(rel, "next") {
				return true
			}
		}
	}
	return false
}

// cutOutsideQuotes splits s at the first sep that is not inside a quoted string.
// A backslash escapes the next byte inside quotes.
func cutOutsideQuotes(s string, sep byte) (before, after string) {
	quoted := false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case quoted && c == '\\':
			i++
		case c == '"':
			quoted = !quoted
		case !quoted && c == sep:
			return s[:i], s[i+1:]
		}
	}
	return s, ""
}
