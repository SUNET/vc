package eduapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/SUNET/vc/pkg/oauth2client/oauth2clienttest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const basePath = "/1edtech/eduapi/base/v1p0"

// newTestClient serves mux under the Edu-API base path and returns a client for it.
func newTestClient(t *testing.T, mux *http.ServeMux) (*httptest.Server, *Client) {
	t.Helper()
	root := http.NewServeMux()
	// The test client puts its token endpoint at <base URL>/oauth2/token.
	oauth2clienttest.RegisterTokenHandler(root, basePath+"/oauth2/token", "test-token")
	root.Handle(basePath+"/", http.StripPrefix(basePath, mux))
	srv := httptest.NewServer(root)
	t.Cleanup(srv.Close)

	return srv, NewClient(oauth2clienttest.NewClient(t, srv.URL+basePath, "application/json", "eduapi"))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func TestGetPerson(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/persons/p-lisa", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, Person{
			SourcedID:      "p-lisa",
			RecordLanguage: "en",
			LegalName:      &PersonName{GivenName: "Lisa", FamilyName: "Andersson"},
			DateOfBirth:    "1995-05-15",
			PrimaryEmail:   &OptionallyTypedEmail{Email: "lisa@student.su.se"},
			OtherIdentifiers: []IdentifierEntry{
				{IdentifierType: "nationalIdentityNumber", Identifier: "199505151234"},
			},
		})
	})
	_, client := newTestClient(t, mux)

	p, err := client.GetPerson(context.Background(), "p-lisa")
	require.NoError(t, err)
	assert.Equal(t, "Lisa", p.LegalName.GivenName)
	assert.Equal(t, "1995-05-15", p.DateOfBirth)
	assert.Equal(t, "lisa@student.su.se", p.PrimaryEmail.Email)
	assert.Len(t, p.OtherIdentifiers, 1)

	_, err = client.GetPerson(context.Background(), "nonexistent")
	assert.Error(t, err)
}

func TestGetCourseOfferingOrganizationAcademicSession(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/courseOfferings/co-1", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, CourseOffering{
			SourcedID:       "co-1",
			RecordLanguage:  "sv",
			Title:           []LanguageTypedString{{RecordLanguage: "en", Value: "Linear Algebra"}, {RecordLanguage: "sv", Value: "Linjar algebra"}},
			PrimaryCode:     &IdentifierEntry{IdentifierType: "systemId", Identifier: "MATH301"},
			Organization:    "org-1",
			AcademicSession: "as-1",
		})
	})
	mux.HandleFunc("/organizations/org-1", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, Organization{SourcedID: "org-1", Name: []LanguageTypedString{{RecordLanguage: "en", Value: "Stockholm University"}}, OrganizationType: "university"})
	})
	mux.HandleFunc("/academicSessions/as-1", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, AcademicSession{SourcedID: "as-1", SessionType: "term", StartDate: "2025-08-26T00:00:00Z"})
	})
	_, client := newTestClient(t, mux)
	ctx := context.Background()

	co, err := client.GetCourseOffering(ctx, "co-1")
	require.NoError(t, err)
	assert.Equal(t, "org-1", co.Organization)
	assert.Equal(t, "MATH301", co.PrimaryCode.Identifier)

	org, err := client.GetOrganization(ctx, "org-1")
	require.NoError(t, err)
	assert.Equal(t, "university", org.OrganizationType)

	as, err := client.GetAcademicSession(ctx, "as-1")
	require.NoError(t, err)
	assert.Equal(t, "term", as.SessionType)
}

// enrollmentServer pages enrollments two at a time, advertising each next page
// with the given link style (relative or absolute).
func enrollmentServer(t *testing.T, all []Enrollment, absolute bool, gotFilters *[]string) (*httptest.Server, *Client) {
	t.Helper()
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/enrollments", func(w http.ResponseWriter, r *http.Request) {
		if gotFilters != nil {
			*gotFilters = append(*gotFilters, r.URL.Query().Get("filter"))
		}
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		end := min(offset+2, len(all))
		if end < len(all) {
			q := url.Values{"filter": {r.URL.Query().Get("filter")}, "offset": {strconv.Itoa(end)}}
			target := basePath + "/enrollments?" + q.Encode()
			if absolute {
				target = srv.URL + target
			}
			w.Header().Set("Link", fmt.Sprintf(`<%s>; rel="next", <%s>; rel="last"`, target, target))
		}
		writeJSON(w, all[offset:end])
	})
	srv, client := newTestClient(t, mux)
	return srv, client
}

func sampleEnrollments() []Enrollment {
	return []Enrollment{
		{SourcedID: "e1", Person: "p-lisa", EducationOffering: "co-1", OfferingType: "course", Role: "student", IsActive: true},
		{SourcedID: "e2", Person: "p-lisa", EducationOffering: "co-2", OfferingType: "course", Role: "student", IsActive: false},
		{SourcedID: "e3", Person: "p-lisa", EducationOffering: "co-3", OfferingType: "course", Role: "student", IsActive: true},
		{SourcedID: "e4", Person: "p-lisa", EducationOffering: "col-1", OfferingType: "collection", Role: "student", IsActive: true},
		{SourcedID: "e5", Person: "p-lisa", EducationOffering: "co-5", OfferingType: "course", Role: "student", IsActive: true},
	}
}

func TestListActiveEnrollmentsFollowsNextAndFiltersInactive(t *testing.T) {
	for _, absolute := range []bool{false, true} {
		t.Run(fmt.Sprintf("absolute=%v", absolute), func(t *testing.T) {
			var filters []string
			_, client := enrollmentServer(t, sampleEnrollments(), absolute, &filters)

			got, err := client.ListActiveEnrollments(context.Background(), "p-lisa")
			require.NoError(t, err)

			var ids []string
			for _, e := range got {
				ids = append(ids, e.SourcedID)
			}
			assert.Equal(t, []string{"e1", "e3", "e4", "e5"}, ids)
			assert.Len(t, filters, 3, "three pages requested")
			for _, f := range filters {
				assert.Equal(t, "person='p-lisa'", f)
			}
		})
	}
}

func TestListActiveEnrollmentsEmpty(t *testing.T) {
	_, client := enrollmentServer(t, []Enrollment{}, false, nil)

	got, err := client.ListActiveEnrollments(context.Background(), "p-none")
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestListActiveEnrollmentsRejectsQuote(t *testing.T) {
	var filters []string
	_, client := enrollmentServer(t, sampleEnrollments(), false, &filters)

	for _, id := range []string{"x' OR person!='y", `a\b`} {
		_, err := client.ListActiveEnrollments(context.Background(), id)
		assert.Error(t, err, "id %q", id)
	}
	assert.Empty(t, filters, "no request must be sent")
}

func TestListActiveEnrollmentsRefusesCrossOriginNext(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/enrollments", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<https://evil.example.org/enrollments?offset=1>; rel="next"`)
		writeJSON(w, []Enrollment{{SourcedID: "e1", IsActive: true}})
	})
	_, client := newTestClient(t, mux)

	_, err := client.ListActiveEnrollments(context.Background(), "p-lisa")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "different origin")
}

func TestListActiveEnrollmentsPageCap(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/enrollments", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `</1edtech/eduapi/base/v1p0/enrollments?offset=1>; rel="next"`)
		writeJSON(w, []Enrollment{})
	})
	_, client := newTestClient(t, mux)

	_, err := client.ListActiveEnrollments(context.Background(), "p-lisa")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pages")
}

func TestNextLink(t *testing.T) {
	tests := []struct {
		name string
		link []string
		want string
	}{
		{"none", nil, ""},
		{"next only", []string{`</a?o=2>; rel="next"`}, "/a?o=2"},
		{"unquoted rel", []string{`</a?o=2>; rel=next`}, "/a?o=2"},
		{"several relations", []string{`</f>; rel="first", </a?o=2>; rel="next", </l>; rel="last"`}, "/a?o=2"},
		{"separate header lines", []string{`</f>; rel="first"`, `</a?o=2>; rel="next"`}, "/a?o=2"},
		{"no next", []string{`</f>; rel="first", </l>; rel="last"`}, ""},
		{"rel list", []string{`</a?o=2>; rel="next last"`}, "/a?o=2"},
		{"case-insensitive", []string{`</a?o=2>; REL="Next"`}, "/a?o=2"},
		{"malformed", []string{`not a link`}, ""},
		{"prefix not next", []string{`</a>; rel="nextish"`}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			for _, l := range tc.link {
				h.Add("Link", l)
			}
			assert.Equal(t, tc.want, nextLink(h))
		})
	}
}

func TestRequestsCarryBasePathAndToken(t *testing.T) {
	var gotAuth, gotPath string
	mux := http.NewServeMux()
	mux.HandleFunc("/persons/p-1", func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.RequestURI
		writeJSON(w, Person{SourcedID: "p-1"})
	})
	_, client := newTestClient(t, mux)

	_, err := client.GetPerson(context.Background(), "p-1")
	require.NoError(t, err)
	assert.Equal(t, "Bearer test-token", gotAuth)
	assert.Equal(t, basePath+"/persons/p-1", gotPath)
}
