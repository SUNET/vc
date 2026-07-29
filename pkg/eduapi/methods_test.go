package eduapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/logger"
)

// testServer creates a mock Edu-API server with realistic Ladok-style data and
// returns the server and a pre-configured client. The caller must defer srv.Close().
func testServer(t *testing.T) (*httptest.Server, *Client) {
	t.Helper()

	mux := http.NewServeMux()

	// OAuth 2.0 token endpoint
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{ // #nosec G104
			"access_token": "test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})

	// GET /persons/{personId}
	mux.HandleFunc("/ims/oneroster/rostering/v1p2/persons/p-lisa", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(PersonResponse{ // #nosec G104
			Person: Person{
				SourcedID:   "p-lisa",
				Status:      "active",
				DateLastMod: "2025-09-01T10:00:00Z",
				Name: PersonName{
					FamilyName: "Andersson",
					GivenName:  "Lisa",
					MiddleName: "Maria",
				},
				Email: []TypedContact{
					{Type: "institutional", Value: "lisa.andersson@student.su.se"},
				},
				Phone: []TypedContact{
					{Type: "mobile", Value: "+46701234567"},
				},
				Identifiers: []IdentifierEntry{
					{IdentifierType: "personnummer", Identifier: "199505151234"},
					{IdentifierType: "ladokUID", Identifier: "abc-def-123"},
				},
				Demographics: &Demographics{
					BirthDate: "1995-05-15",
				},
			},
		})
	})

	// GET /students (collection)
	mux.HandleFunc("/ims/oneroster/rostering/v1p2/students", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Honour limit query param for pagination testing
		persons := []Person{
			{SourcedID: "p-lisa", Name: PersonName{GivenName: "Lisa", FamilyName: "Andersson"}},
			{SourcedID: "p-erik", Name: PersonName{GivenName: "Erik", FamilyName: "Johansson"}},
			{SourcedID: "p-anna", Name: PersonName{GivenName: "Anna", FamilyName: "Svensson"}},
		}

		if r.URL.Query().Get("limit") == "2" {
			persons = persons[:2]
		}
		if r.URL.Query().Get("filter") == "familyName='Svensson'" {
			persons = []Person{persons[2]}
		}

		json.NewEncoder(w).Encode(PersonsResponse{Persons: persons}) // #nosec G104
	})

	// GET /persons/{personId}/enrollments
	mux.HandleFunc("/ims/oneroster/rostering/v1p2/persons/p-lisa/enrollments", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(EnrollmentsResponse{ // #nosec G104
			Enrollments: []Enrollment{
				{
					SourcedID: "e-1001",
					Status:    "active",
					Role:      "student",
					PersonRef: GUIDRef{SourcedID: "p-lisa"},
					ClassRef:  GUIDRef{SourcedID: "c-math301"},
					BeginDate: "2025-08-26",
					EndDate:   "2026-01-15",
					Primary:   true,
				},
				{
					SourcedID: "e-1002",
					Status:    "active",
					Role:      "student",
					PersonRef: GUIDRef{SourcedID: "p-lisa"},
					ClassRef:  GUIDRef{SourcedID: "c-cs201"},
					BeginDate: "2025-08-26",
					EndDate:   "2026-01-15",
				},
			},
		})
	})

	// GET /classes/{classId}
	mux.HandleFunc("/ims/oneroster/rostering/v1p2/classes/c-math301", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{ // #nosec G104
			"class": CourseOffering{
				SourcedID:    "c-math301",
				Status:       "active",
				Title:        "Advanced Linear Algebra",
				CourseCode:   "MATH301",
				ClassType:    "scheduled",
				SchoolRef:    GUIDRef{SourcedID: "org-su-math"},
				SubjectCodes: []string{"MAT"},
				TermRefs:     []GUIDRef{{SourcedID: "term-ht2025"}},
			},
		})
	})

	// GET /orgs/{orgId}
	mux.HandleFunc("/ims/oneroster/rostering/v1p2/orgs/org-su-math", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{ // #nosec G104
			"org": Organization{
				SourcedID:  "org-su-math",
				Name:       "Department of Mathematics",
				Type:       "department",
				Identifier: "SE-202100-3062",
				ParentRef:  &GUIDRef{SourcedID: "org-su"},
			},
		})
	})

	// GET /academicSessions/{sessionId}
	mux.HandleFunc("/ims/oneroster/rostering/v1p2/academicSessions/term-ht2025", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{ // #nosec G104
			"academicSession": AcademicSession{
				SourcedID:  "term-ht2025",
				Title:      "Autumn Term 2025",
				Type:       "term",
				StartDate:  "2025-08-26",
				EndDate:    "2026-01-15",
				SchoolYear: "2025",
			},
		})
	})

	// GET /students/{studentId}/results
	mux.HandleFunc("/ims/oneroster/gradebook/v1p2/students/p-lisa/results", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ResultsResponse{ // #nosec G104
			Results: []Result{
				{
					SourcedID:   "r-2001",
					PersonRef:   GUIDRef{SourcedID: "p-lisa"},
					ClassRef:    GUIDRef{SourcedID: "li-math301-exam"},
					Score:       "VG",
					ScoreStatus: "fully graded",
					ScoreDate:   "2026-01-20",
				},
				{
					SourcedID:   "r-2002",
					PersonRef:   GUIDRef{SourcedID: "p-lisa"},
					ClassRef:    GUIDRef{SourcedID: "li-cs201-lab"},
					Score:       "G",
					ScoreStatus: "fully graded",
					ScoreDate:   "2025-12-10",
				},
			},
		})
	})

	srv := httptest.NewServer(mux)

	log, err := logger.New("test", "", false)
	if err != nil {
		t.Fatal(err)
	}

	client, err := NewClient(ClientConfig{
		BaseURL:      srv.URL,
		TokenURL:     srv.URL + "/oauth2/token",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		TokenCache:   cache.NewMemoryCache[string](1 * time.Hour),
	}, log)
	if err != nil {
		t.Fatal(err)
	}

	return srv, client
}

func TestGetPerson(t *testing.T) {
	srv, client := testServer(t)
	defer srv.Close()

	person, err := client.GetPerson(context.Background(), "p-lisa")
	if err != nil {
		t.Fatalf("GetPerson: %v", err)
	}

	if person.SourcedID != "p-lisa" {
		t.Errorf("SourcedID = %q, want p-lisa", person.SourcedID)
	}
	if person.Name.GivenName != "Lisa" {
		t.Errorf("GivenName = %q, want Lisa", person.Name.GivenName)
	}
	if person.Name.FamilyName != "Andersson" {
		t.Errorf("FamilyName = %q, want Andersson", person.Name.FamilyName)
	}
	if person.Name.MiddleName != "Maria" {
		t.Errorf("MiddleName = %q, want Maria", person.Name.MiddleName)
	}
	if len(person.Email) != 1 || person.Email[0].Value != "lisa.andersson@student.su.se" {
		t.Errorf("Email = %v, want [{institutional lisa.andersson@student.su.se}]", person.Email)
	}
	if person.Demographics == nil || person.Demographics.BirthDate != "1995-05-15" {
		t.Errorf("BirthDate = %v, want 1995-05-15", person.Demographics)
	}
	if len(person.Identifiers) != 2 {
		t.Errorf("Identifiers count = %d, want 2", len(person.Identifiers))
	}
}

func TestGetPersonNotFound(t *testing.T) {
	srv, client := testServer(t)
	defer srv.Close()

	_, err := client.GetPerson(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent person, got nil")
	}
}

func TestGetStudents(t *testing.T) {
	srv, client := testServer(t)
	defer srv.Close()

	students, err := client.GetStudents(context.Background())
	if err != nil {
		t.Fatalf("GetStudents: %v", err)
	}

	if len(students) != 3 {
		t.Fatalf("got %d students, want 3", len(students))
	}
	if students[0].SourcedID != "p-lisa" {
		t.Errorf("first student SourcedID = %q, want p-lisa", students[0].SourcedID)
	}
	if students[2].Name.FamilyName != "Svensson" {
		t.Errorf("third student FamilyName = %q, want Svensson", students[2].Name.FamilyName)
	}
}

func TestGetStudentsWithLimit(t *testing.T) {
	srv, client := testServer(t)
	defer srv.Close()

	students, err := client.GetStudents(context.Background(), WithLimit(2))
	if err != nil {
		t.Fatalf("GetStudents(WithLimit): %v", err)
	}

	if len(students) != 2 {
		t.Errorf("got %d students, want 2 (limit=2)", len(students))
	}
}

func TestGetStudentsWithFilter(t *testing.T) {
	srv, client := testServer(t)
	defer srv.Close()

	students, err := client.GetStudents(context.Background(), WithFilter("familyName='Svensson'"))
	if err != nil {
		t.Fatalf("GetStudents(WithFilter): %v", err)
	}

	if len(students) != 1 {
		t.Fatalf("got %d students, want 1 (filtered)", len(students))
	}
	if students[0].Name.FamilyName != "Svensson" {
		t.Errorf("FamilyName = %q, want Svensson", students[0].Name.FamilyName)
	}
}

func TestGetEnrollmentsForPerson(t *testing.T) {
	srv, client := testServer(t)
	defer srv.Close()

	enrollments, err := client.GetEnrollmentsForPerson(context.Background(), "p-lisa")
	if err != nil {
		t.Fatalf("GetEnrollmentsForPerson: %v", err)
	}

	if len(enrollments) != 2 {
		t.Fatalf("got %d enrollments, want 2", len(enrollments))
	}

	e := enrollments[0]
	if e.SourcedID != "e-1001" {
		t.Errorf("SourcedID = %q, want e-1001", e.SourcedID)
	}
	if e.Status != "active" {
		t.Errorf("Status = %q, want active", e.Status)
	}
	if e.Role != "student" {
		t.Errorf("Role = %q, want student", e.Role)
	}
	if e.PersonRef.SourcedID != "p-lisa" {
		t.Errorf("PersonRef = %q, want p-lisa", e.PersonRef.SourcedID)
	}
	if e.ClassRef.SourcedID != "c-math301" {
		t.Errorf("ClassRef = %q, want c-math301", e.ClassRef.SourcedID)
	}
	if !e.Primary {
		t.Error("Primary = false, want true")
	}
	if e.BeginDate != "2025-08-26" {
		t.Errorf("BeginDate = %q, want 2025-08-26", e.BeginDate)
	}
}

func TestGetCourseOffering(t *testing.T) {
	srv, client := testServer(t)
	defer srv.Close()

	course, err := client.GetCourseOffering(context.Background(), "c-math301")
	if err != nil {
		t.Fatalf("GetCourseOffering: %v", err)
	}

	if course.SourcedID != "c-math301" {
		t.Errorf("SourcedID = %q, want c-math301", course.SourcedID)
	}
	if course.Title != "Advanced Linear Algebra" {
		t.Errorf("Title = %q, want Advanced Linear Algebra", course.Title)
	}
	if course.CourseCode != "MATH301" {
		t.Errorf("CourseCode = %q, want MATH301", course.CourseCode)
	}
	if course.ClassType != "scheduled" {
		t.Errorf("ClassType = %q, want scheduled", course.ClassType)
	}
	if course.SchoolRef.SourcedID != "org-su-math" {
		t.Errorf("SchoolRef = %q, want org-su-math", course.SchoolRef.SourcedID)
	}
	if len(course.SubjectCodes) != 1 || course.SubjectCodes[0] != "MAT" {
		t.Errorf("SubjectCodes = %v, want [MAT]", course.SubjectCodes)
	}
}

func TestGetOrganization(t *testing.T) {
	srv, client := testServer(t)
	defer srv.Close()

	org, err := client.GetOrganization(context.Background(), "org-su-math")
	if err != nil {
		t.Fatalf("GetOrganization: %v", err)
	}

	if org.SourcedID != "org-su-math" {
		t.Errorf("SourcedID = %q, want org-su-math", org.SourcedID)
	}
	if org.Name != "Department of Mathematics" {
		t.Errorf("Name = %q, want Department of Mathematics", org.Name)
	}
	if org.Type != "department" {
		t.Errorf("Type = %q, want department", org.Type)
	}
	if org.Identifier != "SE-202100-3062" {
		t.Errorf("Identifier = %q, want SE-202100-3062", org.Identifier)
	}
	if org.ParentRef == nil || org.ParentRef.SourcedID != "org-su" {
		t.Errorf("ParentRef = %v, want org-su", org.ParentRef)
	}
}

func TestGetAcademicSession(t *testing.T) {
	srv, client := testServer(t)
	defer srv.Close()

	session, err := client.GetAcademicSession(context.Background(), "term-ht2025")
	if err != nil {
		t.Fatalf("GetAcademicSession: %v", err)
	}

	if session.SourcedID != "term-ht2025" {
		t.Errorf("SourcedID = %q, want term-ht2025", session.SourcedID)
	}
	if session.Title != "Autumn Term 2025" {
		t.Errorf("Title = %q, want Autumn Term 2025", session.Title)
	}
	if session.Type != "term" {
		t.Errorf("Type = %q, want term", session.Type)
	}
	if session.StartDate != "2025-08-26" {
		t.Errorf("StartDate = %q, want 2025-08-26", session.StartDate)
	}
	if session.EndDate != "2026-01-15" {
		t.Errorf("EndDate = %q, want 2026-01-15", session.EndDate)
	}
	if session.SchoolYear != "2025" {
		t.Errorf("SchoolYear = %q, want 2025", session.SchoolYear)
	}
}

func TestGetResultsForPerson(t *testing.T) {
	srv, client := testServer(t)
	defer srv.Close()

	results, err := client.GetResultsForPerson(context.Background(), "p-lisa")
	if err != nil {
		t.Fatalf("GetResultsForPerson: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}

	r := results[0]
	if r.SourcedID != "r-2001" {
		t.Errorf("SourcedID = %q, want r-2001", r.SourcedID)
	}
	if r.Score != "VG" {
		t.Errorf("Score = %q, want VG", r.Score)
	}
	if r.ScoreStatus != "fully graded" {
		t.Errorf("ScoreStatus = %q, want fully graded", r.ScoreStatus)
	}
	if r.ScoreDate != "2026-01-20" {
		t.Errorf("ScoreDate = %q, want 2026-01-20", r.ScoreDate)
	}
	if r.PersonRef.SourcedID != "p-lisa" {
		t.Errorf("PersonRef = %q, want p-lisa", r.PersonRef.SourcedID)
	}
}

func TestGetResultsForPersonWithOptions(t *testing.T) {
	srv, client := testServer(t)
	defer srv.Close()

	// Verify query options are accepted (mock returns same data regardless)
	results, err := client.GetResultsForPerson(
		context.Background(), "p-lisa",
		WithLimit(10),
		WithOffset(0),
		WithSort("scoreDate"),
		WithOrderBy("desc"),
	)
	if err != nil {
		t.Fatalf("GetResultsForPerson(opts): %v", err)
	}
	if len(results) != 2 {
		t.Errorf("got %d results, want 2", len(results))
	}
}

// TestFullStudentJourney exercises a realistic usage pattern: look up a student,
// fetch their enrollments, resolve each course and organization, get the term,
// and finally retrieve grades.
func TestFullStudentJourney(t *testing.T) {
	srv, client := testServer(t)
	defer srv.Close()
	ctx := context.Background()

	// 1. Look up the student
	person, err := client.GetPerson(ctx, "p-lisa")
	if err != nil {
		t.Fatalf("step 1 GetPerson: %v", err)
	}
	if person.Name.GivenName != "Lisa" {
		t.Fatalf("unexpected person: %s", person.Name.GivenName)
	}

	// 2. Fetch her enrollments
	enrollments, err := client.GetEnrollmentsForPerson(ctx, person.SourcedID)
	if err != nil {
		t.Fatalf("step 2 GetEnrollmentsForPerson: %v", err)
	}
	if len(enrollments) == 0 {
		t.Fatal("step 2: no enrollments found")
	}

	// 3. Resolve the first enrollment's course offering
	course, err := client.GetCourseOffering(ctx, enrollments[0].ClassRef.SourcedID)
	if err != nil {
		t.Fatalf("step 3 GetCourseOffering: %v", err)
	}
	if course.Title != "Advanced Linear Algebra" {
		t.Errorf("step 3: course title = %q", course.Title)
	}

	// 4. Resolve the course's school/department
	org, err := client.GetOrganization(ctx, course.SchoolRef.SourcedID)
	if err != nil {
		t.Fatalf("step 4 GetOrganization: %v", err)
	}
	if org.Name != "Department of Mathematics" {
		t.Errorf("step 4: org name = %q", org.Name)
	}

	// 5. Resolve the term
	if len(course.TermRefs) == 0 {
		t.Fatal("step 5: no term refs on course")
	}
	term, err := client.GetAcademicSession(ctx, course.TermRefs[0].SourcedID)
	if err != nil {
		t.Fatalf("step 5 GetAcademicSession: %v", err)
	}
	if term.Title != "Autumn Term 2025" {
		t.Errorf("step 5: term title = %q", term.Title)
	}

	// 6. Get the student's grades
	results, err := client.GetResultsForPerson(ctx, person.SourcedID)
	if err != nil {
		t.Fatalf("step 6 GetResultsForPerson: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("step 6: got %d results, want 2", len(results))
	}
}
