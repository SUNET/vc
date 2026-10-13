package oeapi

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

// testServer creates a mock OEAPI server with realistic data and returns the
// server and a pre-configured client. The caller must defer srv.Close().
func testServer(t *testing.T) (*httptest.Server, *Client) {
	t.Helper()

	mux := http.NewServeMux()

	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{ // #nosec G104
			"access_token": "test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})

	mux.HandleFunc("/v6/persons/p-lisa", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.oeapi+json")
		json.NewEncoder(w).Encode(Person{ // #nosec G104
			PersonID:      "p-lisa",
			PrimaryCode:   &CodeRef{CodeType: "identifier", Code: "s12345678"},
			GivenName:     "Lisa",
			Surname:       "Andersson",
			SurnamePrefix: "van",
			DisplayName:   "Lisa van Andersson",
			DateOfBirth:   "1995-05-15",
			Nationality:   &Country{Alpha2: "SE", Alpha3: "SWE"},
			Email:         "lisa.andersson@student.su.se",
			Affiliations:  []string{"student"},
			OtherCodes: []CodeRef{
				{CodeType: "nationalIdentityNumber", Code: "199505151234"},
			},
		})
	})

	mux.HandleFunc("/v6/persons/p-lisa/programme-offering-associations", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.oeapi+json")
		total := 1
		json.NewEncoder(w).Encode(Page[ProgrammeOfferingAssociation]{ // #nosec G104
			PageSize:   10,
			PageNumber: 1,
			TotalPages: &total,
			Items: []ProgrammeOfferingAssociation{
				{
					AssociationID:       "a-1",
					Role:                "student",
					State:               "associated",
					StartDateTime:       "2025-01-01T08:30:00+01:00",
					ProgrammeOfferingID: "po-1",
					ProgrammeOffering: &ProgrammeOffering{
						ProgrammeOfferingID: "po-1",
						PrimaryCode:         &CodeRef{CodeType: "identifier", Code: "BIO-2025"},
						Name:                []LanguageTypedString{{Language: "en-GB", Value: "Biology offering"}},
						Programme: &Programme{
							ProgrammeID:  "pr-1",
							Name:         []LanguageTypedString{{Language: "en-GB", Value: "Biology"}},
							Abbreviation: "BIO",
							Level:        "master",
						},
						Organisation: &Organisation{
							OrganisationID: "org-1",
							Name:           []LanguageTypedString{{Language: "nl-NL", Value: "SURF"}},
							ShortName:      "SURF",
						},
						AcademicSession: &AcademicSession{
							AcademicSessionID:   "as-1",
							AcademicSessionType: "semester",
							Name:                []LanguageTypedString{{Language: "en-GB", Value: "Autumn term 2025"}},
						},
					},
					Result: &Result{
						State:     "completed",
						Pass:      "passed",
						Score:     "9",
						Final:     true,
						StudyLoad: &StudyLoad{StudyLoadUnit: "ects", Value: 3},
					},
				},
			},
		})
	})

	mux.HandleFunc("/v6/persons/p-lisa/course-offering-associations", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.oeapi+json")
		json.NewEncoder(w).Encode(Page[CourseOfferingAssociation]{ // #nosec G104
			PageSize:   10,
			PageNumber: 1,
			Items: []CourseOfferingAssociation{
				{
					AssociationID:    "ca-1",
					Role:             "student",
					State:            "associated",
					CourseOfferingID: "co-1",
					CourseOffering: &CourseOffering{
						CourseOfferingID: "co-1",
						Name:             []LanguageTypedString{{Language: "en-GB", Value: "Intro to Biology"}},
						Course: &Course{
							CourseID:     "c-1",
							Name:         []LanguageTypedString{{Language: "en-GB", Value: "Biology 101"}},
							Abbreviation: "BIO101",
						},
					},
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
		srv.Close()
		t.Fatal(err)
	}
	return srv, client
}

func TestGetPerson(t *testing.T) {
	srv, client := testServer(t)
	defer srv.Close()

	person, err := client.GetPerson(context.Background(), "p-lisa")
	if err != nil {
		t.Fatal(err)
	}
	if person.PersonID != "p-lisa" {
		t.Errorf("PersonID = %q, want p-lisa", person.PersonID)
	}
	if person.PrimaryCode == nil || person.PrimaryCode.Code != "s12345678" {
		t.Errorf("PrimaryCode = %+v, want code s12345678", person.PrimaryCode)
	}
	if len(person.OtherCodes) != 1 {
		t.Errorf("OtherCodes len = %d, want 1", len(person.OtherCodes))
	}
}

func TestGetProgrammeOfferingAssociationsForPerson(t *testing.T) {
	srv, client := testServer(t)
	defer srv.Close()

	associations, err := client.GetProgrammeOfferingAssociationsForPerson(context.Background(), "p-lisa")
	if err != nil {
		t.Fatal(err)
	}
	if len(associations) != 1 {
		t.Fatalf("associations len = %d, want 1", len(associations))
	}
	a := associations[0]
	if a.State != "associated" {
		t.Errorf("State = %q, want associated", a.State)
	}
	if a.ProgrammeOffering == nil || a.ProgrammeOffering.Programme == nil {
		t.Fatal("expected embedded programme offering and programme")
	}
	if a.Result == nil || a.Result.Score != "9" {
		t.Errorf("Result = %+v, want score 9", a.Result)
	}
}

func TestGetCourseOfferingAssociationsForPerson(t *testing.T) {
	srv, client := testServer(t)
	defer srv.Close()

	associations, err := client.GetCourseOfferingAssociationsForPerson(context.Background(), "p-lisa")
	if err != nil {
		t.Fatal(err)
	}
	if len(associations) != 1 {
		t.Fatalf("associations len = %d, want 1", len(associations))
	}
	if associations[0].CourseOffering == nil || associations[0].CourseOffering.Course == nil {
		t.Fatal("expected embedded course offering and course")
	}
}
