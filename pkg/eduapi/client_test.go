package eduapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SUNET/vc/pkg/logger"
)

func TestTokenCaching(t *testing.T) {
	tokenCalls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		tokenCalls++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{ // #nosec G104
			"access_token": "test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})
	mux.HandleFunc("/ims/oneroster/rostering/v1p2/persons/p-1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(PersonResponse{ // #nosec G104
			Person: Person{SourcedID: "p-1", Name: PersonName{GivenName: "Test", FamilyName: "User"}},
		})
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	log, err := logger.New("test", "", false)
	if err != nil {
		t.Fatal(err)
	}

	client := NewClient(ClientConfig{
		BaseURL:      srv.URL,
		TokenURL:     srv.URL + "/oauth2/token",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}, log)

	_, _ = client.GetPerson(context.Background(), "p-1")
	_, _ = client.GetPerson(context.Background(), "p-1")

	if tokenCalls != 1 {
		t.Errorf("token endpoint called %d times, want 1 (should be cached)", tokenCalls)
	}
}

func TestQueryOptions(t *testing.T) {
	q := buildQuery([]QueryOption{
		WithLimit(10),
		WithOffset(20),
		WithFilter("role='student'"),
		WithSort("familyName"),
		WithOrderBy("asc"),
	})

	if q.Get("limit") != "10" {
		t.Errorf("limit = %q, want 10", q.Get("limit"))
	}
	if q.Get("offset") != "20" {
		t.Errorf("offset = %q, want 20", q.Get("offset"))
	}
	if q.Get("filter") != "role='student'" {
		t.Errorf("filter = %q, want role='student'", q.Get("filter"))
	}
	if q.Get("sort") != "familyName" {
		t.Errorf("sort = %q, want familyName", q.Get("sort"))
	}
	if q.Get("orderBy") != "asc" {
		t.Errorf("orderBy = %q, want asc", q.Get("orderBy"))
	}
}
