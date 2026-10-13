package oeapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/cache"
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
	mux.HandleFunc("/v6/persons/p-1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.oeapi+json")
		json.NewEncoder(w).Encode(Person{PersonID: "p-1", GivenName: "Test", Surname: "User"}) // #nosec G104
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

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

	_, _ = client.GetPerson(context.Background(), "p-1")
	_, _ = client.GetPerson(context.Background(), "p-1")

	if tokenCalls != 1 {
		t.Errorf("token endpoint called %d times, want 1 (should be cached)", tokenCalls)
	}
}

func TestNewClientRequiresTokenCache(t *testing.T) {
	log, err := logger.New("test", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewClient(ClientConfig{BaseURL: "https://example.org"}, log); err == nil {
		t.Fatal("expected error when TokenCache is nil")
	}
}

func TestQueryOptions(t *testing.T) {
	q := buildQuery([]QueryOption{
		WithPageSize(50),
		WithPageNumber(2),
		WithRole("student"),
		WithState("associated"),
	})
	want := url.Values{
		"pageSize":   {"50"},
		"pageNumber": {"2"},
		"role":       {"student"},
		"state":      {"associated"},
	}
	if q.Encode() != want.Encode() {
		t.Errorf("buildQuery = %q, want %q", q.Encode(), want.Encode())
	}
}
