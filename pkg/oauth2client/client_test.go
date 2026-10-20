package oauth2client

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
	mux.HandleFunc("/resource", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true}) // #nosec G104
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	log, err := logger.New("test", "", false)
	if err != nil {
		t.Fatal(err)
	}

	client, err := New(Config{
		BaseURL:      srv.URL,
		TokenURL:     srv.URL + "/oauth2/token",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Name:         "test",
		TokenCache:   cache.NewMemoryCache[string](1 * time.Hour),
	}, log)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.Get(context.Background(), "/resource", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Get(context.Background(), "/resource", nil); err != nil {
		t.Fatal(err)
	}

	if tokenCalls != 1 {
		t.Errorf("token endpoint called %d times, want 1 (should be cached)", tokenCalls)
	}
}

func TestNewRequiresTokenCache(t *testing.T) {
	log, err := logger.New("test", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{BaseURL: "https://example.org", Name: "test"}, log); err == nil {
		t.Fatal("expected error when TokenCache is nil")
	}
}
