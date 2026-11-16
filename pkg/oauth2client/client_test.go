package oauth2client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
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

func newTestClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	log, err := logger.New("test", "", false)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(Config{
		BaseURL:      srv.URL + "/base",
		TokenURL:     srv.URL + "/oauth2/token",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Name:         "test",
		TokenCache:   cache.NewMemoryCache[string](1 * time.Hour),
	}, log)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newTokenAndResourceServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "test-token", "expires_in": 3600})
	})
	mux.HandleFunc("/base/resource", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Total-Count", "7")
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})
	return httptest.NewServer(mux)
}

func TestGetWithHeaders(t *testing.T) {
	srv := newTokenAndResourceServer()
	defer srv.Close()

	_, h, err := newTestClient(t, srv).GetWithHeaders(context.Background(), "/resource", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := h.Get("X-Total-Count"); got != "7" {
		t.Errorf("X-Total-Count = %q, want 7", got)
	}
}

func TestGetURL(t *testing.T) {
	srv := newTokenAndResourceServer()
	defer srv.Close()
	c := newTestClient(t, srv)

	for _, u := range []string{srv.URL + "/base/resource", "/base/resource"} {
		if _, _, err := c.GetURL(context.Background(), u); err != nil {
			t.Errorf("GetURL(%q): %v", u, err)
		}
	}

	for _, u := range []string{"https://evil.example.org/base/resource", "http://127.0.0.1:1/base/resource"} {
		if _, _, err := c.GetURL(context.Background(), u); err == nil {
			t.Errorf("GetURL(%q): expected cross-origin error", u)
		}
	}
}

func TestRedirectToOtherOriginIsRefused(t *testing.T) {
	var leaked atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			leaked.Store(true)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer other.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "test-token", "expires_in": 3600})
	})
	// Same hostname, different port: Go would keep the Authorization header.
	mux.HandleFunc("/base/other-port", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/base/resource", http.StatusFound)
	})
	mux.HandleFunc("/base/same-origin", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/base/resource", http.StatusFound)
	})
	mux.HandleFunc("/base/resource", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := newTestClient(t, srv)

	_, err := c.Get(context.Background(), "/other-port", nil)
	if err == nil {
		t.Fatal("expected the cross-origin redirect to be refused")
	}
	if leaked.Load() {
		t.Error("Authorization header reached the other origin")
	}

	if _, err := c.Get(context.Background(), "/same-origin", nil); err != nil {
		t.Errorf("same-origin redirect must still work: %v", err)
	}
}
