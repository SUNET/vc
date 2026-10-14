// Package oauth2clienttest provides test helpers for building oauth2client
// clients against httptest servers, shared by the external-API client tests.
package oauth2clienttest

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/oauth2client"
)

// RegisterTokenHandler registers a static OAuth2 CCG token endpoint at path on mux.
func RegisterTokenHandler(mux *http.ServeMux, path, token string) {
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": token,
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	})
}

// NewClient builds an oauth2client client for baseURL with its token endpoint at
// baseURL+"/oauth2/token".
func NewClient(t *testing.T, baseURL, accept, name string) *oauth2client.Client {
	t.Helper()
	log, err := logger.New("test", "", false)
	if err != nil {
		t.Fatal(err)
	}
	c, err := oauth2client.New(oauth2client.Config{
		BaseURL:      baseURL,
		TokenURL:     baseURL + "/oauth2/token",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Accept:       accept,
		Name:         name,
		TokenCache:   cache.NewMemoryCache[string](1 * time.Hour),
	}, log)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
