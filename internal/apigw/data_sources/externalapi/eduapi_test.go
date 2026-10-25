package externalapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	pkgcache "github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const eduAPICoreReadonly = "http://purl.1edtech.org/spec/eduapi/v1p0/scope/core.readonly"

// requestedScopes runs one Edu-API fetch against a fake provider and returns
// the scope values its token endpoint received.
func requestedScopes(t *testing.T, configured []string) []string {
	t.Helper()

	var (
		mu     sync.Mutex
		scopes []string
	)
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		scopes = append(scopes, r.PostForm.Get("scope"))
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "test-token", "expires_in": 3600})
	})
	mux.HandleFunc("/base/persons/p-1", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"sourcedId":"p-1","recordLanguage":"en","recordStatus":"active"}`))
	})
	mux.HandleFunc("/base/enrollments", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	src, err := NewEduAPI(context.Background(), model.Remote{
		Type:         model.RemoteTypeEduAPI,
		BaseURL:      srv.URL + "/base",
		TokenURL:     srv.URL + "/oauth2/token",
		ClientID:     "vc",
		ClientSecret: "secret",
		Scopes:       configured,
		Timeout:      5 * time.Second,
	}, nil, (&model.Cfg{}).DocumentShape,
		pkgcache.NewMemoryCache[map[string]*model.CompleteDocument](time.Hour),
		pkgcache.NewMemoryCache[string](time.Hour), log)
	require.NoError(t, err)

	require.NoError(t, src.FetchAndStoreForVCI(context.Background(), "p-1", "any", "session-1"))

	mu.Lock()
	defer mu.Unlock()
	return append([]string(nil), scopes...)
}

func TestNewEduAPIDefaultsScope(t *testing.T) {
	got := requestedScopes(t, nil)

	require.NotEmpty(t, got, "token endpoint must be called")
	for _, s := range got {
		assert.Equal(t, eduAPICoreReadonly, s)
	}
}

func TestNewEduAPIKeepsConfiguredScopes(t *testing.T) {
	got := requestedScopes(t, []string{"sis.read", "other.scope"})

	require.NotEmpty(t, got, "token endpoint must be called")
	for _, s := range got {
		assert.Equal(t, "sis.read other.scope", s)
	}
}
