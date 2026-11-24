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
	}, nil,
		pkgcache.NewMemoryCache[map[string]*model.CompleteDocument](time.Hour),
		pkgcache.NewMemoryCache[string](time.Hour), log)
	require.NoError(t, err)

	require.NoError(t, src.FetchAndStoreForVCI(context.Background(), "p-1", "any", "session-1", nil))

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

const enrollmentsJSON = `[
	{"sourcedId":"e1","person":"p-1","educationOffering":"co-1","offeringType":"course","role":"student","isActive":true},
	{"sourcedId":"e2","person":"p-1","educationOffering":"co-2","offeringType":"course","role":"student","isActive":true},
	{"sourcedId":"e3","person":"p-1","educationOffering":"co-3","offeringType":"course","role":"student","isActive":false,"enrollmentStatus":"completed"}
]`

// fetchWithEnrollments runs one fetch against a fake Edu-API and returns the
// stored document's data and the fetch error. enrollmentsStatus is the status
// the enrollments endpoint answers with.
func fetchWithEnrollments(t *testing.T, enrollmentsStatus int, params *pkgcache.ExternalAPIParams) (map[string]any, error) {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "test-token", "expires_in": 3600})
	})
	mux.HandleFunc("/base/persons/p-1", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"sourcedId":"p-1","recordLanguage":"en","recordStatus":"active"}`))
	})
	mux.HandleFunc("/base/enrollments", func(w http.ResponseWriter, _ *http.Request) {
		if enrollmentsStatus != http.StatusOK {
			http.Error(w, "boom", enrollmentsStatus)
			return
		}
		_, _ = w.Write([]byte(enrollmentsJSON))
	})
	mux.HandleFunc("/base/courseOfferings/", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Path[len("/base/courseOfferings/"):]
		_, _ = w.Write([]byte(`{"sourcedId":"` + id + `"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	docs := pkgcache.NewMemoryCache[map[string]*model.CompleteDocument](time.Hour)
	src, err := NewEduAPI(context.Background(), model.Remote{
		Type:         model.RemoteTypeEduAPI,
		BaseURL:      srv.URL + "/base",
		TokenURL:     srv.URL + "/oauth2/token",
		ClientID:     "vc",
		ClientSecret: "secret",
		Timeout:      5 * time.Second,
	}, nil, docs, pkgcache.NewMemoryCache[string](time.Hour), log)
	require.NoError(t, err)

	if err := src.FetchAndStoreForVCI(context.Background(), "p-1", "any", "session-1", params); err != nil {
		return nil, err
	}
	stored, ok := docs.Get(context.Background(), "session-1")
	require.True(t, ok)
	for _, d := range stored {
		return d.DocumentData, nil
	}
	return nil, nil
}

func offering(id string) *pkgcache.ExternalAPIParams {
	return &pkgcache.ExternalAPIParams{EduAPI: &pkgcache.EduAPIParams{EducationOfferingID: id}}
}

func TestEduAPIEnrollmentChoice(t *testing.T) {
	t.Run("no params keeps the first course enrollment", func(t *testing.T) {
		data, err := fetchWithEnrollments(t, http.StatusOK, nil)
		require.NoError(t, err)
		assert.Equal(t, "co-1", data["enrollment.educationOffering"])
	})

	t.Run("an empty offering keeps the first course enrollment", func(t *testing.T) {
		data, err := fetchWithEnrollments(t, http.StatusOK, offering(""))
		require.NoError(t, err)
		assert.Equal(t, "co-1", data["enrollment.educationOffering"])
	})

	t.Run("a requested offering picks that enrollment", func(t *testing.T) {
		data, err := fetchWithEnrollments(t, http.StatusOK, offering("co-2"))
		require.NoError(t, err)
		assert.Equal(t, "co-2", data["enrollment.educationOffering"])
		assert.Equal(t, "co-2", data["course.sourcedId"])
	})

	t.Run("a finished enrollment is matched when its offering is requested", func(t *testing.T) {
		data, err := fetchWithEnrollments(t, http.StatusOK, offering("co-3"))
		require.NoError(t, err)
		assert.Equal(t, "co-3", data["enrollment.educationOffering"])
		assert.Equal(t, false, data["enrollment.isActive"])
		assert.Equal(t, "completed", data["enrollment.enrollmentStatus"])
	})

	t.Run("a finished enrollment is never picked without an offering", func(t *testing.T) {
		data, err := fetchWithEnrollments(t, http.StatusOK, nil)
		require.NoError(t, err)
		assert.NotEqual(t, "co-3", data["enrollment.educationOffering"])
	})

	t.Run("an offering the person is not enrolled in fails", func(t *testing.T) {
		_, err := fetchWithEnrollments(t, http.StatusOK, offering("co-9"))
		require.ErrorIs(t, err, ErrNotEnrolled)
	})

	t.Run("a failed enrollments call fails when an offering is requested", func(t *testing.T) {
		_, err := fetchWithEnrollments(t, http.StatusInternalServerError, offering("co-2"))
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrNotEnrolled)
	})

	t.Run("a failed enrollments call is tolerated without an offering", func(t *testing.T) {
		_, err := fetchWithEnrollments(t, http.StatusInternalServerError, nil)
		require.NoError(t, err)
	})
}
