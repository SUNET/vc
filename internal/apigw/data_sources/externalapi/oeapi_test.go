package externalapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	pkgcache "github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/oauth2client/oauth2clienttest"
	"github.com/SUNET/vc/pkg/oeapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fetchOEAPI runs one fetch against a fake OEAPI and returns the stored
// document's data and the fetch error. courseStatus is the status the course
// association endpoint answers with.
func fetchOEAPI(t *testing.T, courseStatus int, params *pkgcache.ExternalAPIParams) (map[string]any, error) {
	t.Helper()

	mux := http.NewServeMux()
	oauth2clienttest.RegisterTokenHandler(mux, "/oauth2/token", "test-token")
	mux.HandleFunc("/v6/persons/p-1", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(oeapi.Person{PersonID: "p-1", GivenName: "Lisa"})
	})
	mux.HandleFunc("/v6/persons/p-1/course-offering-associations", func(w http.ResponseWriter, _ *http.Request) {
		if courseStatus != http.StatusOK {
			http.Error(w, "boom", courseStatus)
			return
		}
		_ = json.NewEncoder(w).Encode(oeapi.Page[oeapi.CourseOfferingAssociation]{Items: []oeapi.CourseOfferingAssociation{
			{AssociationID: "ca-1", State: "associated", CourseOfferingID: "co-1"},
			{AssociationID: "ca-2", State: "associated", CourseOfferingID: "co-2"},
			{AssociationID: "ca-3", State: "withdrawn", CourseOfferingID: "co-3"},
		}})
	})
	mux.HandleFunc("/v6/persons/p-1/programme-offering-associations", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(oeapi.Page[oeapi.ProgrammeOfferingAssociation]{Items: []oeapi.ProgrammeOfferingAssociation{
			{AssociationID: "pa-1", State: "associated", ProgrammeOfferingID: "po-1", ProgrammeOffering: &oeapi.ProgrammeOffering{ProgrammeOfferingID: "po-1"}},
			{AssociationID: "pa-2", State: "associated", ProgrammeOfferingID: "po-2", ProgrammeOffering: &oeapi.ProgrammeOffering{ProgrammeOfferingID: "po-2"}},
		}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	docs := pkgcache.NewMemoryCache[map[string]*model.CompleteDocument](time.Hour)
	src, err := NewOEAPI(context.Background(), model.Remote{
		Type:         model.RemoteTypeOEAPI,
		BaseURL:      srv.URL,
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

func oeapiOffering(course, programme string) *pkgcache.ExternalAPIParams {
	return &pkgcache.ExternalAPIParams{OEAPI: &pkgcache.OEAPIParams{CourseOfferingID: course, ProgrammeOfferingID: programme}}
}

func TestOEAPIAssociationChoice(t *testing.T) {
	t.Run("no params keeps the first association of each kind", func(t *testing.T) {
		data, err := fetchOEAPI(t, http.StatusOK, nil)
		require.NoError(t, err)
		assert.Equal(t, "ca-1", data["course.associationId"])
		assert.Equal(t, "pa-1", data["programme.associationId"])
	})

	t.Run("a requested course offering picks that association", func(t *testing.T) {
		data, err := fetchOEAPI(t, http.StatusOK, oeapiOffering("co-2", ""))
		require.NoError(t, err)
		assert.Equal(t, "ca-2", data["course.associationId"])
		assert.Equal(t, "pa-1", data["programme.associationId"], "an unset id keeps the first programme")
	})

	t.Run("a requested programme offering picks that association", func(t *testing.T) {
		data, err := fetchOEAPI(t, http.StatusOK, oeapiOffering("", "po-2"))
		require.NoError(t, err)
		assert.Equal(t, "pa-2", data["programme.associationId"])
		assert.Equal(t, "ca-1", data["course.associationId"])
	})

	t.Run("a course offering the person is not associated with fails", func(t *testing.T) {
		_, err := fetchOEAPI(t, http.StatusOK, oeapiOffering("co-9", ""))
		require.ErrorIs(t, err, ErrNotEnrolled)
	})

	t.Run("a non-associated association is matched when its offering is requested", func(t *testing.T) {
		data, err := fetchOEAPI(t, http.StatusOK, oeapiOffering("co-3", ""))
		require.NoError(t, err)
		assert.Equal(t, "ca-3", data["course.associationId"])
		assert.Equal(t, "withdrawn", data["course.state"])
	})

	t.Run("a programme offering the person is not associated with fails", func(t *testing.T) {
		_, err := fetchOEAPI(t, http.StatusOK, oeapiOffering("", "po-9"))
		require.ErrorIs(t, err, ErrNotEnrolled)
	})

	t.Run("a failed association call fails when its offering is requested", func(t *testing.T) {
		_, err := fetchOEAPI(t, http.StatusInternalServerError, oeapiOffering("co-2", ""))
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrNotEnrolled)
	})

	t.Run("a failed association call is tolerated without an offering", func(t *testing.T) {
		_, err := fetchOEAPI(t, http.StatusInternalServerError, nil)
		require.NoError(t, err)
	})
}
