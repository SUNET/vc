package externalapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	pkgcache "github.com/SUNET/vc/pkg/cache"
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

	docs := newTestDocCache()
	src, err := NewOEAPI(context.Background(), testRemote(model.RemoteTypeOEAPI, srv.URL, ""), nil,
		docs, pkgcache.NewMemoryCache[string](time.Hour), newTestLog(t))
	require.NoError(t, err)

	return fetchStored(t, src, docs, params)
}

func oeapiOffering(course, programme string) *pkgcache.ExternalAPIParams {
	return &pkgcache.ExternalAPIParams{OEAPI: &pkgcache.OEAPIParams{CourseOfferingID: course, ProgrammeOfferingID: programme}}
}

func TestOEAPIAssociationChoice(t *testing.T) {
	picks := []struct {
		name       string
		params     *pkgcache.ExternalAPIParams
		wantCourse string
		wantProg   string
		wantState  string
	}{
		{"no params keeps the first association of each kind", nil, "ca-1", "pa-1", ""},
		{"a requested course offering picks that association", oeapiOffering("co-2", ""), "ca-2", "pa-1", ""},
		{"a requested programme offering picks that association", oeapiOffering("", "po-2"), "ca-1", "pa-2", ""},
		{"a non-associated association is matched when its offering is requested", oeapiOffering("co-3", ""), "ca-3", "pa-1", "withdrawn"},
	}
	for _, tc := range picks {
		t.Run(tc.name, func(t *testing.T) {
			data, err := fetchOEAPI(t, http.StatusOK, tc.params)
			require.NoError(t, err)
			assert.Equal(t, tc.wantCourse, data["course.associationId"])
			assert.Equal(t, tc.wantProg, data["programme.associationId"])
			if tc.wantState != "" {
				assert.Equal(t, tc.wantState, data["course.state"])
			}
		})
	}

	t.Run("an offering the person is not associated with fails", func(t *testing.T) {
		for _, params := range []*pkgcache.ExternalAPIParams{oeapiOffering("co-9", ""), oeapiOffering("", "po-9")} {
			_, err := fetchOEAPI(t, http.StatusOK, params)
			require.ErrorIs(t, err, ErrNotEnrolled)
		}
	})

	t.Run("a failed association call fails only when its offering is requested", func(t *testing.T) {
		_, err := fetchOEAPI(t, http.StatusInternalServerError, oeapiOffering("co-2", ""))
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrNotEnrolled)

		_, err = fetchOEAPI(t, http.StatusInternalServerError, nil)
		require.NoError(t, err)
	})
}
