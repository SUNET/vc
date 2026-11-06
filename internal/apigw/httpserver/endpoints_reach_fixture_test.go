package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/SUNET/vc/internal/apigw/apiv1"
	"github.com/SUNET/vc/internal/apigw/db"
	"github.com/SUNET/vc/pkg/httphelpers"
	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// reachAccepts answers for a fixture what a store's pair condition answers. The
// store contract test holds the same answer on Mongo, Postgres and MariaDB.
func reachAccepts(reach httphelpers.ResourceReach, source, scope string) bool {
	if reach.Everything() {
		return true
	}
	matches := func(value httphelpers.ResourceValue, stored string) bool {
		exact, isExact := value.Exact()
		return !isExact || exact == stored
	}
	for _, pair := range reach.Pairs() {
		if matches(pair.AuthenticSource, source) && matches(pair.Scope, scope) {
			return true
		}
	}
	return false
}

func listQueryAccepts(query *db.ListQuery, source, scope string) bool {
	return reachAccepts(query.Reach, source, scope)
}

func searchQueryAccepts(query *db.SearchDocumentsQuery, source, scope string) bool {
	return reachAccepts(query.Reach, source, scope)
}

// mappingFixtureStore answers SearchMappings with one mapping per distinct source
// of the fixture documents.
type mappingFixtureStore struct {
	db.IdentityMappingStore
	documents []*model.MetaData
}

func (s *mappingFixtureStore) SearchMappings(_ context.Context, query *db.SearchMappingsQuery) ([]*model.IdentityMapping, error) {
	sources, everySource := query.Reach.SourcesForScope(httphelpers.IdentityMappingScope)
	found := []*model.IdentityMapping{}
	seen := []string{}
	for _, meta := range s.documents {
		if slices.Contains(seen, meta.AuthenticSource) {
			continue
		}
		seen = append(seen, meta.AuthenticSource)
		if selectedBy(query.AuthenticSource, meta.AuthenticSource) && (everySource || slices.Contains(sources, meta.AuthenticSource)) {
			found = append(found, &model.IdentityMapping{AuthenticSource: meta.AuthenticSource})
		}
	}
	return found, nil
}

// TestIdentityMappingSearchKeepsSourcesPairedWithItsScope holds the scope check of
// the route: a session reaches a mapping when the engine allows its source with
// scope identity_mapping.
func TestIdentityMappingSearchKeepsSourcesPairedWithItsScope(t *testing.T) {
	documents := readFixtureDocuments()
	sources := []string{}
	for _, doc := range documents {
		if !slices.Contains(sources, doc.AuthenticSource) {
			sources = append(sources, doc.AuthenticSource)
		}
	}

	for _, row := range []struct {
		name    string
		rules   []string
		refused bool
	}{
		{name: "no rule", rules: []string{readRule("apigw", "*", "*", "bob", "*", "*")}, refused: true},
		{name: "another scope only", rules: []string{aliceRule("A", "pid")}, refused: true},
		{name: "its scope", rules: []string{aliceRule("A", "identity_mapping")}},
		{name: "one source paired with it", rules: []string{aliceRule("A", "identity_mapping"), aliceRule("B", "pid")}},
		{name: "in a set of scopes", rules: []string{aliceRule("(* set A B)", "(* set pid identity_mapping)")}},
		{name: "wildcard scope", rules: []string{aliceRule("(* set A B)", "*")}},
		{name: "wildcard source", rules: []string{aliceRule("*", "identity_mapping")}},
		{name: "scope form", rules: []string{aliceRule("B", "identity*")}},
	} {
		t.Run(row.name, func(t *testing.T) {
			chain := newReadChain(t, documents, row.rules, true)
			req := httptest.NewRequest(http.MethodGet, "/api/v1/identity/mapping/search?search=s", nil)
			chain.sessionAs("alice")(req)
			reply := httptest.NewRecorder()
			chain.engine.ServeHTTP(reply, req)
			if row.refused {
				assert.Equal(t, http.StatusForbidden, reply.Code, reply.Body.String())
				return
			}
			require.Equal(t, http.StatusOK, reply.Code, reply.Body.String())

			var found apiv1.IdentityMappingSearchReply
			require.NoError(t, json.Unmarshal(reply.Body.Bytes(), &found))
			received := make([]string, 0, len(found.Data))
			for _, mapping := range found.Data {
				received = append(received, mapping.AuthenticSource)
			}
			want := []string{}
			for _, source := range sources {
				if chain.spocp.QueryElement(httphelpers.BuildSPOCPQuery("apigw", http.MethodGet, "/api/v1/identity/mapping/search", "alice", source, httphelpers.IdentityMappingScope)) {
					want = append(want, source)
				}
			}
			assert.ElementsMatch(t, want, received)
		})
	}
}
