package resourcereach_test

import (
	"testing"

	"github.com/SUNET/vc/pkg/httphelpers"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/resourcereach"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResourceReachAgreesWithEngine holds the two promises of the type over every
// form the rule parser accepts: Selecting answers as the engine answers, and a pair
// store filter is never wider than the engine.
func TestResourceReachAgreesWithEngine(t *testing.T) {
	values := []string{"A", "a", "A ", "B", "eu-1", "x-eu", "*", "eu*", "pid", "ehic", "identity_mapping"}
	positions := []string{
		"A", "*", "(*)", "(* set A B)", "(* set (* set A) eu-1)", "(* set * B)", "(* set eu* B)", "(* set (*) B)",
		"eu*", "**", "(* prefix eu)", "(* suffix eu)", "(* set A (* prefix eu))", "(* set A (* suffix eu))", "(foo bar)", "(* set (foo bar) B)",
	}
	const service, method, path, subject = "apigw", "GET", "/api/v1/datastore/search", "alice"

	for _, source := range positions {
		for _, scope := range positions {
			rule := "(vc (service apigw)(method GET)(path /api/v1/*)(subject alice)(authentic_source " + source + ")(scope " + scope + "))"
			t.Run(rule, func(t *testing.T) {
				engine, err := httphelpers.BuildSPOCPEngine(model.APIAuth{Rules: []string{rule}})
				require.NoError(t, err)
				reach, err := resourcereach.Resolve(engine, service, method, path, subject)
				require.NoError(t, err)

				for _, namedSource := range values {
					for _, namedScope := range values {
						allowed := engine.QueryElement(httphelpers.BuildSPOCPQuery(service, method, path, subject, namedSource, namedScope))
						assert.Equal(t, allowed, !reach.Selecting(namedSource, namedScope).Nothing(),
							"Selecting(%q, %q)", namedSource, namedScope)
						if !allowed {
							assert.Falsef(t, reachPairsAccept(reach, namedSource, namedScope), "pair filter widens to (%q, %q)", namedSource, namedScope)
						}
					}
				}
			})
		}
	}
}

func reachPairsAccept(reach resourcereach.Reach, source, scope string) bool {
	if reach.Everything() {
		return true
	}
	matches := func(value resourcereach.Value, stored string) bool {
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
