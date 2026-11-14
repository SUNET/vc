package httphelpers

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// A request type whose selector the guard cannot read reaches no handler. The
// route table in internal/apigw/httpserver covers only today's request types,
// which all hold strings.
func TestBoundSelectorsRefuseASelectorThatHoldsNoString(t *testing.T) {
	source := "B"
	tests := []struct {
		name    string
		request any
	}{
		{name: "by Go name", request: &struct{ AuthenticSource *string }{&source}},
		{name: "by JSON tag", request: &struct {
			Picked []string `json:"scope"`
		}{[]string{"other"}}},
		{name: "nested", request: &struct {
			Meta map[string]struct{ Scope *string }
		}{
			map[string]struct{ Scope *string }{"d": {&source}},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := boundSelectors(tt.request)
			require.Error(t, err)
		})
	}
}
