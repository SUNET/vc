package httpserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SUNET/vc/internal/apigw/apiv1"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/sdjwtvc"
	"github.com/SUNET/vc/pkg/vcclient"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// lookupAPI captures the request the handler builds, which is the only place
// the holder's language preference can enter apiv1.
type lookupAPI struct {
	unimplementedApiv1
	got *vcclient.UserLookupRequest
}

func (a *lookupAPI) GetVCTMFromScope(context.Context, *apiv1.GetVCTMFromScopeRequest) (*sdjwtvc.VCTM, error) {
	return &sdjwtvc.VCTM{VCT: "urn:example:pid"}, nil
}

func (a *lookupAPI) UserLookup(_ context.Context, req *vcclient.UserLookupRequest) (*vcclient.UserLookupReply, error) {
	a.got = req

	return &vcclient.UserLookupReply{RedirectURL: "https://wallet.example/cb?code=abc"}, nil
}

// userLookupEngine registers the real route behind the same session
// middleware service.go puts it behind, seeding the session keys the handler
// reads.
func userLookupEngine(t *testing.T, mockAPI Apiv1) *gin.Engine {
	t.Helper()

	s, engine, rg := newSessionTestEngine(t, mockAPI)
	rg.Use(seedSession(map[string]any{
		"scope":         "pid",
		"request_uri":   "urn:ietf:params:oauth:request_uri:abc",
		"auth_provider": model.AuthProviderOpenID4VP,
		"response_code": "response-code-1",
	}))
	s.httpHelpers.Server.RegEndpoint(context.Background(), rg, http.MethodGet,
		"user/lookup", http.StatusOK, s.endpointUserLookup)

	return engine
}

// The consent page names the credential from its type metadata, which may
// carry one display entry per language. apiv1 cannot see the request, so the
// handler has to carry Accept-Language across; without this the page picked
// whichever entry the metadata listed first.
func TestUserLookupCarriesTheHolderLanguagePreference(t *testing.T) {
	for _, tc := range []struct {
		name         string
		header       string
		want         []string
		wantRejected []string
	}{
		{
			name:         "the browser's ordered preference reaches apiv1",
			header:       "sv-SE,sv;q=0.9,en-US;q=0.8",
			want:         []string{"sv-se", "sv", "en-us"},
			wantRejected: []string{},
		},
		{
			name:         "a request with no Accept-Language carries none",
			header:       "",
			want:         []string{},
			wantRejected: []string{},
		},
		{
			// A q=0 tag is not a preference, so it is absent from Locales,
			// but it still has to reach apiv1 or the selection there cannot
			// keep honouring it.
			name:         "a refused tag travels separately from the preferences",
			header:       "sv-SE;q=0, sv;q=1, en;q=0.8",
			want:         []string{"sv", "en"},
			wantRejected: []string{"sv-se"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := &lookupAPI{}
			engine := userLookupEngine(t, api)

			req := httptest.NewRequest(http.MethodGet, "/user/lookup", nil)
			if tc.header != "" {
				req.Header.Set("Accept-Language", tc.header)
			}
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
			require.NotNil(t, api.got, "UserLookup was never called")
			assert.Equal(t, tc.want, api.got.Locales)
			assert.Equal(t, tc.wantRejected, api.got.RejectedLocales)
		})
	}
}
