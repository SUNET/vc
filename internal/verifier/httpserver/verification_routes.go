package httpserver

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// endpointHandler is the handler shape httphelpers.RegEndpoint takes.
type endpointHandler func(context.Context, *gin.Context) (any, error)

// verificationRoute is one route registered under a /verification group.
type verificationRoute struct {
	method string
	// path is relative to the group, so its first segment is the route name
	// a browser asset has to fetch.
	path    string
	status  int
	handler func(*Service) endpointHandler
}

// name is the first path segment, with any gin parameters dropped.
func (r verificationRoute) name() string {
	name, _, _ := strings.Cut(r.path, "/")
	return name
}

// sessionVerificationRoutes are registered under the user-session group.
var sessionVerificationRoutes = []verificationRoute{
	{http.MethodGet, "request-object", http.StatusOK, func(s *Service) endpointHandler { return s.endpointVerificationRequestObject }},
	{http.MethodPost, "direct_post", http.StatusOK, func(s *Service) endpointHandler { return s.endpointVerificationDirectPost }},
	{http.MethodGet, "callback", http.StatusOK, func(s *Service) endpointHandler { return s.endpointVerificationCallback }},
	// Here, rather than on the root group, so endpointSessionPreference can
	// read session_id from the gin cookie when the body omits it
	// (standalone verifier UI).
	{http.MethodPost, "session-preference", http.StatusOK, func(s *Service) endpointHandler { return s.endpointSessionPreference }},
}

// oidcVerificationRoutes are registered under the root group.
var oidcVerificationRoutes = []verificationRoute{
	{http.MethodGet, "request-object/:session_id", http.StatusOK, func(s *Service) endpointHandler { return s.endpointOIDCRequestObject }},
	{http.MethodPost, "oidc-direct_post", http.StatusOK, func(s *Service) endpointHandler { return s.endpointOIDCDirectPost }},
	{http.MethodGet, "oidc-callback", http.StatusOK, func(s *Service) endpointHandler { return s.endpointOIDCCallback }},
	{http.MethodGet, "display/:session_id", http.StatusOK, func(s *Service) endpointHandler { return s.endpointCredentialDisplay }},
	{http.MethodPost, "confirm/:session_id", http.StatusOK, func(s *Service) endpointHandler { return s.endpointConfirmCredentialDisplay }},
}

// verificationRouteNames is every route name registered under /verification.
//
// The tables above are what New() registers from, so this is derived from
// the registrations rather than restating them: renaming or deleting a
// route changes this list with it, and the static-asset guard in
// verification_routes_test.go then fails if an asset still fetches the old
// name.
func verificationRouteNames() map[string]bool {
	names := map[string]bool{}
	for _, r := range append(append([]verificationRoute{}, sessionVerificationRoutes...), oidcVerificationRoutes...) {
		names[r.name()] = true
	}
	return names
}
