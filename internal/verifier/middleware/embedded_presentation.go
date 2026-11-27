package middleware

import (
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/SUNET/vc/pkg/model"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

// EmbeddedPresentationPaths are the endpoints a relying party's own page
// calls to drive the standalone DCQL presentation flow, and the only ones
// verifier.embedded_presentation opens to another origin.
//
// All four or none: a page that may start a presentation but may not learn
// how it ended has nothing to render, and one that may read a result it was
// never allowed to start cannot reach a response_code to read. The set is
// the flow documented in docs/verifier/EMBEDDING.md.
//
// Deliberately absent:
//   - /ui/resume, which exists for the Digital Credentials API. That flow is
//     bound to verifier.public_url through the request's signed
//     expected_origins, so it cannot work from another origin whatever CORS
//     says.
//   - /ui/metadata, which publishes the deployment's credential catalogue and
//     presets. An embedded page builds its own DCQL rather than driving the
//     verifier's picker, so opening it would widen what is readable without
//     making the flow work.
var EmbeddedPresentationPaths = map[string]bool{
	"/ui/interaction": true,
	"/ui/notify":      true,
	"/ui/completion":  true,
	"/ui/result":      true,
}

// VerifierCORS answers cross-origin requests under both of the verifier's
// CORS keys: api_server.cors, which applies to every route this server has,
// and verifier.embedded_presentation, which opens the standalone
// presentation flow's four endpoints and nothing else.
//
// ONE handler, because exactly one policy may run per request. Installing
// the two as separate middleware does not compose: gin-contrib/cors answers
// an origin outside its own list with 403 and aborts, so whichever ran first
// refused the other's origins. With both keys set and disjoint lists, that
// left neither working - the server-wide origin lost the four paths it used
// to reach, and the embedded origin never got past the server-wide handler.
//
// Which policy applies:
//   - an origin api_server.cors lists keeps that policy everywhere,
//     including on the four paths, so configuring embedded_presentation
//     takes nothing away from a deployment that already had access;
//   - any other origin gets the embedded policy, but only on the four paths;
//   - everything else is the server-wide policy, or no CORS at all when
//     api_server.cors is unset.
//
// Returns nil when neither key is configured, and an error when
// embedded_presentation is enabled with no origin - installing a handler
// that allows nothing would read as though the feature were on while every
// preflight still failed, and the operator would find out from a browser
// console instead of from startup.
func VerifierCORS(serverWide *model.CORS, embedded *model.EmbeddedPresentationConfig) (gin.HandlerFunc, error) {
	var serverWideOrigins []string
	if serverWide != nil {
		serverWideOrigins = serverWide.AllowedOrigins
	}

	var serverWideHandler gin.HandlerFunc
	if len(serverWideOrigins) > 0 {
		serverWideHandler = cors.New(cors.Config{
			AllowOrigins:     serverWideOrigins,
			AllowMethods:     []string{http.MethodGet, http.MethodPost, http.MethodOptions},
			AllowHeaders:     []string{"Content-Type", "Authorization", "DPoP"},
			AllowCredentials: true,
			MaxAge:           12 * time.Hour,
		})
	}

	var embeddedHandler gin.HandlerFunc
	if embedded.Enabled() {
		if len(embedded.AllowedOrigins) == 0 {
			return nil, errors.New("verifier.embedded_presentation.enable is set with no allowed_origins: list the relying party's origin, or remove the stanza")
		}
		// AllowCredentials stays off: nothing in this flow is cookie-backed.
		// /ui/interaction returns the session id in its reply and the other
		// three take it on the query string, so the browser has no reason to
		// send verifier_user_session - and an embedded page that cannot send
		// it cannot be made to spend another visitor's session either.
		embeddedHandler = cors.New(cors.Config{
			AllowOrigins:     embedded.AllowedOrigins,
			AllowMethods:     []string{http.MethodGet, http.MethodPost, http.MethodOptions},
			AllowHeaders:     []string{"Content-Type"},
			AllowCredentials: false,
			MaxAge:           12 * time.Hour,
		})
	}

	if serverWideHandler == nil && embeddedHandler == nil {
		return nil, nil
	}

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		if embeddedHandler != nil &&
			EmbeddedPresentationPaths[c.Request.URL.Path] &&
			!allowedServerWide(serverWideOrigins, origin) {
			embeddedHandler(c)
			return
		}
		if serverWideHandler != nil {
			serverWideHandler(c)
			return
		}
		c.Next()
	}, nil
}

// allowedServerWide reports whether api_server.cors covers this origin, the
// way gin-contrib/cors reads its own list: an exact match, or the "*" entry
// that stands for every origin.
func allowedServerWide(origins []string, origin string) bool {
	if origin == "" {
		return false
	}

	return slices.Contains(origins, "*") || slices.Contains(origins, origin)
}
