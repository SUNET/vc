package middleware

import (
	"errors"
	"net/http"
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

// EmbeddedPresentationCORS answers cross-origin requests for the endpoints in
// EmbeddedPresentationPaths, and only those: every other route on this server
// is left exactly as it was, including the ones api_server.cors would also
// have opened.
//
// Returns an error when enabled with no origin, rather than installing a
// handler that allows nothing. Such a configuration reads as though the
// feature were on while every preflight still fails, and the operator finds
// out from a browser console instead of from startup.
func EmbeddedPresentationCORS(cfg *model.EmbeddedPresentationConfig) (gin.HandlerFunc, error) {
	if !cfg.Enabled() {
		return nil, nil
	}
	if len(cfg.AllowedOrigins) == 0 {
		return nil, errors.New("verifier.embedded_presentation.enable is set with no allowed_origins: list the relying party's origin, or remove the stanza")
	}

	// AllowCredentials stays off: nothing in this flow is cookie-backed.
	// /ui/interaction returns the session id in its reply and the other
	// three take it on the query string, so the browser has no reason to
	// send verifier_user_session - and an embedded page that cannot send it
	// cannot be made to spend another visitor's session either.
	handler := cors.New(cors.Config{
		AllowOrigins:     cfg.AllowedOrigins,
		AllowMethods:     []string{http.MethodGet, http.MethodPost, http.MethodOptions},
		AllowHeaders:     []string{"Content-Type"},
		AllowCredentials: false,
		MaxAge:           12 * time.Hour,
	})

	return func(c *gin.Context) {
		if !EmbeddedPresentationPaths[c.Request.URL.Path] {
			c.Next()
			return
		}
		handler(c)
	}, nil
}
