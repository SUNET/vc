package middleware

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
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
	serverWideMatch := newServerWideMatcher(serverWideOrigins)

	var serverWideHandler gin.HandlerFunc
	if len(serverWideOrigins) > 0 {
		var err error
		serverWideHandler, err = newCORSHandler(cors.Config{
			AllowOrigins:     serverWideOrigins,
			AllowMethods:     []string{http.MethodGet, http.MethodPost, http.MethodOptions},
			AllowHeaders:     []string{"Content-Type", "Authorization", "DPoP"},
			AllowCredentials: true,
			MaxAge:           12 * time.Hour,
		}, "api_server.cors.allowed_origins")
		if err != nil {
			return nil, err
		}
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
		var err error
		embeddedHandler, err = newCORSHandler(cors.Config{
			AllowOrigins:     embedded.AllowedOrigins,
			AllowMethods:     []string{http.MethodGet, http.MethodPost, http.MethodOptions},
			AllowHeaders:     []string{"Content-Type"},
			AllowCredentials: false,
			MaxAge:           12 * time.Hour,
		}, "verifier.embedded_presentation.allowed_origins")
		if err != nil {
			return nil, err
		}
	}

	if serverWideHandler == nil && embeddedHandler == nil {
		return nil, nil
	}

	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		if embeddedHandler != nil &&
			EmbeddedPresentationPaths[c.Request.URL.Path] &&
			!serverWideMatch.allows(origin) {
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

// newCORSHandler builds one gin-contrib/cors handler, asking the library to
// check the configuration before it is handed over.
//
// cors.New panics on a configuration its own Validate rejects - an origin
// with no scheme, say - so without this the verifier answers a typo in an
// operator's allowed_origins with a stack trace at startup. Validate is the
// library's own, so the check cannot disagree with what New would have done.
func newCORSHandler(cfg cors.Config, key string) (gin.HandlerFunc, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", key, err)
	}

	// Validate does not cover a malformed regular expression, and cannot be
	// made to: it skips its own scheme check for any entry containing "*",
	// which every useful pattern does. The library then compiles the pattern
	// with MustCompile on each cross-origin request, so an entry like
	// "/.*[/" starts the verifier and panics the first time a browser asks -
	// taking down the flow it was configured to serve. Compile it here
	// instead, once, where the answer is a startup error naming the entry.
	for _, origin := range newServerWideMatcher(cfg.AllowOrigins).origins {
		match := serverWideOriginRegex.FindStringSubmatch(origin)
		if match == nil {
			continue
		}
		if _, err := regexp.Compile(match[1]); err != nil {
			return nil, fmt.Errorf("%s: %q is not a usable regular expression: %w", key, origin, err)
		}
	}

	return cors.New(cfg), nil
}

// serverWideOriginRegex is gin-contrib/cors's own test for "this list entry
// is a regular expression, not a literal origin" (its originRegex).
var serverWideOriginRegex = regexp.MustCompile(`^/(.+)/[gimuy]?$`)

// serverWideMatcher answers "does api_server.cors cover this origin?" exactly
// as gin-contrib/cors's own validateOrigin would, since the point of asking
// is to hand the origin to the handler that will accept it. Get it wrong in
// either direction and a request is routed to a policy that refuses it.
//
// TestAllowedServerWideAgreesWithTheCORSLibrary is a differential test
// against the library itself, so the two cannot drift.
type serverWideMatcher struct {
	// allowAll mirrors the library's AllowAllOrigins, which newCors sets
	// from the RAW list and only for an entry that is exactly "*".
	allowAll bool
	// origins is the list as validateOrigin reads it: trimmed and
	// lowercased by the library's normalize().
	origins []string
}

// newServerWideMatcher prepares api_server.cors's list once, rather than per
// request.
//
// The two passes are not the same pass, and that is the point: " * " is a
// valid entry (Validate skips its scheme check for anything containing "*"),
// but it is not the raw "*" that turns on AllowAllOrigins, so the library
// normalizes it to "*" and then compares it literally against each Origin -
// which no browser ever sends - refusing every cross-origin request. Reading
// it as a wildcard here would route every origin to that handler, including
// the embedded ones, and they would be refused with it.
func newServerWideMatcher(origins []string) serverWideMatcher {
	matcher := serverWideMatcher{origins: make([]string, 0, len(origins))}
	for _, origin := range origins {
		if origin == "*" {
			matcher.allowAll = true
		}
		matcher.origins = append(matcher.origins, strings.ToLower(strings.TrimSpace(origin)))
	}

	return matcher
}

// allows reads the list the same three ways the library does: AllowAllOrigins
// stands for every origin, a /…/ entry is a regular expression matched
// against the origin, and any other entry is compared literally - the ENTRY
// as normalized against the origin as sent.
func (m serverWideMatcher) allows(origin string) bool {
	if origin == "" {
		return false
	}
	if m.allowAll {
		return true
	}

	for _, value := range m.origins {
		if match := serverWideOriginRegex.FindStringSubmatch(value); match != nil {
			// Compile, not MustCompile: a pattern that will not compile is
			// refused at startup by newCORSHandler, and a selector that
			// panicked here would only move that crash.
			if re, err := regexp.Compile(match[1]); err == nil && re.MatchString(origin) {
				return true
			}

			continue
		}

		if value == origin {
			return true
		}
	}

	return false
}
