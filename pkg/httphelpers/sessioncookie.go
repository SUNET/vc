package httphelpers

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/SUNET/vc/pkg/model"

	"github.com/gin-contrib/sessions"
)

// SessionCookieOptions builds the user-session cookie options for a server,
// with maxAge as the cookie's lifetime in seconds.
//
// It exists so that the cookie is assembled in ONE place: the verifier and
// the apigw each built their own literal, and they had already drifted -
// only the apigw honoured trust_proxy_tls, so a verifier behind a
// TLS-terminating proxy served its session cookie without Secure.
//
// Secure follows the deployment rather than the configuration. TLS on this
// server sets it, and so does trust_proxy_tls, which is how a deployment
// says that the TLS it is reached over terminates in front of it.
func SessionCookieOptions(apiServer model.APIServer, maxAge int) (sessions.Options, error) {
	options := sessions.Options{
		Path:     "/",
		Domain:   "",
		MaxAge:   maxAge,
		Secure:   apiServer.TLS.Enable || apiServer.TrustProxyTLS,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	cookie := apiServer.SessionCookie
	if cookie == nil {
		return options, nil
	}

	options.Domain = cookie.Domain

	switch cookie.SameSite {
	case "", "lax":
		options.SameSite = http.SameSiteLaxMode
	case "strict":
		options.SameSite = http.SameSiteStrictMode
	case "none":
		options.SameSite = http.SameSiteNoneMode
	default:
		return sessions.Options{}, fmt.Errorf("session_cookie.same_site is %q, which is not one of lax, strict, none", cookie.SameSite)
	}

	// A browser drops a SameSite=None cookie that is not Secure, so the
	// configuration that asks for one is refused here rather than at every
	// request: the flow it was meant to enable would fail with no session
	// and nothing in the logs to say the cookie was never stored.
	if options.SameSite == http.SameSiteNoneMode && !options.Secure {
		return sessions.Options{}, errors.New(`session_cookie.same_site is "none", which a browser accepts only on a Secure cookie: enable api_server.tls or set api_server.trust_proxy_tls`)
	}

	return options, nil
}
