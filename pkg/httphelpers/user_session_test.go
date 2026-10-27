package httphelpers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-contrib/sessions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testAuthKey = "0123456789abcdef0123456789abcdef"
	testEncKey  = "fedcba9876543210fedcba9876543210"
)

// issueSessionCookie saves a session through the store and returns the
// cookie the browser would get.
func issueSessionCookie(t *testing.T, store sessions.Store, name string) *http.Cookie {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	session, err := store.New(req, name)
	require.NoError(t, err)
	session.Values["who"] = "someone"
	require.NoError(t, store.Save(req, rec, session))

	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	return cookies[0]
}

// The session's lifetime has to bound how long an encoded cookie stays
// DECODABLE, not only the Max-Age sent to the browser.
//
// gin-contrib's cookie.Store.Options assigns CookieStore.Options and
// nothing else; gorilla clamps the securecookie codecs separately, through
// CookieStore.MaxAge. So the Set-Cookie header followed the configuration
// while the server went on accepting a copied cookie for gorilla's 30-day
// default, whatever session_duration said (SUNET/vc#756).
//
// A negative age is the probe. securecookie reads every timestamp as too
// old under one, so a cookie encoded a moment ago is refused IF the codecs
// were clamped, and accepted if they were not - no waiting, and the
// timestamp hook is unexported.
func TestSessionCookieDecodeLifetimeFollowsTheConfiguredAge(t *testing.T) {
	const name = "test_session"

	t.Run("a lapsed age refuses a fresh cookie", func(t *testing.T) {
		store := newCookieStore(testAuthKey, testEncKey, sessions.Options{Path: "/", MaxAge: -1})
		cookie := issueSessionCookie(t, store, name)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(cookie)

		// Gorilla hands back a fresh session AND the decode error.
		session, err := store.Get(req, name)
		require.NotNil(t, session)
		assert.Error(t, err, "the cookie decoded cleanly past its age")
		assert.True(t, session.IsNew,
			"the cookie was still decodable - the securecookie codecs never got the age")
		assert.Empty(t, session.Values["who"])
	})

	t.Run("a live age accepts it", func(t *testing.T) {
		store := newCookieStore(testAuthKey, testEncKey, sessions.Options{Path: "/", MaxAge: 3600})
		cookie := issueSessionCookie(t, store, name)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.AddCookie(cookie)

		session, err := store.Get(req, name)
		require.NoError(t, err)
		assert.False(t, session.IsNew, "a cookie inside its lifetime must still decode")
		assert.Equal(t, "someone", session.Values["who"])
	})
}

// The cookie attributes still reach the browser.
func TestSessionCookieKeepsItsAttributes(t *testing.T) {
	store := newCookieStore(testAuthKey, testEncKey, sessions.Options{
		Path:     "/",
		MaxAge:   7200,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	cookie := issueSessionCookie(t, store, "test_session")

	assert.Equal(t, "/", cookie.Path)
	assert.Equal(t, 7200, cookie.MaxAge)
	assert.True(t, cookie.HttpOnly)
	assert.True(t, cookie.Secure)
	assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
}
