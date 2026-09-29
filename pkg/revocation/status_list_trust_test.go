package revocation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/tokenstatuslist"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

// recordingTrustVerifier stands in for the trust stack: it records what it
// was asked about and answers trusted or not.
type recordingTrustVerifier struct {
	key       *ecdsa.PublicKey
	trusted   bool
	seenURI   string
	seenToken string
	calls     int
}

func (r *recordingTrustVerifier) VerifyStatusListToken(_ context.Context, tokenString, listURI string) (*jwt.Token, error) {
	r.calls++
	r.seenURI = listURI
	r.seenToken = tokenString
	if !r.trusted {
		return nil, errors.New("status list is signed by an untrusted party: no trust anchor")
	}
	return jwt.Parse(tokenString, func(*jwt.Token) (any, error) { return r.key, nil },
		jwt.WithValidMethods([]string{"ES256"}))
}

func serveStatusList(t *testing.T) (uri string, sign func(*testing.T, *ecdsa.PrivateKey, jwt.MapClaims), serverURL func() string) {
	t.Helper()
	var token string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", tokenstatuslist.MediaTypeJWT)
		_, _ = w.Write([]byte(token))
	}))
	t.Cleanup(server.Close)

	return server.URL + "/statuslists/0",
		func(t *testing.T, key *ecdsa.PrivateKey, claims jwt.MapClaims) {
			t.Helper()
			tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
			tok.Header["typ"] = tokenstatuslist.JWTTypHeader
			signed, err := tok.SignedString(key)
			require.NoError(t, err)
			token = signed
		},
		func() string { return server.URL }
}

// TestStatusList_TrustVerifierIsTheAuthority: a status list says whether a
// credential is still valid, so "may this party say that" is the same trust
// question asked of the credential's issuer and must be answered the same
// way - through go-trust, on key material from the token's own header.
//
// A key resolver answers only "is this the key I expected to find", never
// "is this signer trusted", so it must not be what decides.
func TestStatusList_TrustVerifierIsTheAuthority(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	uri, sign, _ := serveStatusList(t)

	statuses := make([]uint8, 8)
	statuses[2] = tokenstatuslist.StatusInvalid
	sign(t, key, jwt.MapClaims{
		"sub": uri, "iat": time.Now().Unix(),
		"status_list": statusListClaim(t, statuses, 8),
	})

	tv := &recordingTrustVerifier{key: &key.PublicKey, trusted: true}
	checker, err := NewStatusListChecker(
		WithCache(cache.NewMemoryCache[[]uint8](time.Minute)),
		WithHTTPClient(http.DefaultClient),
		// A resolver that would fail: it must not be consulted.
		WithKeyResolver(failingKeyResolver{}),
		WithTokenVerifier(tv),
	)
	require.NoError(t, err)

	result, err := checker.CheckStatus(t.Context(), &Reference{Scheme: SchemeStatusList, URI: uri, Index: 2})
	require.NoError(t, err)
	require.Equal(t, StatusInvalid, result.Status)
	require.Equal(t, 1, tv.calls, "the trust verifier must be the path taken")
	require.Equal(t, uri, tv.seenURI, "the list URI travels with the token for policy scope")
}

// TestStatusList_UntrustedSignerIsRefused: a signature that verifies against
// a key in the token's own header proves only self-consistency. Anyone can
// mint a token and embed their own jwk.
func TestStatusList_UntrustedSignerIsRefused(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	uri, sign, _ := serveStatusList(t)

	sign(t, key, jwt.MapClaims{
		"sub": uri, "iat": time.Now().Unix(),
		"status_list": statusListClaim(t, []uint8{0, 0, 0}, 8),
	})

	tv := &recordingTrustVerifier{key: &key.PublicKey, trusted: false}
	checker, err := NewStatusListChecker(
		WithCache(cache.NewMemoryCache[[]uint8](time.Minute)),
		WithHTTPClient(http.DefaultClient),
		WithKeyResolver(testKeyResolver{key: &key.PublicKey}),
		WithTokenVerifier(tv),
	)
	require.NoError(t, err)

	_, err = checker.CheckStatus(t.Context(), &Reference{Scheme: SchemeStatusList, URI: uri, Index: 1})
	require.Error(t, err, "an untrusted signer must be refused even though the signature verifies")
	require.Contains(t, err.Error(), "untrusted")
}

// TestStatusList_TrustPathStillChecksTypAndSub: the trust verifier answers
// "is this signer trusted", not "is this a status list for this URI". The
// spec checks must still run, or the trust path would be a way around them.
func TestStatusList_TrustPathStillChecksTypAndSub(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	uri, _, serverURL := serveStatusList(t)

	tv := &recordingTrustVerifier{key: &key.PublicKey, trusted: true}
	checker, err := NewStatusListChecker(
		WithCache(cache.NewMemoryCache[[]uint8](time.Minute)),
		WithHTTPClient(http.DefaultClient),
		WithTokenVerifier(tv),
	)
	require.NoError(t, err)

	// sub names a different list.
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub": serverURL() + "/statuslists/999", "iat": time.Now().Unix(),
		"status_list": statusListClaim(t, []uint8{0, 0, 0}, 8),
	})
	tok.Header["typ"] = tokenstatuslist.JWTTypHeader
	signed, err := tok.SignedString(key)
	require.NoError(t, err)
	tv.key = &key.PublicKey

	// Serve that token.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", tokenstatuslist.MediaTypeJWT)
		_, _ = w.Write([]byte(signed))
	}))
	t.Cleanup(server.Close)

	_, err = checker.CheckStatus(t.Context(), &Reference{
		Scheme: SchemeStatusList, URI: server.URL + "/statuslists/0", Index: 1,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not match the requested status list URI")
	_ = uri
}
