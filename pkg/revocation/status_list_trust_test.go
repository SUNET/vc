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
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/testsupport/jwktest"
	"github.com/SUNET/vc/pkg/tokenstatuslist"

	"github.com/fxamacker/cbor/v2"
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

func (r *recordingTrustVerifier) VerifyStatusListToken(_ context.Context, tokenString, listURI, fallbackIssuer string) (*jwt.Token, error) {
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
			// A real trust-path token names its own key - that is what the
			// trust verifier resolves and evaluates. Without one the
			// checker has nothing to send to the PDP and takes the
			// pinned-key path instead; see jwtHeaderNamesAKey.
			tok.Header["jwk"] = jwktest.PublicKeyJWK(&key.PublicKey)
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
	tok.Header["jwk"] = jwktest.PublicKeyJWK(&key.PublicKey)
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

// signStatusListJWT mints a status list token, optionally naming its own
// key in the header. Whether it does is exactly what routes it to the trust
// verifier or to the operator's configured key.
func signStatusListJWT(t *testing.T, key *ecdsa.PrivateKey, uri, issuer string, nameKey bool, statuses []uint8) string {
	t.Helper()
	claims := jwt.MapClaims{
		"sub": uri, "iat": time.Now().Unix(),
		"status_list": statusListClaim(t, statuses, 8),
	}
	if issuer != "" {
		claims["iss"] = issuer
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = tokenstatuslist.JWTTypHeader
	if nameKey {
		tok.Header["jwk"] = jwktest.PublicKeyJWK(&key.PublicKey)
	}
	signed, err := tok.SignedString(key)
	require.NoError(t, err)
	return signed
}

func serveToken(t *testing.T, mediaType string, body *[]byte) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", mediaType)
		_, _ = w.Write(*body)
	}))
	t.Cleanup(server.Close)
	return server
}

// TestStatusList_PinnedKeyVerifiesTokenTheTrustPathCannotJudge: a status
// service that publishes no key material in its tokens - siros-status-service
// is one - gives JWTTrustVerifier nothing to resolve or evaluate. Sending
// such a token down the trust path anyway made status_list_key_file
// unreachable, so every list failed to verify, and fail_open then accepted
// revoked credentials.
func TestStatusList_PinnedKeyVerifiesTokenTheTrustPathCannotJudge(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var body []byte
	server := serveToken(t, tokenstatuslist.MediaTypeJWT, &body)
	uri := server.URL + "/statuslists/0"

	statuses := make([]uint8, 8)
	statuses[2] = tokenstatuslist.StatusInvalid
	body = []byte(signStatusListJWT(t, key, uri, "", false, statuses))

	tv := &recordingTrustVerifier{key: &key.PublicKey, trusted: true}
	checker, err := NewStatusListChecker(
		WithCache(cache.NewMemoryCache[[]uint8](time.Minute)),
		WithHTTPClient(http.DefaultClient),
		WithTokenVerifier(tv),
		WithStatusListKey(&key.PublicKey),
	)
	require.NoError(t, err)

	result, err := checker.CheckStatus(t.Context(), &Reference{Scheme: SchemeStatusList, URI: uri, Index: 2})
	require.NoError(t, err, "the pinned key must verify a token the PDP cannot judge")
	require.Equal(t, StatusInvalid, result.Status)
	require.Zero(t, tv.calls, "a token naming no key has nothing to send to the PDP")
}

// TestStatusList_NoKeyMaterialAndNoPinIsRefused keeps that fail-closed: a
// token the PDP cannot judge and no operator statement about its key is not
// a token to believe.
func TestStatusList_NoKeyMaterialAndNoPinIsRefused(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var body []byte
	server := serveToken(t, tokenstatuslist.MediaTypeJWT, &body)
	uri := server.URL + "/statuslists/0"
	body = []byte(signStatusListJWT(t, key, uri, "", false, make([]uint8, 8)))

	tv := &recordingTrustVerifier{key: &key.PublicKey, trusted: true}
	checker, err := NewStatusListChecker(
		WithCache(cache.NewMemoryCache[[]uint8](time.Minute)),
		WithHTTPClient(http.DefaultClient),
		// A resolver that WOULD answer. It must not be reached: reaching it
		// is how a token skips the PDP just by omitting its header.
		WithKeyResolver(testKeyResolver{key: &key.PublicKey}),
		WithTokenVerifier(tv),
	)
	require.NoError(t, err)

	_, err = checker.CheckStatus(t.Context(), &Reference{Scheme: SchemeStatusList, URI: uri, Index: 1})
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot be trust-evaluated")
}

// TestStatusList_TokenOutsidePinScopeIsRefused: the pin is scoped to the
// configured status_list_issuer, so a token from anyone else is not covered
// by it - and with a trust verifier configured it must not fall through to
// the generic resolver either.
func TestStatusList_TokenOutsidePinScopeIsRefused(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var body []byte
	server := serveToken(t, tokenstatuslist.MediaTypeJWT, &body)
	uri := server.URL + "/statuslists/0"
	body = []byte(signStatusListJWT(t, key, uri, "https://someone.else.example.com", false, make([]uint8, 8)))

	tv := &recordingTrustVerifier{key: &key.PublicKey, trusted: true}
	checker, err := NewStatusListChecker(
		WithCache(cache.NewMemoryCache[[]uint8](time.Minute)),
		WithHTTPClient(http.DefaultClient),
		WithKeyResolver(testKeyResolver{key: &key.PublicKey}),
		WithTokenVerifier(tv),
		WithStatusListKey(&key.PublicKey),
		WithFallbackIssuer("https://status.example.com"),
	)
	require.NoError(t, err)

	_, err = checker.CheckStatus(t.Context(), &Reference{Scheme: SchemeStatusList, URI: uri, Index: 1})
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not apply to it")
}

// TestStatusList_CWTCannotSkipThePDP: JWTTrustVerifier works on JWTs, so a
// CWT served by the same party reaches a status value with no policy
// decision at all. With a trust verifier configured, only an
// operator-pinned key verifies one.
//
// The CWT here is genuinely signed and genuinely parseable, and the key
// resolver WOULD hand back the key that signed it - so the only thing that
// can refuse it is the rule under test.
func TestStatusList_CWTCannotSkipThePDP(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var body []byte
	server := serveToken(t, tokenstatuslist.MediaTypeCWT, &body)
	uri := server.URL + "/statuslists/0"

	statuses := make([]uint8, 16)
	statuses[3] = tokenstatuslist.StatusInvalid
	body = signedStatusListCWT(t, key, uri, statuses)

	// Sanity: without a trust verifier the very same bytes verify and
	// report the status, so anything the next two checks refuse is refused
	// by the rule, not by a malformed token.
	plain, err := NewStatusListChecker(
		WithCache(cache.NewMemoryCache[[]uint8](time.Minute)),
		WithHTTPClient(http.DefaultClient),
		WithKeyResolver(testKeyResolver{key: &key.PublicKey}),
	)
	require.NoError(t, err)
	result, err := plain.CheckStatus(t.Context(), &Reference{Scheme: SchemeStatusList, URI: uri, Index: 3})
	require.NoError(t, err)
	require.Equal(t, StatusInvalid, result.Status)

	tv := &recordingTrustVerifier{key: &key.PublicKey, trusted: true}
	guarded, err := NewStatusListChecker(
		WithCache(cache.NewMemoryCache[[]uint8](time.Minute)),
		WithHTTPClient(http.DefaultClient),
		WithKeyResolver(testKeyResolver{key: &key.PublicKey}),
		WithTokenVerifier(tv),
	)
	require.NoError(t, err)

	_, err = guarded.CheckStatus(t.Context(), &Reference{Scheme: SchemeStatusList, URI: uri, Index: 3})
	require.Error(t, err, "a CWT must not reach a status value without a policy decision")
	require.Contains(t, err.Error(), "cannot be trust-evaluated")

	// Pinning the key is the operator standing in for the decision the PDP
	// cannot make, and it is the supported way to run CWT lists under a
	// trust framework.
	pinned, err := NewStatusListChecker(
		WithCache(cache.NewMemoryCache[[]uint8](time.Minute)),
		WithHTTPClient(http.DefaultClient),
		WithTokenVerifier(tv),
		WithStatusListKey(&key.PublicKey),
		WithFallbackIssuer(cwtTestIssuer),
	)
	require.NoError(t, err)
	result, err = pinned.CheckStatus(t.Context(), &Reference{Scheme: SchemeStatusList, URI: uri, Index: 3})
	require.NoError(t, err)
	require.Equal(t, StatusInvalid, result.Status)
}

const cwtTestIssuer = "https://status.example.com"

// signedStatusListCWT mints a valid, signed status list CWT in the draft's
// layout.
func signedStatusListCWT(t *testing.T, key *ecdsa.PrivateKey, uri string, statuses []uint8) []byte {
	t.Helper()

	compressed, err := tokenstatuslist.CompressStatuses(statuses)
	require.NoError(t, err)

	encoder, err := mdoc.NewCBOREncoder()
	require.NoError(t, err)

	payload, err := encoder.Marshal(map[int]any{
		1: cwtTestIssuer,
		2: uri,
		6: time.Now().Unix(),
		tokenstatuslist.CWTClaimStatusList: map[string]any{
			"bits": 8, "lst": compressed,
		},
	})
	require.NoError(t, err)

	protectedBytes, err := encoder.Marshal(map[int64]any{
		int64(1): int64(-7), int64(16): tokenstatuslist.CWTTypHeader,
	})
	require.NoError(t, err)

	sign1, err := signCWTWithProtected(t, protectedBytes, payload, key)
	require.NoError(t, err)

	token, err := encoder.Marshal(cbor.Tag{Number: 18, Content: []any{
		sign1.Protected, map[any]any{}, sign1.Payload, sign1.Signature,
	}})
	require.NoError(t, err)
	return token
}

// TestJWTHeaderNamesAKey pins the routing predicate itself.
func TestJWTHeaderNamesAKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	require.True(t, jwtHeaderNamesAKey(signStatusListJWT(t, key, "u", "", true, make([]uint8, 8))))
	require.False(t, jwtHeaderNamesAKey(signStatusListJWT(t, key, "u", "", false, make([]uint8, 8))))

	for _, header := range []string{"x5c", "kid"} {
		tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"sub": "u"})
		tok.Header[header] = "anything"
		signed, signErr := tok.SignedString(key)
		require.NoError(t, signErr)
		require.True(t, jwtHeaderNamesAKey(signed), header+" names a key to resolve")
	}

	require.False(t, jwtHeaderNamesAKey("not-a-jwt"))
	require.False(t, jwtHeaderNamesAKey("!!!.x.y"))
}

// TestStatusList_PinnedKeyOutranksTokenCarriedKey: status_list_key_file is
// an operator statement about WHICH key signs these lists. The trust path
// verifies against whatever key the token carries, so a status service that
// rotated its signing key - or anyone who minted a token with their own jwk
// - was accepted while the operator believed the pin was enforcing
// something.
func TestStatusList_PinnedKeyOutranksTokenCarriedKey(t *testing.T) {
	pinned, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rotated, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var body []byte
	server := serveToken(t, tokenstatuslist.MediaTypeJWT, &body)
	uri := server.URL + "/statuslists/0"

	statuses := make([]uint8, 8)
	statuses[2] = tokenstatuslist.StatusInvalid

	// An evaluator that trusts everything - the permissive default - so the
	// only thing that can refuse the rotated key is the pin.
	tv := &recordingTrustVerifier{trusted: true}

	newChecker := func(t *testing.T) *StatusListChecker {
		t.Helper()
		checker, cErr := NewStatusListChecker(
			WithCache(cache.NewMemoryCache[[]uint8](time.Minute)),
			WithHTTPClient(http.DefaultClient),
			WithTokenVerifier(tv),
			WithStatusListKey(&pinned.PublicKey),
		)
		require.NoError(t, cErr)
		return checker
	}

	// The pinned key signs, and names itself in the header. Accepted, and
	// the trust path is not what decided it.
	body = []byte(signStatusListJWT(t, pinned, uri, "", true, statuses))
	tv.key = &pinned.PublicKey
	before := tv.calls
	result, err := newChecker(t).CheckStatus(t.Context(), &Reference{Scheme: SchemeStatusList, URI: uri, Index: 2})
	require.NoError(t, err)
	require.Equal(t, StatusInvalid, result.Status)
	require.Equal(t, before, tv.calls, "a pinned list is verified against the pin, not the token's own key")

	// A different key signs and embeds ITSELF, which is exactly what the
	// trust path would happily verify. The pin must refuse it.
	body = []byte(signStatusListJWT(t, rotated, uri, "", true, statuses))
	tv.key = &rotated.PublicKey
	_, err = newChecker(t).CheckStatus(t.Context(), &Reference{Scheme: SchemeStatusList, URI: uri, Index: 2})
	require.Error(t, err, "a key the operator did not pin must not be accepted just because the token carries it")
}

// TestStatusList_RegistryShapedTokenVerifiesWithoutATrustVerifier is the
// deployment the PDP condition in internal/verifier/apiv1 protects.
//
// vc's own registry issues status list tokens with no kid, jwk or x5c
// (internal/registry/tokenstatuslistissuer). With a trust verifier
// configured those verify against a pinned key or not at all, which is
// right when there is a policy to consult - and fatal when there is not,
// because a default registry-only deployment has no pinned key and would
// stop verifying its own lists. fail_open then reads that as "not revoked".
//
// Without a trust verifier the ordinary key resolver answers, as it always
// did.
func TestStatusList_RegistryShapedTokenVerifiesWithoutATrustVerifier(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var body []byte
	server := serveToken(t, tokenstatuslist.MediaTypeJWT, &body)
	uri := server.URL + "/statuslists/0"

	statuses := make([]uint8, 8)
	statuses[2] = tokenstatuslist.StatusInvalid
	// nameKey false: exactly the registry's shape - an iss, and nothing in
	// the header to resolve a key from.
	body = []byte(signStatusListJWT(t, key, uri, "https://registry.example.com", false, statuses))

	checker, err := NewStatusListChecker(
		WithCache(cache.NewMemoryCache[[]uint8](time.Minute)),
		WithHTTPClient(http.DefaultClient),
		WithKeyResolver(testKeyResolver{key: &key.PublicKey}),
	)
	require.NoError(t, err)

	result, err := checker.CheckStatus(t.Context(), &Reference{Scheme: SchemeStatusList, URI: uri, Index: 2})
	require.NoError(t, err, "a registry-issued list must verify in a deployment with no PDP")
	require.Equal(t, StatusInvalid, result.Status)

	// And with a trust verifier it is refused rather than silently accepted,
	// which is why installing one without a PDP would be the bug.
	tv := &recordingTrustVerifier{key: &key.PublicKey, trusted: true}
	guarded, err := NewStatusListChecker(
		WithCache(cache.NewMemoryCache[[]uint8](time.Minute)),
		WithHTTPClient(http.DefaultClient),
		WithKeyResolver(testKeyResolver{key: &key.PublicKey}),
		WithTokenVerifier(tv),
	)
	require.NoError(t, err)
	_, err = guarded.CheckStatus(t.Context(), &Reference{Scheme: SchemeStatusList, URI: uri, Index: 2})
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot be trust-evaluated")
}
