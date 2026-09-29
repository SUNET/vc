package revocation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/tokenstatuslist"

	"github.com/SUNET/vc/pkg/vc20/contextstore"
	"github.com/fxamacker/cbor/v2"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

// statusListFixture serves one status list token from a test server and
// hands back a checker wired to it. The token is minted by the caller from
// the server's own URL, because sub must equal the URI it is served from.
type statusListFixture struct {
	server  *httptest.Server
	key     *ecdsa.PrivateKey
	checker *StatusListChecker
	token   *string
}

func newStatusListFixture(t *testing.T) *statusListFixture {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var token string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", tokenstatuslist.MediaTypeJWT)
		_, _ = w.Write([]byte(token))
	}))
	t.Cleanup(server.Close)

	checker, err := NewStatusListChecker(
		WithCache(cache.NewMemoryCache[[]uint8](5*time.Minute)),
		WithHTTPClient(server.Client()),
		WithKeyResolver(testKeyResolver{key: &key.PublicKey}),
		// These fixtures mint tokens without iss, which is what a
		// conforming status service does, so the deployment has to name the
		// issuer identity to resolve the signing key under.
		WithFallbackIssuer("https://status.example.com"),
	)
	require.NoError(t, err)

	return &statusListFixture{server: server, key: key, checker: checker, token: &token}
}

func (f *statusListFixture) uri() string { return f.server.URL + "/statuslists/0" }

// sign mints a Status List Token with the given claims and typ header.
func (f *statusListFixture) sign(t *testing.T, typ string, claims jwt.MapClaims) {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = typ
	signed, err := tok.SignedString(f.key)
	require.NoError(t, err)
	*f.token = signed
}

func statusListClaim(t *testing.T, statuses []uint8, bits int) map[string]any {
	t.Helper()
	sl := tokenstatuslist.New(statuses)
	sl.Bits = bits
	lst, err := sl.CompressAndEncode()
	require.NoError(t, err)
	return map[string]any{"bits": bits, "lst": lst}
}

// TestStatusListToken_SubMustMatchRequestedURI is the security case: without
// the sub check, a token the same issuer signed for a DIFFERENT list is
// accepted for this one. Here the other list reads index 1 as VALID while
// the real list has it INVALID, so the credential would verify.
func TestStatusListToken_SubMustMatchRequestedURI(t *testing.T) {
	f := newStatusListFixture(t)

	// A perfectly valid token - for someone else's list.
	f.sign(t, tokenstatuslist.JWTTypHeader, jwt.MapClaims{
		"sub":         f.server.URL + "/statuslists/999",
		"iat":         time.Now().Unix(),
		"status_list": statusListClaim(t, []uint8{0, 0, 0}, 8),
	})

	_, err := f.checker.CheckStatus(t.Context(), &Reference{
		Scheme: SchemeStatusList, URI: f.uri(), Index: 1,
	})
	require.Error(t, err, "a status list token minted for another URI must be refused")
	require.Contains(t, err.Error(), "does not match the requested status list URI")
}

func TestStatusListToken_MissingSubIsRefused(t *testing.T) {
	f := newStatusListFixture(t)
	f.sign(t, tokenstatuslist.JWTTypHeader, jwt.MapClaims{
		"iat":         time.Now().Unix(),
		"status_list": statusListClaim(t, []uint8{0, 0, 0}, 8),
	})

	_, err := f.checker.CheckStatus(t.Context(), &Reference{
		Scheme: SchemeStatusList, URI: f.uri(), Index: 1,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "no sub claim")
}

// TestStatusListToken_TypHeaderIsEnforced: Section 5.1 makes typ mandatory.
// Without the check, any JWT the issuer signs - an access token, an
// attestation - can be replayed as a status list.
func TestStatusListToken_TypHeaderIsEnforced(t *testing.T) {
	f := newStatusListFixture(t)
	f.sign(t, "JWT", jwt.MapClaims{
		"sub":         f.uri(),
		"iat":         time.Now().Unix(),
		"status_list": statusListClaim(t, []uint8{0, 0, 0}, 8),
	})

	_, err := f.checker.CheckStatus(t.Context(), &Reference{
		Scheme: SchemeStatusList, URI: f.uri(), Index: 1,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "expected \"statuslist+jwt\"")
}

// TestStatusListToken_IssIsOptional: Section 5.1's REQUIRED claims are sub,
// iat and status_list. vc used to refuse any token without iss, which
// rejects conformant status services. With status_list_issuer configured
// (the fixture sets it), such a token is accepted.
func TestStatusListToken_IssIsOptional(t *testing.T) {
	f := newStatusListFixture(t)
	f.sign(t, tokenstatuslist.JWTTypHeader, jwt.MapClaims{
		"sub":         f.uri(),
		"iat":         time.Now().Unix(),
		"status_list": statusListClaim(t, []uint8{0, tokenstatuslist.StatusInvalid, 0}, 8),
	})

	result, err := f.checker.CheckStatus(t.Context(), &Reference{
		Scheme: SchemeStatusList, URI: f.uri(), Index: 1,
	})
	require.NoError(t, err, "a status list token without iss is spec-compliant and must be accepted")
	require.Equal(t, StatusInvalid, result.Status)
}

// TestStatusListToken_BitsHonoured: a narrow list read at 8 bits returns a
// different credential's status. 128 entries at bits=1 is 16 bytes, so
// index 5 is in range either way - the wrong reading is silent.
func TestStatusListToken_BitsHonoured(t *testing.T) {
	f := newStatusListFixture(t)

	statuses := make([]uint8, 128)
	statuses[5] = tokenstatuslist.StatusInvalid

	f.sign(t, tokenstatuslist.JWTTypHeader, jwt.MapClaims{
		"sub":         f.uri(),
		"iat":         time.Now().Unix(),
		"status_list": statusListClaim(t, statuses, 1),
	})

	result, err := f.checker.CheckStatus(t.Context(), &Reference{
		Scheme: SchemeStatusList, URI: f.uri(), Index: 5,
	})
	require.NoError(t, err)
	require.Equal(t, StatusInvalid, result.Status, "index 5 of a bits=1 list is INVALID; reading it at 8 bits reports VALID")
}

// TestStatusListToken_MissingBitsIsRefused: bits is REQUIRED. Defaulting it
// would silently pick a layout the issuer did not use.
func TestStatusListToken_MissingBitsIsRefused(t *testing.T) {
	f := newStatusListFixture(t)

	sl := tokenstatuslist.New([]uint8{0, 1, 2})
	lst, err := sl.CompressAndEncode()
	require.NoError(t, err)

	f.sign(t, tokenstatuslist.JWTTypHeader, jwt.MapClaims{
		"sub":         f.uri(),
		"iat":         time.Now().Unix(),
		"status_list": map[string]any{"lst": lst},
	})

	_, err = f.checker.CheckStatus(t.Context(), &Reference{
		Scheme: SchemeStatusList, URI: f.uri(), Index: 1,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing the required bits member")
}

// TestStatusListToken_ContentTypeWithParameters: a server that answers
// "application/statuslist+jwt; charset=utf-8" must not fall through to the
// sniffing branch.
func TestStatusListToken_ContentTypeWithParameters(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var token string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", tokenstatuslist.MediaTypeJWT+"; charset=utf-8")
		_, _ = w.Write([]byte(token))
	}))
	t.Cleanup(server.Close)

	checker, err := NewStatusListChecker(
		WithCache(cache.NewMemoryCache[[]uint8](5*time.Minute)),
		WithHTTPClient(server.Client()),
		WithKeyResolver(testKeyResolver{key: &key.PublicKey}),
		WithFallbackIssuer("https://status.example.com"),
	)
	require.NoError(t, err)

	uri := server.URL + "/statuslists/0"
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub":         uri,
		"iat":         time.Now().Unix(),
		"status_list": statusListClaim(t, []uint8{0, tokenstatuslist.StatusInvalid}, 8),
	})
	tok.Header["typ"] = tokenstatuslist.JWTTypHeader
	token, err = tok.SignedString(key)
	require.NoError(t, err)

	result, err := checker.CheckStatus(t.Context(), &Reference{Scheme: SchemeStatusList, URI: uri, Index: 1})
	require.NoError(t, err)
	require.Equal(t, StatusInvalid, result.Status)
}

// TestMdocClaimsFeedTheSharedRevocationExtractor pins the contract that lets
// ONE revocation check cover every credential format: mdoc surfaces its MSO
// status parameter under the "status" key, in the same shape a JOSE
// Referenced Token uses, so ExtractStatusListReference reads mdoc, SD-JWT
// and JWP alike. If GetClaims stopped emitting it, mdoc would drop out of
// the check silently - the verifier would see a credential with no status
// and treat it as simply not revocable.
func TestMdocClaimsFeedTheSharedRevocationExtractor(t *testing.T) {
	dc := &mdoc.MDocDocumentClaims{
		DocType:    "org.iso.18013.5.1.mDL",
		Namespaces: map[string]map[string]any{},
		Status:     &mdoc.StatusReference{URI: "https://registry.example.com/statuslists/3", Index: 9},
	}

	ref := ExtractStatusListReference(dc.GetClaims())
	require.NotNil(t, ref, "the shared status extractor found nothing in mdoc claims")
	require.Equal(t, "https://registry.example.com/statuslists/3", ref.URI)
	require.Equal(t, int64(9), ref.Index)
}

// TestMdocMSOStatusWinsOverADataElement: the MSO reference is issuer-signed
// and cannot be withheld; a "status" data element can be chosen by whoever
// assembles the presentation. If the element won, a holder could point the
// verifier at a list the issuer never used.
func TestMdocMSOStatusWinsOverADataElement(t *testing.T) {
	dc := &mdoc.MDocDocumentClaims{
		DocType: "org.iso.18013.5.1.mDL",
		Namespaces: map[string]map[string]any{
			mdoc.Namespace: {"status": map[string]any{
				"status_list": map[string]any{"uri": "https://attacker.example.com/list", "idx": 0},
			}},
		},
		Status: &mdoc.StatusReference{URI: "https://issuer.example.com/statuslists/1", Index: 5},
	}

	ref := ExtractStatusListReference(dc.GetClaims())
	require.NotNil(t, ref)
	require.Equal(t, "https://issuer.example.com/statuslists/1", ref.URI,
		"the MSO reference must win over a holder-supplied data element")
	require.Equal(t, int64(5), ref.Index)
}

// TestVC20CredentialStatusReachesTheStatusCheck closes the loop for W3C VC
// 2.0: not just that ExtractCredentialStatusReference parses an entry, but
// that the registered checker consults it and performs the real lookup.
//
// Without this, a regression where StatusListChecker.Extract stopped trying
// credentialStatus would turn every VC 2.0 credential from "checked" into
// "refused by the fail-closed guard" - still safe, but completely broken,
// and the fail-closed tests would all keep passing.
func TestVC20CredentialStatusReachesTheStatusCheck(t *testing.T) {
	f := newStatusListFixture(t)

	statuses := make([]uint8, 64)
	statuses[42] = tokenstatuslist.StatusInvalid

	f.sign(t, tokenstatuslist.JWTTypHeader, jwt.MapClaims{
		"sub":         f.uri(),
		"iat":         time.Now().Unix(),
		"status_list": statusListClaim(t, statuses, 8),
	})

	claims := map[string]any{
		"type": []any{"VerifiableCredential"},
		"credentialStatus": map[string]any{
			"id":              f.uri() + "#42",
			"type":            contextstore.TokenStatusListEntryType,
			"statusListUri":   f.uri(),
			"statusListIndex": "42",
			"statusPurpose":   "revocation",
		},
	}

	registry := NewRegistry(f.checker)
	result, err := registry.Validate(t.Context(), claims)
	require.NoError(t, err)
	require.NotNil(t, result, "a VC 2.0 credentialStatus must reach the status check")
	require.Equal(t, StatusInvalid, result.Status)

	// And a valid index through the same path, so the test cannot pass by
	// refusing everything.
	claims["credentialStatus"].(map[string]any)["statusListIndex"] = "7"
	result, err = registry.Validate(t.Context(), claims)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, StatusValid, result.Status)
}

// TestStatusListToken_NoIssAndNoConfiguredIssuerIsRefused is the other half
// of making iss optional.
//
// A token without iss carries nothing to resolve a signing key from. The
// list URI is not a substitute: a status service publishes its status-list
// signing key separately from the list URL, so using the URI as an issuer
// identity sends the resolver looking for discovery under
// "<list URI>/.well-known/...", which is not there. Refusing is the
// fail-closed answer - an unverifiable status list must not be read as a
// verified one.
func TestStatusListToken_NoIssAndNoConfiguredIssuerIsRefused(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var token string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", tokenstatuslist.MediaTypeJWT)
		_, _ = w.Write([]byte(token))
	}))
	t.Cleanup(server.Close)

	// No WithFallbackIssuer.
	checker, err := NewStatusListChecker(
		WithCache(cache.NewMemoryCache[[]uint8](5*time.Minute)),
		WithHTTPClient(server.Client()),
		WithKeyResolver(testKeyResolver{key: &key.PublicKey}),
	)
	require.NoError(t, err)

	uri := server.URL + "/statuslists/0"
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub":         uri,
		"iat":         time.Now().Unix(),
		"status_list": statusListClaim(t, []uint8{0, 1}, 8),
	})
	tok.Header["typ"] = tokenstatuslist.JWTTypHeader
	token, err = tok.SignedString(key)
	require.NoError(t, err)

	_, err = checker.CheckStatus(t.Context(), &Reference{Scheme: SchemeStatusList, URI: uri, Index: 1})
	require.Error(t, err)
	require.Contains(t, err.Error(), "status_list_issuer")
}

// TestStatusListToken_IssStillWins: a token that does carry iss must use it,
// not the configured fallback, or a deployment with one configured would
// resolve every issuer's tokens under the same identity.
func TestStatusListToken_IssStillWins(t *testing.T) {
	f := newStatusListFixture(t)

	seen := &recordingKeyResolver{key: &f.key.PublicKey}
	checker, err := NewStatusListChecker(
		WithCache(cache.NewMemoryCache[[]uint8](5*time.Minute)),
		WithHTTPClient(f.server.Client()),
		WithKeyResolver(seen),
		WithFallbackIssuer("https://fallback.example.com"),
	)
	require.NoError(t, err)

	f.sign(t, tokenstatuslist.JWTTypHeader, jwt.MapClaims{
		"iss":         "https://real-issuer.example.com",
		"sub":         f.uri(),
		"iat":         time.Now().Unix(),
		"status_list": statusListClaim(t, []uint8{0, tokenstatuslist.StatusInvalid}, 8),
	})

	_, err = checker.CheckStatus(t.Context(), &Reference{Scheme: SchemeStatusList, URI: f.uri(), Index: 1})
	require.NoError(t, err)
	require.Equal(t, "https://real-issuer.example.com", seen.issuer)
}

// recordingKeyResolver captures the issuer identity it was asked about.
type recordingKeyResolver struct {
	key    any
	issuer string
}

func (r *recordingKeyResolver) ResolveKey(_ context.Context, issuer, _ string) (any, error) {
	r.issuer = issuer
	return r.key, nil
}

// TestStatusListToken_CWTTypHeaderIsEnforced closes the gap the JWT path
// already covered: without checking COSE protected header 16, a different
// COSE_Sign1 object signed by the same trusted key is accepted as a status
// list if its claims happen to be shaped alike.
func TestStatusListToken_CWTTypHeaderIsEnforced(t *testing.T) {
	for name, headers := range map[string]map[int64]any{
		"absent":       {},
		"wrong string": {int64(16): "application/cwt"},
		"wrong type":   {int64(16): 61},
	} {
		t.Run(name, func(t *testing.T) {
			err := checkCWTTypeHeader(headers)
			require.Error(t, err)
			require.Contains(t, err.Error(), tokenstatuslist.CWTTypHeader)
		})
	}

	// The real value is accepted in both encodings a COSE header can use.
	require.NoError(t, checkCWTTypeHeader(map[int64]any{int64(16): tokenstatuslist.CWTTypHeader}))
	require.NoError(t, checkCWTTypeHeader(map[int64]any{int64(16): []byte(tokenstatuslist.CWTTypHeader)}))

	// The bare subtype vc used to write is still read, so a list published
	// by an older vc verifies until it is next regenerated.
	require.NoError(t, checkCWTTypeHeader(map[int64]any{int64(16): "statuslist+cwt"}))
	require.NoError(t, checkCWTTypeHeader(map[int64]any{int64(16): []byte("statuslist+cwt")}))
}

// serveCWT serves a hand-built COSE_Sign1 with the given protected headers
// and checks what the status list checker makes of it.
//
// The signature is deliberately junk. The typ check runs before any key is
// resolved, so a token that fails it must be refused for THAT reason - which
// is what makes this a test of the call site rather than of the predicate.
func serveCWT(t *testing.T, protected map[int64]any) error {
	t.Helper()

	encoder, err := mdoc.NewCBOREncoder()
	require.NoError(t, err)

	protectedBytes, err := encoder.Marshal(protected)
	require.NoError(t, err)
	payloadBytes, err := encoder.Marshal(map[int]any{2: "https://example.com/statuslists/0"})
	require.NoError(t, err)

	token, err := encoder.Marshal(cbor.Tag{Number: 18, Content: []any{
		protectedBytes, map[any]any{}, payloadBytes, []byte("not-a-signature"),
	}})
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", tokenstatuslist.MediaTypeCWT)
		_, _ = w.Write(token)
	}))
	t.Cleanup(server.Close)

	checker, err := NewStatusListChecker(
		WithCache(cache.NewMemoryCache[[]uint8](5*time.Minute)),
		WithHTTPClient(server.Client()),
		WithKeyResolver(testKeyResolver{key: struct{}{}}),
		WithFallbackIssuer("https://status.example.com"),
	)
	require.NoError(t, err)

	_, err = checker.CheckStatus(t.Context(), &Reference{
		Scheme: SchemeStatusList, URI: server.URL + "/statuslists/0", Index: 0,
	})
	return err
}

// TestStatusListToken_CWTTypCheckIsWiredIn: the predicate above is only
// worth anything if parseCWTStatusList actually calls it.
func TestStatusListToken_CWTTypCheckIsWiredIn(t *testing.T) {
	// alg=ES256, content type of something that is not a status list.
	err := serveCWT(t, map[int64]any{1: -7, 16: "application/cwt"})
	require.Error(t, err)
	require.Contains(t, err.Error(), tokenstatuslist.CWTTypHeader,
		"a CWT with the wrong content type must be refused for that reason")

	// With the right content type the same token gets further - it still
	// fails, on the junk signature, which proves the typ check is not
	// simply rejecting everything.
	err = serveCWT(t, map[int64]any{1: -7, 16: tokenstatuslist.CWTTypHeader})
	require.Error(t, err)
	require.NotContains(t, err.Error(), tokenstatuslist.CWTTypHeader)
}

// TestStatusListToken_ConfiguredKeyVerifiesWithoutIss is the case a
// fallback ISSUER cannot cover. siros-status-service publishes its AS JWKS
// for access-token verification while signing status lists with a separate
// key that has no JWKS endpoint, so discovery finds nothing and every
// external status list fails to verify - which, with fail_open at its
// default of true, means a REVOKED credential is accepted.
//
// Naming the key directly is the only thing that verifies such a token.
func TestStatusListToken_ConfiguredKeyVerifiesWithoutIss(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var token string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", tokenstatuslist.MediaTypeJWT)
		_, _ = w.Write([]byte(token))
	}))
	t.Cleanup(server.Close)

	// A resolver that finds nothing, which is what discovery against a
	// service with no status-list JWKS actually does.
	checker, err := NewStatusListChecker(
		WithCache(cache.NewMemoryCache[[]uint8](5*time.Minute)),
		WithHTTPClient(server.Client()),
		WithKeyResolver(failingKeyResolver{}),
		WithFallbackIssuer("https://status.example.com"),
		WithStatusListKey(&key.PublicKey),
	)
	require.NoError(t, err)

	uri := server.URL + "/statuslists/0"
	statuses := make([]uint8, 16)
	statuses[3] = tokenstatuslist.StatusInvalid

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub":         uri,
		"iat":         time.Now().Unix(),
		"status_list": statusListClaim(t, statuses, 8),
	})
	tok.Header["typ"] = tokenstatuslist.JWTTypHeader
	token, err = tok.SignedString(key)
	require.NoError(t, err)

	result, err := checker.CheckStatus(t.Context(), &Reference{Scheme: SchemeStatusList, URI: uri, Index: 3})
	require.NoError(t, err, "a configured key must verify a token the resolver cannot resolve")
	require.Equal(t, StatusInvalid, result.Status)
}

// TestStatusListToken_NoKeyAndNoIssuerIsStillRefused keeps the fail-closed
// half: configuring neither must not silently accept.
func TestStatusListToken_NoKeyAndNoIssuerIsStillRefused(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var token string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", tokenstatuslist.MediaTypeJWT)
		_, _ = w.Write([]byte(token))
	}))
	t.Cleanup(server.Close)

	checker, err := NewStatusListChecker(
		WithCache(cache.NewMemoryCache[[]uint8](5*time.Minute)),
		WithHTTPClient(server.Client()),
		WithKeyResolver(failingKeyResolver{}),
	)
	require.NoError(t, err)

	uri := server.URL + "/statuslists/0"
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub":         uri,
		"iat":         time.Now().Unix(),
		"status_list": statusListClaim(t, []uint8{0, 1}, 8),
	})
	tok.Header["typ"] = tokenstatuslist.JWTTypHeader
	token, err = tok.SignedString(key)
	require.NoError(t, err)

	_, err = checker.CheckStatus(t.Context(), &Reference{Scheme: SchemeStatusList, URI: uri, Index: 1})
	require.Error(t, err)
	require.Contains(t, err.Error(), "status_list_key_file")
}

// failingKeyResolver stands in for discovery that finds no status-list key.
type failingKeyResolver struct{}

func (failingKeyResolver) ResolveKey(_ context.Context, issuer, _ string) (any, error) {
	return nil, errors.New("no JWKS published for " + issuer)
}

// TestStatusListToken_ConfiguredKeyPinsEvenWithIss: within its scope, a
// named key is a statement about which key signs these lists. Consulting
// the resolver anyway because the token happened to carry an iss would
// return a different key - and made the documented precedence untrue for
// exactly the tokens most likely to be encountered.
//
// Scope is the configured status-list issuer; a token from a DIFFERENT
// issuer still goes to the resolver, which
// TestStatusListToken_PinnedKeyDoesNotAnswerForAnotherIssuer covers.
func TestStatusListToken_ConfiguredKeyPinsEvenWithIss(t *testing.T) {
	pinned, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var token string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", tokenstatuslist.MediaTypeJWT)
		_, _ = w.Write([]byte(token))
	}))
	t.Cleanup(server.Close)

	// The resolver would hand back a DIFFERENT key, which is the situation
	// a rotating or mis-scoped JWKS produces.
	checker, err := NewStatusListChecker(
		WithCache(cache.NewMemoryCache[[]uint8](5*time.Minute)),
		WithHTTPClient(server.Client()),
		WithKeyResolver(testKeyResolver{key: &other.PublicKey}),
		// The pin is scoped to this issuer, so the token below carries it.
		WithFallbackIssuer("https://status.example.com"),
		WithStatusListKey(&pinned.PublicKey),
	)
	require.NoError(t, err)

	uri := server.URL + "/statuslists/0"
	statuses := make([]uint8, 8)
	statuses[2] = tokenstatuslist.StatusInvalid

	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss":         "https://status.example.com",
		"sub":         uri,
		"iat":         time.Now().Unix(),
		"status_list": statusListClaim(t, statuses, 8),
	})
	tok.Header["typ"] = tokenstatuslist.JWTTypHeader
	token, err = tok.SignedString(pinned)
	require.NoError(t, err)

	result, err := checker.CheckStatus(t.Context(), &Reference{Scheme: SchemeStatusList, URI: uri, Index: 2})
	require.NoError(t, err, "a token carrying iss must still verify against the pinned key")
	require.Equal(t, StatusInvalid, result.Status)
}

// TestStatusListToken_PinnedKeyDoesNotAnswerForAnotherIssuer: a deployment
// may run vc's own registry alongside an external status service, and those
// lists are signed by different keys. An unscoped pin made the external key
// answer for registry tokens too, so registry lists stopped verifying the
// moment a key file was configured - which fail_open would then tolerate.
func TestStatusListToken_PinnedKeyDoesNotAnswerForAnotherIssuer(t *testing.T) {
	registryKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	externalKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var token string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", tokenstatuslist.MediaTypeJWT)
		_, _ = w.Write([]byte(token))
	}))
	t.Cleanup(server.Close)

	checker, err := NewStatusListChecker(
		WithCache(cache.NewMemoryCache[[]uint8](5*time.Minute)),
		WithHTTPClient(server.Client()),
		// The resolver knows the REGISTRY key, as it would in a deployment
		// whose registry publishes a JWKS.
		WithKeyResolver(testKeyResolver{key: &registryKey.PublicKey}),
		WithFallbackIssuer("https://status.example.com"),
		WithStatusListKey(&externalKey.PublicKey),
	)
	require.NoError(t, err)

	uri := server.URL + "/statuslists/0"
	statuses := make([]uint8, 8)
	statuses[1] = tokenstatuslist.StatusInvalid

	// A registry token: its own issuer, signed with the registry key.
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss":         "https://registry.example.com",
		"sub":         uri,
		"iat":         time.Now().Unix(),
		"status_list": statusListClaim(t, statuses, 8),
	})
	tok.Header["typ"] = tokenstatuslist.JWTTypHeader
	token, err = tok.SignedString(registryKey)
	require.NoError(t, err)

	result, err := checker.CheckStatus(t.Context(), &Reference{Scheme: SchemeStatusList, URI: uri, Index: 1})
	require.NoError(t, err, "a registry list must still verify when an external key is configured")
	require.Equal(t, StatusInvalid, result.Status)
}

// cwtLayout describes one spelling of the CWT status list wire format, so
// the same end-to-end path can be driven with the draft's layout and with
// the one vc used to write.
type cwtLayout struct {
	statusListClaim int
	typ             string
	members         func(bits int, lst []byte) any
}

func textMembers(bits int, lst []byte) any {
	return map[string]any{"bits": bits, "lst": lst}
}

func intMembers(bits int, lst []byte) any {
	return map[int]any{1: bits, 2: lst}
}

// serveSignedCWT mints a genuinely signed status list CWT in the given
// layout, serves it, and asks the checker for one index. Unlike serveCWT
// above (which tests the typ gate with a junk signature) this one has to
// get all the way through verification, because what is under test is
// whether the claims are FOUND.
func serveSignedCWT(t *testing.T, layout cwtLayout, statuses []uint8, index int) (*CheckResult, error) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var token []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", tokenstatuslist.MediaTypeCWT)
		_, _ = w.Write(token)
	}))
	t.Cleanup(server.Close)

	uri := server.URL + "/statuslists/0"

	compressed, err := tokenstatuslist.CompressStatuses(statuses)
	require.NoError(t, err)

	encoder, err := mdoc.NewCBOREncoder()
	require.NoError(t, err)

	payload, err := encoder.Marshal(map[int]any{
		1:                      "https://status.example.com",
		2:                      uri,
		6:                      time.Now().Unix(),
		layout.statusListClaim: layout.members(8, compressed),
	})
	require.NoError(t, err)

	// mdoc.Sign1 builds its own protected header (alg only), but a status
	// list CWT also has to carry the content type there, and the signature
	// covers those bytes - so the protected header is built first and
	// signed as chosen.
	protectedBytes, err := encoder.Marshal(map[int64]any{int64(1): int64(-7), int64(16): layout.typ})
	require.NoError(t, err)
	sign1, err := signCWTWithProtected(t, protectedBytes, payload, key)
	require.NoError(t, err)

	token, err = encoder.Marshal(cbor.Tag{Number: 18, Content: []any{
		sign1.Protected, map[any]any{}, sign1.Payload, sign1.Signature,
	}})
	require.NoError(t, err)

	checker, err := NewStatusListChecker(
		WithCache(cache.NewMemoryCache[[]uint8](5*time.Minute)),
		WithHTTPClient(server.Client()),
		WithKeyResolver(testKeyResolver{key: &key.PublicKey}),
	)
	require.NoError(t, err)

	return checker.CheckStatus(t.Context(), &Reference{
		Scheme: SchemeStatusList, URI: uri, Index: int64(index),
	})
}

// signCWTWithProtected signs a COSE_Sign1 over protected bytes the caller
// chose, which mdoc.Sign1 does not allow (it builds its own).
func signCWTWithProtected(t *testing.T, protectedBytes, payload []byte, key *ecdsa.PrivateKey) (*mdoc.COSESign1, error) {
	t.Helper()

	encoder, err := mdoc.NewCBOREncoder()
	require.NoError(t, err)

	sigStructure, err := encoder.Marshal([]any{"Signature1", protectedBytes, []byte{}, payload})
	require.NoError(t, err)

	digest := sha256.Sum256(sigStructure)
	r, sv, err := ecdsa.Sign(rand.Reader, key, digest[:])
	require.NoError(t, err)

	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	sv.FillBytes(signature[32:])

	return &mdoc.COSESign1{
		Protected:   protectedBytes,
		Unprotected: map[any]any{},
		Payload:     payload,
		Signature:   signature,
	}, nil
}

// TestStatusListToken_CWTLayouts drives the whole CWT path with both
// spellings. The draft's is what vc writes; the legacy one is what an older
// vc wrote, and a deployment must not go dark on revocation for the refresh
// cycle it takes for its lists to be regenerated.
func TestStatusListToken_CWTLayouts(t *testing.T) {
	statuses := make([]uint8, 16)
	statuses[3] = tokenstatuslist.StatusInvalid

	layouts := map[string]cwtLayout{
		"draft labels, text members, full media type": {
			statusListClaim: 65533,
			typ:             "application/statuslist+cwt",
			members:         textMembers,
		},
		"legacy labels, integer members, bare subtype": {
			statusListClaim: 65534,
			typ:             "statuslist+cwt",
			members:         intMembers,
		},
		"legacy labels with the draft media type": {
			statusListClaim: 65534,
			typ:             "application/statuslist+cwt",
			members:         intMembers,
		},
	}

	for name, layout := range layouts {
		t.Run(name, func(t *testing.T) {
			result, err := serveSignedCWT(t, layout, statuses, 3)
			require.NoError(t, err)
			require.Equal(t, StatusInvalid, result.Status)
		})
	}
}

// TestStatusListToken_CWTWithOnlyTTLIsRefused: 65534 now means ttl, and a
// token carrying one but no status_list has to be reported as missing a
// status_list rather than being read as a malformed one.
func TestStatusListToken_CWTWithOnlyTTLIsRefused(t *testing.T) {
	statuses := make([]uint8, 16)

	_, err := serveSignedCWT(t, cwtLayout{
		statusListClaim: 65534,
		typ:             "application/statuslist+cwt",
		members:         func(int, []byte) any { return uint64(43200) },
	}, statuses, 3)

	require.Error(t, err)
	require.Contains(t, err.Error(), "status_list claim not found")
}
