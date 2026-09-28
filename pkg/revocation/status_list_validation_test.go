package revocation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/tokenstatuslist"
	"github.com/SUNET/vc/pkg/vc20/contextstore"

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
// rejects conformant status services.
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
