package revocation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"maps"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/tokenstatuslist"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testKeyResolver returns a fixed key for any issuer/kid lookup.
type testKeyResolver struct {
	key any
}

func (r testKeyResolver) ResolveKey(_ context.Context, _, _ string) (any, error) {
	return r.key, nil
}

func TestExtractStatusListReference(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		claims := map[string]any{
			"status": map[string]any{
				"status_list": map[string]any{
					"uri": "https://registry.example.com/statuslists/0",
					"idx": float64(42),
				},
			},
		}
		ref := ExtractStatusListReference(claims)
		require.NotNil(t, ref)
		assert.Equal(t, SchemeStatusList, ref.Scheme)
		assert.Equal(t, "https://registry.example.com/statuslists/0", ref.URI)
		assert.Equal(t, int64(42), ref.Index)
	})

	t.Run("no status claim", func(t *testing.T) {
		ref := ExtractStatusListReference(map[string]any{"iss": "x"})
		assert.Nil(t, ref)
	})

	t.Run("missing uri", func(t *testing.T) {
		claims := map[string]any{
			"status": map[string]any{
				"status_list": map[string]any{"idx": float64(1)},
			},
		}
		assert.Nil(t, ExtractStatusListReference(claims))
	})
}

func TestRegistry_CheckStatus(t *testing.T) {
	t.Run("nil reference returns nil", func(t *testing.T) {
		r := NewRegistry()
		result, err := r.CheckStatus(t.Context(), nil)
		assert.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("no checker for scheme", func(t *testing.T) {
		r := NewRegistry()
		_, err := r.CheckStatus(t.Context(), &Reference{Scheme: "unknown"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no checker registered")
	})
}

func TestRegistry_Validate(t *testing.T) {
	t.Run("no checkers returns nil", func(t *testing.T) {
		r := NewRegistry()
		result, err := r.Validate(t.Context(), map[string]any{"iss": "x"})
		assert.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("no status claim returns nil", func(t *testing.T) {
		statusCache := cache.NewMemoryCache[[]uint8](5 * time.Minute)
		checker, err := NewStatusListChecker(WithCache(statusCache), WithKeyResolver(testKeyResolver{}))
		require.NoError(t, err)
		r := NewRegistry(checker)
		result, err := r.Validate(t.Context(), map[string]any{"iss": "x"})
		assert.NoError(t, err)
		assert.Nil(t, result, "credential without status is not revocable")
	})
}

func TestStatusListChecker_CheckStatus(t *testing.T) {
	// Create a test status list with entry 0=valid, 1=revoked, 2=suspended
	statuses := []uint8{tokenstatuslist.StatusValid, tokenstatuslist.StatusInvalid, tokenstatuslist.StatusSuspended}

	// Generate an EC key pair for signing the status list token
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Serve a token whose sub is the URL it was fetched from.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sl := tokenstatuslist.NewWithConfig(statuses, "https://registry.test", "http://"+r.Host+r.URL.Path)
		signedJWT, err := sl.GenerateJWT(tokenstatuslist.JWTSigningConfig{SigningKey: privateKey, SigningMethod: jwt.SigningMethodES256})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", tokenstatuslist.MediaTypeJWT)
		_, _ = w.Write([]byte(signedJWT))
	}))
	defer server.Close()

	statusCache := cache.NewMemoryCache[[]uint8](5 * time.Minute)
	checker, err := NewStatusListChecker(
		WithCache(statusCache),
		WithHTTPClient(server.Client()),
		WithKeyResolver(testKeyResolver{key: &privateKey.PublicKey}),
	)
	require.NoError(t, err)

	registry := NewRegistry(checker)

	t.Run("valid credential", func(t *testing.T) {
		ref := &Reference{Scheme: SchemeStatusList, URI: server.URL + "/statuslists/0", Index: 0}
		result, err := registry.CheckStatus(t.Context(), ref)
		require.NoError(t, err)
		assert.Equal(t, StatusValid, result.Status)
	})

	t.Run("revoked credential", func(t *testing.T) {
		ref := &Reference{Scheme: SchemeStatusList, URI: server.URL + "/statuslists/0", Index: 1}
		result, err := registry.CheckStatus(t.Context(), ref)
		require.NoError(t, err)
		assert.Equal(t, StatusInvalid, result.Status)
	})

	t.Run("suspended credential", func(t *testing.T) {
		ref := &Reference{Scheme: SchemeStatusList, URI: server.URL + "/statuslists/0", Index: 2}
		result, err := registry.CheckStatus(t.Context(), ref)
		require.NoError(t, err)
		assert.Equal(t, StatusSuspended, result.Status)
	})

	t.Run("index out of range", func(t *testing.T) {
		ref := &Reference{Scheme: SchemeStatusList, URI: server.URL + "/statuslists/0", Index: 999}
		_, err := registry.CheckStatus(t.Context(), ref)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "out of range")
	})
}

// serveToken serves one fixed token and returns a checker trusting key.
func serveToken(t *testing.T, key *ecdsa.PrivateKey, contentType string, body []byte, opts ...StatusListCheckerOption) (*StatusListChecker, *httptest.Server, cache.Cache[[]uint8]) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)

	statusCache := cache.NewMemoryCache[[]uint8](time.Hour)
	checker, err := NewStatusListChecker(append([]StatusListCheckerOption{
		WithCache(statusCache),
		WithHTTPClient(server.Client()),
		WithKeyResolver(testKeyResolver{key: &key.PublicKey}),
	}, opts...)...)
	require.NoError(t, err)
	return checker, server, statusCache
}

func TestStatusListChecker_RejectsBadTokens(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	statuses := []uint8{tokenstatuslist.StatusValid}
	lst, err := tokenstatuslist.CompressAndEncode(statuses)
	require.NoError(t, err)

	t.Run("jwt without typ", func(t *testing.T) {
		tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"iss": "x", "sub": "u", "status_list": map[string]any{"bits": 8, "lst": lst}})
		signed, err := tok.SignedString(key)
		require.NoError(t, err)
		checker, srv, _ := serveToken(t, key, tokenstatuslist.MediaTypeJWT, []byte(signed))
		_, err = checker.CheckStatus(t.Context(), &Reference{Scheme: SchemeStatusList, URI: srv.URL, Index: 0})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "typ")
	})

	t.Run("jwt sub mismatch", func(t *testing.T) {
		sl := tokenstatuslist.NewWithConfig(statuses, "x", "https://elsewhere.example/statuslists/9")
		signed, err := sl.GenerateJWT(tokenstatuslist.JWTSigningConfig{SigningKey: key, SigningMethod: jwt.SigningMethodES256})
		require.NoError(t, err)
		checker, srv, _ := serveToken(t, key, tokenstatuslist.MediaTypeJWT, []byte(signed))
		_, err = checker.CheckStatus(t.Context(), &Reference{Scheme: SchemeStatusList, URI: srv.URL, Index: 0})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not match")
	})

	t.Run("jwt expired", func(t *testing.T) {
		claims := tokenstatuslist.JWTClaims{
			Subject: "u", ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			StatusList: tokenstatuslist.StatusListClaim{Bits: 8, Lst: lst},
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		tok.Header["typ"] = tokenstatuslist.JWTTypHeader
		signed, err := tok.SignedString(key)
		require.NoError(t, err)
		checker, srv, _ := serveToken(t, key, tokenstatuslist.MediaTypeJWT, []byte(signed))
		_, err = checker.CheckStatus(t.Context(), &Reference{Scheme: SchemeStatusList, URI: srv.URL, Index: 0})
		require.Error(t, err)
	})

	t.Run("jwt with exp 0", func(t *testing.T) {
		const uri = "https://registry.example.com/statuslists/1"
		tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"iss": "x", "sub": uri, "exp": 0, "status_list": map[string]any{"bits": 8, "lst": lst}})
		tok.Header["typ"] = tokenstatuslist.JWTTypHeader
		signed, err := tok.SignedString(key)
		require.NoError(t, err)
		checker, _, _ := serveToken(t, key, tokenstatuslist.MediaTypeJWT, nil)
		_, err = checker.parseJWTStatusList(t.Context(), uri, []byte(signed))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
	})

	t.Run("cwt sub mismatch", func(t *testing.T) {
		sl := tokenstatuslist.NewWithConfig(statuses, "x", "https://elsewhere.example/statuslists/9")
		cwtBytes, err := sl.GenerateCWT(tokenstatuslist.CWTSigningConfig{SigningKey: key})
		require.NoError(t, err)
		checker, srv, _ := serveToken(t, key, tokenstatuslist.MediaTypeCWT, cwtBytes)
		_, err = checker.CheckStatus(t.Context(), &Reference{Scheme: SchemeStatusList, URI: srv.URL, Index: 0})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not match")
	})

	t.Run("cwt expired", func(t *testing.T) {
		sl := tokenstatuslist.NewWithConfig(statuses, "x", "")
		sl.ExpiresIn = time.Nanosecond
		checker, srv, _ := serveToken(t, key, tokenstatuslist.MediaTypeCWT, nil)
		sl.Subject = srv.URL
		cwtBytes, err := sl.GenerateCWT(tokenstatuslist.CWTSigningConfig{SigningKey: key})
		require.NoError(t, err)
		time.Sleep(1100 * time.Millisecond)
		_, err = checker.parseCWTStatusList(t.Context(), srv.URL, cwtBytes)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
	})
}

func TestStatusListChecker_CWTAccepted(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	checker, srv, _ := serveToken(t, key, tokenstatuslist.MediaTypeCWT, nil)
	sl := tokenstatuslist.NewWithConfig([]uint8{0, tokenstatuslist.StatusInvalid}, "x", srv.URL)
	cwtBytes, err := sl.GenerateCWT(tokenstatuslist.CWTSigningConfig{SigningKey: key})
	require.NoError(t, err)

	tok, err := checker.parseCWTStatusList(t.Context(), srv.URL, cwtBytes)
	require.NoError(t, err)
	assert.Equal(t, []uint8{0, tokenstatuslist.StatusInvalid}, tok.statuses)
}

func TestStatusListChecker_EntryTTL(t *testing.T) {
	ttl := func(c *StatusListChecker, tok *statusListToken) time.Duration {
		t.Helper()
		d, err := c.entryTTL(tok)
		require.NoError(t, err)
		return d
	}

	c := &StatusListChecker{}
	assert.Equal(t, time.Duration(0), ttl(c, &statusListToken{}))
	assert.Equal(t, time.Minute, ttl(c, &statusListToken{ttl: time.Minute}))

	// exp sooner than ttl wins
	got := ttl(c, &statusListToken{ttl: time.Hour, exp: time.Now().Add(time.Minute)})
	assert.InDelta(t, float64(time.Minute), float64(got), float64(2*time.Second))

	// configured maximum caps a longer ttl and an unset one
	c.maxCacheTTL = 30 * time.Second
	assert.Equal(t, 30*time.Second, ttl(c, &statusListToken{ttl: time.Hour}))
	assert.Equal(t, 30*time.Second, ttl(c, &statusListToken{}))
}

// A token that expired between parsing and caching must be rejected, not cached.
func TestStatusListChecker_EntryTTL_RejectsExpired(t *testing.T) {
	for name, c := range map[string]*StatusListChecker{
		"no max":   {},
		"with max": {maxCacheTTL: time.Minute},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := c.entryTTL(&statusListToken{ttl: time.Hour, exp: time.Now().Add(-time.Second)})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "expired")
		})
	}
}

func TestCWTToken_NumericClaims(t *testing.T) {
	const uri = "https://registry.example.com/statuslists/1"
	lst, err := tokenstatuslist.CompressStatuses([]uint8{0, 1})
	require.NoError(t, err)
	claims := func(extra map[int]any) map[int]any {
		m := map[int]any{cwtClaimSub: uri, cwtClaimStatusList: map[int]any{1: 8, statusListKeyLst: lst}}
		maps.Copy(m, extra)
		return m
	}
	now := time.Now()

	t.Run("float exp in the past is rejected", func(t *testing.T) {
		_, err := cwtToken(uri, claims(map[int]any{cwtClaimExp: float64(now.Add(-time.Hour).Unix()) + 0.5}), 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
	})

	t.Run("float exp in the future sets the deadline", func(t *testing.T) {
		tok, err := cwtToken(uri, claims(map[int]any{cwtClaimExp: float64(now.Add(time.Hour).Unix()) + 0.5}), 0)
		require.NoError(t, err)
		assert.WithinDuration(t, now.Add(time.Hour), tok.exp, 2*time.Second)
	})

	t.Run("integer widths are accepted", func(t *testing.T) {
		for _, exp := range []any{int64(now.Add(time.Hour).Unix()), uint64(now.Add(time.Hour).Unix()), int(now.Add(time.Hour).Unix())} {
			tok, err := cwtToken(uri, claims(map[int]any{cwtClaimExp: exp}), 0)
			require.NoError(t, err, "%T", exp)
			assert.False(t, tok.exp.IsZero())
		}
	})

	t.Run("present but non-numeric exp is rejected", func(t *testing.T) {
		for _, exp := range []any{"tomorrow", []byte{1}, math.NaN(), math.Inf(1), nil} {
			_, err := cwtToken(uri, claims(map[int]any{cwtClaimExp: exp}), 0)
			require.Error(t, err, "%v", exp)
			assert.Contains(t, err.Error(), "invalid exp")
		}
	})

	t.Run("ttl accepts integers and floats", func(t *testing.T) {
		tok, err := cwtToken(uri, claims(map[int]any{cwtClaimTTL: int64(60)}), 0)
		require.NoError(t, err)
		assert.Equal(t, time.Minute, tok.ttl)

		tok, err = cwtToken(uri, claims(map[int]any{cwtClaimTTL: 1.5}), 0)
		require.NoError(t, err)
		assert.Equal(t, 1500*time.Millisecond, tok.ttl)
	})

	t.Run("present but invalid ttl is rejected", func(t *testing.T) {
		for _, ttl := range []any{"soon", -1, math.NaN(), 1e30} {
			_, err := cwtToken(uri, claims(map[int]any{cwtClaimTTL: ttl}), 0)
			require.Error(t, err, "%v", ttl)
			assert.Contains(t, err.Error(), "invalid ttl")
		}
	})

	t.Run("absent exp and ttl are fine", func(t *testing.T) {
		tok, err := cwtToken(uri, claims(nil), 0)
		require.NoError(t, err)
		assert.True(t, tok.exp.IsZero())
		assert.Zero(t, tok.ttl)
		assert.False(t, tok.ttlSet)
	})

	t.Run("explicit zero ttl is recorded as set", func(t *testing.T) {
		tok, err := cwtToken(uri, claims(map[int]any{cwtClaimTTL: int64(0)}), 0)
		require.NoError(t, err)
		assert.True(t, tok.ttlSet)
		assert.Zero(t, tok.ttl)
	})
}

// A token with ttl 0 permits no caching, so every check must refetch.
func TestStatusListChecker_ExplicitZeroTTLIsNotCached(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	lst, err := tokenstatuslist.CompressAndEncode([]uint8{0})
	require.NoError(t, err)

	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
			"iss": "x", "sub": "http://" + r.Host + r.URL.Path, "ttl": 0,
			"status_list": map[string]any{"bits": 8, "lst": lst},
		})
		tok.Header["typ"] = tokenstatuslist.JWTTypHeader
		signed, err := tok.SignedString(key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", tokenstatuslist.MediaTypeJWT)
		_, _ = w.Write([]byte(signed))
	}))
	defer server.Close()

	statusCache := cache.NewMemoryCache[[]uint8](time.Hour)
	defer statusCache.Stop()
	checker, err := NewStatusListChecker(
		WithCache(statusCache),
		WithMaxCacheTTL(time.Hour),
		WithHTTPClient(server.Client()),
		WithKeyResolver(testKeyResolver{key: &key.PublicKey}),
	)
	require.NoError(t, err)

	ref := &Reference{Scheme: SchemeStatusList, URI: server.URL + "/statuslists/0", Index: 0}
	for range 2 {
		_, err := checker.CheckStatus(t.Context(), ref)
		require.NoError(t, err)
	}
	assert.Equal(t, int32(2), hits.Load())
}

// Reads must not extend a cached list past its absolute lifetime.
func TestStatusListChecker_CacheDoesNotSlide(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		sl := tokenstatuslist.NewWithConfig([]uint8{0}, "https://registry.test", "http://"+r.Host+r.URL.Path)
		signed, err := sl.GenerateJWT(tokenstatuslist.JWTSigningConfig{SigningKey: key, SigningMethod: jwt.SigningMethodES256})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", tokenstatuslist.MediaTypeJWT)
		_, _ = w.Write([]byte(signed))
	}))
	defer server.Close()

	const life = 400 * time.Millisecond
	statusCache := cache.NewMemoryCache[[]uint8](life)
	defer statusCache.Stop()
	checker, err := NewStatusListChecker(
		WithCache(statusCache),
		WithMaxCacheTTL(life),
		WithHTTPClient(server.Client()),
		WithKeyResolver(testKeyResolver{key: &key.PublicKey}),
	)
	require.NoError(t, err)

	ref := &Reference{Scheme: SchemeStatusList, URI: server.URL + "/statuslists/0", Index: 0}
	start := time.Now()
	// Keep reading well past the lifetime: a sliding cache would never refetch.
	for time.Since(start) < 3*life/2 {
		_, err := checker.CheckStatus(t.Context(), ref)
		require.NoError(t, err)
		time.Sleep(life / 8)
	}
	assert.GreaterOrEqual(t, hits.Load(), int32(2), "status list was never refetched after its lifetime ended")
}

func TestStatusListChecker_Unreachable(t *testing.T) {
	statusCache := cache.NewMemoryCache[[]uint8](5 * time.Minute)
	checker, err := NewStatusListChecker(
		WithCache(statusCache),
		WithHTTPClient(&http.Client{Timeout: 1 * time.Second}),
		WithKeyResolver(testKeyResolver{}),
	)
	require.NoError(t, err)

	ref := &Reference{Scheme: SchemeStatusList, URI: "http://192.0.2.1/unreachable", Index: 0}
	_, err = checker.CheckStatus(t.Context(), ref)
	assert.Error(t, err)
}

func TestStatusListChecker_Supports(t *testing.T) {
	statusCache := cache.NewMemoryCache[[]uint8](5 * time.Minute)
	checker, _ := NewStatusListChecker(WithCache(statusCache), WithKeyResolver(testKeyResolver{}))

	assert.True(t, checker.Supports(SchemeStatusList))
	assert.False(t, checker.Supports(Scheme("ocsp")))
}

func signedJWTWithBits(t *testing.T, key *ecdsa.PrivateKey, sub string, statusList map[string]any) []byte {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"iss": "x", "sub": sub, "status_list": statusList})
	tok.Header["typ"] = tokenstatuslist.JWTTypHeader
	signed, err := tok.SignedString(key)
	require.NoError(t, err)
	return []byte(signed)
}

// Entry 9 of a bits=1 list is bit 1 of byte 1; reading byte 9 would hide a revocation.
func TestStatusListChecker_PackedBits(t *testing.T) {
	const uri = "https://registry.example.com/statuslists/1"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	checker, _, _ := serveToken(t, key, tokenstatuslist.MediaTypeJWT, nil)

	raw := make([]byte, 16)
	raw[1] = 0b10 // entry 9
	compressed, err := tokenstatuslist.CompressStatuses(raw)
	require.NoError(t, err)
	lst := base64.RawURLEncoding.EncodeToString(compressed)

	t.Run("jwt bits 1", func(t *testing.T) {
		tok, err := checker.parseJWTStatusList(t.Context(), uri, signedJWTWithBits(t, key, uri, map[string]any{"bits": 1, "lst": lst}))
		require.NoError(t, err)
		require.Len(t, tok.statuses, 128)
		assert.Equal(t, tokenstatuslist.StatusInvalid, tok.statuses[9])
		assert.Equal(t, tokenstatuslist.StatusValid, tok.statuses[8])
		assert.Equal(t, tokenstatuslist.StatusValid, tok.statuses[10])
	})

	t.Run("jwt bad bits", func(t *testing.T) {
		for _, bits := range []any{nil, "8", 0, 3, 16, 1.5, -1} {
			_, err := checker.parseJWTStatusList(t.Context(), uri, signedJWTWithBits(t, key, uri, map[string]any{"bits": bits, "lst": lst}))
			require.Error(t, err, "bits %v", bits)
		}
	})

	t.Run("jwt missing bits", func(t *testing.T) {
		_, err := checker.parseJWTStatusList(t.Context(), uri, signedJWTWithBits(t, key, uri, map[string]any{"lst": lst}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "bits")
	})

	t.Run("cwt bits 1", func(t *testing.T) {
		claims := map[int]any{cwtClaimSub: uri, cwtClaimStatusList: map[int]any{1: 1, statusListKeyLst: compressed}}
		tok, err := cwtToken(uri, claims, 0)
		require.NoError(t, err)
		assert.Equal(t, tokenstatuslist.StatusInvalid, tok.statuses[9])
		assert.Equal(t, tokenstatuslist.StatusValid, tok.statuses[8])
	})

	t.Run("cwt bad or missing bits", func(t *testing.T) {
		for _, sl := range []map[int]any{
			{statusListKeyLst: compressed},
			{1: 3, statusListKeyLst: compressed},
			{1: "8", statusListKeyLst: compressed},
		} {
			_, err := cwtToken(uri, map[int]any{cwtClaimSub: uri, cwtClaimStatusList: sl}, 0)
			require.Error(t, err, "%v", sl)
		}
	})
}

func TestStatusListChecker_MaxEntries(t *testing.T) {
	const uri = "https://registry.example.com/statuslists/1"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	compressed, err := tokenstatuslist.CompressStatuses(make([]byte, 100)) // 800 entries at bits=1
	require.NoError(t, err)
	lst := base64.RawURLEncoding.EncodeToString(compressed)
	token := signedJWTWithBits(t, key, uri, map[string]any{"bits": 1, "lst": lst})

	t.Run("within limit", func(t *testing.T) {
		checker, _, _ := serveToken(t, key, tokenstatuslist.MediaTypeJWT, nil, WithMaxEntries(800))
		tok, err := checker.parseJWTStatusList(t.Context(), uri, token)
		require.NoError(t, err)
		assert.Len(t, tok.statuses, 800)
	})

	t.Run("over limit", func(t *testing.T) {
		checker, _, _ := serveToken(t, key, tokenstatuslist.MediaTypeJWT, nil, WithMaxEntries(792))
		_, err := checker.parseJWTStatusList(t.Context(), uri, token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds maximum size")
	})

	t.Run("default is 2^24", func(t *testing.T) {
		assert.Equal(t, int64(1<<24), int64(tokenstatuslist.DefaultMaxEntries))
	})
}

// jwtClaimsFixture returns a checker and a signer for one-entry status list JWTs with extra claims merged in.
func jwtClaimsFixture(t *testing.T, uri string) (*StatusListChecker, func(extra map[string]any) []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	checker, _, _ := serveToken(t, key, tokenstatuslist.MediaTypeJWT, nil)

	compressed, err := tokenstatuslist.CompressStatuses([]uint8{0})
	require.NoError(t, err)
	statusList := map[string]any{"bits": 8, "lst": base64.RawURLEncoding.EncodeToString(compressed)}

	return checker, func(extra map[string]any) []byte {
		claims := jwt.MapClaims{"iss": "x", "sub": uri, "status_list": statusList}
		maps.Copy(claims, extra)
		tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		tok.Header["typ"] = tokenstatuslist.JWTTypHeader
		signed, err := tok.SignedString(key)
		require.NoError(t, err)
		return []byte(signed)
	}
}

func TestStatusListChecker_JWTNullClaims(t *testing.T) {
	const uri = "https://registry.example.com/statuslists/1"
	checker, sign := jwtClaimsFixture(t, uri)

	for _, claim := range []string{"exp", "ttl"} {
		t.Run(claim+" null is rejected", func(t *testing.T) {
			_, err := checker.parseJWTStatusList(t.Context(), uri, sign(map[string]any{claim: nil}))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "must not be null")
		})
	}

	t.Run("omitted exp and ttl are accepted", func(t *testing.T) {
		tok, err := checker.parseJWTStatusList(t.Context(), uri, sign(nil))
		require.NoError(t, err)
		assert.True(t, tok.exp.IsZero())
		assert.False(t, tok.ttlSet)
	})

	t.Run("explicit zero ttl is still accepted", func(t *testing.T) {
		tok, err := checker.parseJWTStatusList(t.Context(), uri, sign(map[string]any{"ttl": 0}))
		require.NoError(t, err)
		assert.True(t, tok.ttlSet)
	})
}

func TestStatusListChecker_JWTQuotedClaims(t *testing.T) {
	const uri = "https://registry.example.com/statuslists/1"
	checker, sign := jwtClaimsFixture(t, uri)

	future := time.Now().Add(time.Hour).Unix()
	for name, extra := range map[string]map[string]any{
		"quoted exp": {"exp": strconv.FormatInt(future, 10)},
		"quoted ttl": {"ttl": "60"},
	} {
		t.Run(name+" is rejected", func(t *testing.T) {
			_, err := checker.parseJWTStatusList(t.Context(), uri, sign(extra))
			require.Error(t, err)
		})
	}

	t.Run("numeric exp and ttl are accepted", func(t *testing.T) {
		tok, err := checker.parseJWTStatusList(t.Context(), uri, sign(map[string]any{"exp": future, "ttl": 60}))
		require.NoError(t, err)
		assert.False(t, tok.exp.IsZero())
		assert.Equal(t, time.Minute, tok.ttl)
	})
}

// A claim spelled with different case is read differently by encoding/json than by a case-sensitive parser.
func TestStatusListChecker_JWTCaseVariantClaims(t *testing.T) {
	const uri = "https://registry.example.com/statuslists/1"
	checker, sign := jwtClaimsFixture(t, uri)
	future := time.Now().Add(time.Hour).Unix()

	for name, extra := range map[string]map[string]any{
		"EXP beside exp": {"exp": 1, "EXP": future},
		"EXP alone":      {"EXP": future},
		"TTL beside ttl": {"ttl": 0, "TTL": 3600},
		"Sub":            {"Sub": uri},
		"Status_List":    {"Status_List": map[string]any{"bits": 8, "lst": "x"}},
	} {
		t.Run(name+" is rejected", func(t *testing.T) {
			_, err := checker.parseJWTStatusList(t.Context(), uri, sign(extra))
			require.Error(t, err)
			assert.Contains(t, err.Error(), "must be spelled")
		})
	}

	t.Run("case variant of a status_list member is rejected", func(t *testing.T) {
		_, err := checker.parseJWTStatusList(t.Context(), uri, sign(map[string]any{
			"status_list": map[string]any{"bits": 8, "LST": "x", "lst": "x"},
		}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must be spelled")
	})

	t.Run("unrelated claims and exact names are accepted", func(t *testing.T) {
		tok, err := checker.parseJWTStatusList(t.Context(), uri, sign(map[string]any{"exp": future, "ttl": 60, "custom": 1, "Custom": 2}))
		require.NoError(t, err)
		assert.False(t, tok.exp.IsZero())
	})
}
