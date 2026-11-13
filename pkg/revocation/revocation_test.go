package revocation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math"
	"net/http"
	"net/http/httptest"
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
		tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"iss": "x", "sub": "u", "status_list": map[string]any{"lst": lst}})
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
			RegisteredClaims: jwt.RegisteredClaims{Subject: "u", ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Minute))},
			StatusList:       tokenstatuslist.StatusListClaim{Bits: 8, Lst: lst},
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		tok.Header["typ"] = tokenstatuslist.JWTTypHeader
		signed, err := tok.SignedString(key)
		require.NoError(t, err)
		checker, srv, _ := serveToken(t, key, tokenstatuslist.MediaTypeJWT, []byte(signed))
		_, err = checker.CheckStatus(t.Context(), &Reference{Scheme: SchemeStatusList, URI: srv.URL, Index: 0})
		require.Error(t, err)
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
		m := map[int]any{cwtClaimSub: uri, cwtClaimStatusList: map[int]any{statusListKeyLst: lst}}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	now := time.Now()

	t.Run("float exp in the past is rejected", func(t *testing.T) {
		_, err := cwtToken(uri, claims(map[int]any{cwtClaimExp: float64(now.Add(-time.Hour).Unix()) + 0.5}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
	})

	t.Run("float exp in the future sets the deadline", func(t *testing.T) {
		tok, err := cwtToken(uri, claims(map[int]any{cwtClaimExp: float64(now.Add(time.Hour).Unix()) + 0.5}))
		require.NoError(t, err)
		assert.WithinDuration(t, now.Add(time.Hour), tok.exp, 2*time.Second)
	})

	t.Run("integer widths are accepted", func(t *testing.T) {
		for _, exp := range []any{int64(now.Add(time.Hour).Unix()), uint64(now.Add(time.Hour).Unix()), int(now.Add(time.Hour).Unix())} {
			tok, err := cwtToken(uri, claims(map[int]any{cwtClaimExp: exp}))
			require.NoError(t, err, "%T", exp)
			assert.False(t, tok.exp.IsZero())
		}
	})

	t.Run("present but non-numeric exp is rejected", func(t *testing.T) {
		for _, exp := range []any{"tomorrow", []byte{1}, math.NaN(), math.Inf(1), nil} {
			_, err := cwtToken(uri, claims(map[int]any{cwtClaimExp: exp}))
			require.Error(t, err, "%v", exp)
			assert.Contains(t, err.Error(), "invalid exp")
		}
	})

	t.Run("ttl accepts integers and floats", func(t *testing.T) {
		tok, err := cwtToken(uri, claims(map[int]any{cwtClaimTTL: int64(60)}))
		require.NoError(t, err)
		assert.Equal(t, time.Minute, tok.ttl)

		tok, err = cwtToken(uri, claims(map[int]any{cwtClaimTTL: 1.5}))
		require.NoError(t, err)
		assert.Equal(t, 1500*time.Millisecond, tok.ttl)
	})

	t.Run("present but invalid ttl is rejected", func(t *testing.T) {
		for _, ttl := range []any{"soon", -1, math.NaN(), 1e30} {
			_, err := cwtToken(uri, claims(map[int]any{cwtClaimTTL: ttl}))
			require.Error(t, err, "%v", ttl)
			assert.Contains(t, err.Error(), "invalid ttl")
		}
	})

	t.Run("absent exp and ttl are fine", func(t *testing.T) {
		tok, err := cwtToken(uri, claims(nil))
		require.NoError(t, err)
		assert.True(t, tok.exp.IsZero())
		assert.Zero(t, tok.ttl)
	})
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
	statusCache := cache.NewMemoryCache[[]uint8](life, cache.WithAbsoluteExpiry())
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
