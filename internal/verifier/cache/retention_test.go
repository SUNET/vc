package cache

import (
	"testing"
	"time"

	"github.com/SUNET/vc/internal/verifier/db"
	pkgcache "github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func cfgWith(presentationTimeout, codeDuration int) *model.Cfg {
	cfg := &model.Cfg{Verifier: &model.Verifier{}, Common: &model.Common{}}
	cfg.Verifier.Inbound.OpenID4VP = &model.OpenID4VPConfig{PresentationTimeout: presentationTimeout}
	cfg.Verifier.Outbound.OIDCProvider = &model.OIDCOP{CodeDuration: codeDuration}
	return cfg
}

// The authorization context has to outlive the deadlines that are checked
// against it. Evicting earlier makes a session that is still valid come back
// as "session not found" partway through a flow.
//
// Before presentation_timeout was read, both deadlines came from
// code_duration and the retention was a flat 15 minutes that happened to
// cover them. Now an operator can set a presentation window of their own,
// so the retention follows the deadlines (SUNET/vc#756).
func TestAuthContextRetentionOutlivesTheDeadlinesItHolds(t *testing.T) {
	for _, tc := range []struct {
		name                              string
		presentationTimeout, codeDuration int
		want                              time.Duration
	}{
		// 300 + 300 = 10 minutes, under the floor: the default
		// configuration retains for exactly as long as it always has.
		{"defaults keep the old 15 minutes", 300, 300, 15 * time.Minute},
		{"short values do not shrink it", 10, 10, 15 * time.Minute},
		// 30 minutes of presenting cannot be held by a 15-minute cache.
		{"a long presentation window stretches it", 1800, 300, 36 * time.Minute},
		{"a long code duration stretches it", 300, 3600, 66 * time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := cfgWith(tc.presentationTimeout, tc.codeDuration)

			got := authContextRetention(cfg)
			assert.Equal(t, tc.want, got)

			deadlines := cfg.Verifier.Inbound.OpenID4VP.GetPresentationTimeout() +
				time.Duration(tc.codeDuration)*time.Second
			assert.Greater(t, got, deadlines,
				"a code issued at the deadline would be evicted in the same second")
		})
	}
}

// An absent oidc_provider section must not collapse the retention to the
// presentation window alone.
func TestAuthContextRetentionWithoutAnOIDCProvider(t *testing.T) {
	cfg := &model.Cfg{Verifier: &model.Verifier{}}
	cfg.Verifier.Inbound.OpenID4VP = &model.OpenID4VPConfig{PresentationTimeout: 1800}

	assert.Equal(t, 31*time.Minute, authContextRetention(cfg))
}

// The retention the service actually hands the store, not just what the
// helper computes.
//
// Testing authContextRetention alone proves nothing about the cache: the
// call site is where the 15-minute literal lived, and a literal put back
// there leaves the helper correct and unused.
func TestTheAuthContextStoreGetsTheDerivedRetention(t *testing.T) {
	cfg := cfgWith(1800, 300)

	// HA off, so the store is in-memory and no Mongo is involved.
	svc, err := New(t.Context(), cfg, &db.Service{}, nil, logger.NewSimple("test"))
	require.NoError(t, err)

	store, ok := svc.AuthContext.(*pkgcache.MemoryStore)
	require.True(t, ok, "expected the non-HA in-memory store")

	assert.Equal(t, authContextRetention(cfg), store.TTL())
	assert.Equal(t, 36*time.Minute, store.TTL(),
		"the store did not get the configured retention")
}

// A live presentation also depends on the request object the wallet
// resolves its request URI from, and on the ephemeral key it encrypts its
// response to. Those sat at 5 and 10 minutes while only the auth context
// followed the configured window, so with a 30-minute presentation the
// request URI stopped resolving after five minutes and encrypted responses
// stopped decrypting after ten - with ExpiresAt still saying the session
// was live (SUNET/vc#756).
func TestSupportingCachesOutliveThePresentationWindow(t *testing.T) {
	long := cfgWith(1800, 300)

	assert.Equal(t, 30*time.Minute, PresentationScopedTTL(long, 5*time.Minute),
		"the request object expires before the presentation it belongs to")
	assert.Equal(t, 30*time.Minute, PresentationScopedTTL(long, 10*time.Minute),
		"the ephemeral key expires before the presentation it belongs to")

	// The floors still hold, so a short window does not shorten them.
	short := cfgWith(60, 300)
	assert.Equal(t, 5*time.Minute, PresentationScopedTTL(short, 5*time.Minute))
	assert.Equal(t, 10*time.Minute, PresentationScopedTTL(short, 10*time.Minute))

	// Defaults are unchanged: 300s presentation against the old literals.
	assert.Equal(t, 5*time.Minute, PresentationScopedTTL(cfgWith(300, 300), 5*time.Minute))
	assert.Equal(t, 10*time.Minute, PresentationScopedTTL(cfgWith(300, 300), 10*time.Minute))

	assert.Equal(t, 5*time.Minute, PresentationScopedTTL(nil, 5*time.Minute))
}

// ... and the caches the service builds really get it.
func TestTheSupportingCachesAreBuiltWithThatTTL(t *testing.T) {
	cfg := cfgWith(1800, 300)

	svc, err := New(t.Context(), cfg, &db.Service{}, nil, logger.NewSimple("test"))
	require.NoError(t, err)

	for name, c := range map[string]any{
		"request objects": svc.RequestObject,
		"ephemeral keys":  svc.EphemeralEncryptionKey,
	} {
		t.Run(name, func(t *testing.T) {
			mem, ok := c.(interface{ TTL() time.Duration })
			require.True(t, ok, "expected the non-HA in-memory cache")
			assert.Equal(t, 30*time.Minute, mem.TTL())
		})
	}
}
