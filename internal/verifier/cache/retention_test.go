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
		{"a long presentation window stretches it", 1800, 300, 35 * time.Minute},
		{"a long code duration stretches it", 300, 3600, 65 * time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := cfgWith(tc.presentationTimeout, tc.codeDuration)

			got := authContextRetention(cfg)
			assert.Equal(t, tc.want, got)

			deadlines := cfg.Verifier.Inbound.OpenID4VP.GetPresentationTimeout() +
				time.Duration(tc.codeDuration)*time.Second
			assert.GreaterOrEqual(t, got, deadlines,
				"a session would be evicted while its code is still valid")
		})
	}
}

// An absent oidc_provider section must not collapse the retention to the
// presentation window alone.
func TestAuthContextRetentionWithoutAnOIDCProvider(t *testing.T) {
	cfg := &model.Cfg{Verifier: &model.Verifier{}}
	cfg.Verifier.Inbound.OpenID4VP = &model.OpenID4VPConfig{PresentationTimeout: 1800}

	assert.Equal(t, 30*time.Minute, authContextRetention(cfg))
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
	assert.Equal(t, 35*time.Minute, store.TTL(),
		"the store did not get the configured retention")
}
