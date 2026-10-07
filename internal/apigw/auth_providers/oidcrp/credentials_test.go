package oidcrp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"golang.org/x/oauth2"
)

func bundle(clientID string, expiresAt time.Time) *credentials {
	return &credentials{
		clientID:  clientID,
		expiresAt: expiresAt,
		config:    &oauth2.Config{ClientID: clientID},
	}
}

// An authorization code is issued to a specific client, so a flow that
// began before a renewal has to finish on the client that began it - the
// OP rejects the exchange otherwise, and the ID token's `aud` names the
// old client too.
func TestCredentialSetKeepsASupersededRegistrationForInFlightFlows(t *testing.T) {
	set := newCredentialSet(time.Hour)

	old := bundle("client-0", time.Now().Add(time.Minute))
	set.store(old)
	require.Equal(t, old, set.load())

	fresh := bundle("client-1", time.Now().Add(time.Hour))
	set.store(fresh)

	assert.Equal(t, fresh, set.load(), "new flows start on the new client")
	assert.Equal(t, old, set.forClient("client-0"), "a flow already in progress finishes on its own")
	assert.Equal(t, fresh, set.forClient("client-1"))
}

// A session created before the client id was recorded has none, and must
// still work the way it did before - on the current registration.
func TestCredentialSetFallsBackForASessionWithNoClientID(t *testing.T) {
	set := newCredentialSet(time.Hour)
	fresh := bundle("client-1", time.Now().Add(time.Hour))
	set.store(fresh)

	assert.Equal(t, fresh, set.forClient(""))
	assert.Equal(t, fresh, set.forClient("a-client-nobody-has-heard-of"))
}

// Superseded registrations are kept for the length of a flow, not forever.
func TestCredentialSetDropsSupersededRegistrationsAfterTheRetainWindow(t *testing.T) {
	set := newCredentialSet(time.Millisecond)

	set.store(bundle("client-0", time.Now().Add(time.Hour)))
	set.store(bundle("client-1", time.Now().Add(time.Hour)))
	require.NotNil(t, set.forClient("client-0"))

	time.Sleep(5 * time.Millisecond)
	set.store(bundle("client-2", time.Now().Add(time.Hour)))

	assert.Equal(t, "client-2", set.forClient("client-0").clientID,
		"an aged-out registration falls back to the current one")
	assert.Equal(t, "client-1", set.forClient("client-1").clientID,
		"the one just retired is still available")
}

// Re-storing the same client id must not retire it into its own history.
func TestCredentialSetDoesNotRetireTheSameClient(t *testing.T) {
	set := newCredentialSet(time.Hour)

	set.store(bundle("client-0", time.Now().Add(time.Hour)))
	second := bundle("client-0", time.Now().Add(2*time.Hour))
	set.store(second)

	assert.Equal(t, second, set.forClient("client-0"))
	assert.Empty(t, set.retired)
}

// retain must drop aged-out entries too, not only store: a callback-heavy
// replica reaches retain far more often, and without pruning there it would
// keep one bundle per remote renewal forever.
func TestCredentialSetRetainPrunesAgedEntries(t *testing.T) {
	set := newCredentialSet(time.Millisecond)

	set.retain(bundle("remote-0", time.Now().Add(time.Hour)))
	require.Len(t, set.retired, 1)

	time.Sleep(5 * time.Millisecond)
	set.retain(bundle("remote-1", time.Now().Add(time.Hour)))

	_, stillThere := set.retired["remote-0"]
	assert.False(t, stillThere, "the aged-out entry should have been pruned by the next retain")
	_, kept := set.retired["remote-1"]
	assert.True(t, kept)
}

func TestCredentialsNeedsRenewal(t *testing.T) {
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

	for name, tc := range map[string]struct {
		creds *credentials
		want  bool
	}{
		"nil": {creds: nil, want: false},
		"never expires": {
			creds: &credentials{},
			want:  false,
		},
		"expires well beyond the window": {
			creds: &credentials{expiresAt: now.Add(24 * time.Hour)},
			want:  false,
		},
		"inside the window": {
			creds: &credentials{expiresAt: now.Add(clientSecretRenewBefore / 2)},
			want:  true,
		},
		"already expired": {
			creds: &credentials{expiresAt: now.Add(-time.Hour)},
			want:  true,
		},
		// A long configured session widens the lead past the default five
		// minutes, so a secret still half an hour out already needs renewing.
		"long session widens the lead": {
			creds: &credentials{expiresAt: now.Add(30 * time.Minute), renewLead: time.Hour},
			want:  true,
		},
		// The floor: an OP handing out short-lived secrets would otherwise
		// never produce one this service calls fresh, and every request
		// would register another client.
		"inside the window but renewed moments ago": {
			creds: &credentials{
				expiresAt:      now.Add(clientSecretRenewBefore / 2),
				renewNotBefore: now.Add(time.Minute),
			},
			want: false,
		},
		"floor elapsed": {
			creds: &credentials{
				expiresAt:      now.Add(clientSecretRenewBefore / 2),
				renewNotBefore: now.Add(-time.Second),
			},
			want: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.creds.needsRenewal(now))
		})
	}
}
