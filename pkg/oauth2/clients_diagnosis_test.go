package oauth2

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Allow's caller falls back to wallet attestation when it returns an error,
// so an unknown client_id is ordinary operation while a CONFIGURED client
// that still fails is a mismatch somebody has to fix. Both used to be
// undifferentiated errors, so the second was indistinguishable from the
// first: it fell through silently, and whatever the attestation path
// reported next said nothing about the redirect_uri that did not match.
func TestAllowDistinguishesAnUnknownClientFromARejectedOne(t *testing.T) {
	_, err := mockClients.Allow("client_not_in_dataset", "https://example.com/callback", "openid")
	require.ErrorIs(t, err, ErrClientNotFound,
		"an unknown client_id is the normal attestation fall-through")

	for name, tc := range map[string]struct{ clientID, redirectURI, scope string }{
		"redirect_uri mismatch":  {"client_1", "https://attacker.example/cb", "ehic"},
		"scope not allowed":      {"client_2", "https://example.com/callback", "el"},
		"no redirect configured": {"client_no_redirect", "https://example.com/callback", "ehic"},
	} {
		t.Run(name+" is not reported as an unknown client", func(t *testing.T) {
			_, err := mockClients.Allow(tc.clientID, tc.redirectURI, tc.scope)
			require.Error(t, err)
			require.False(t, errors.Is(err, ErrClientNotFound),
				"this client IS configured; reporting it as not-found hides the real reason")
			require.Contains(t, err.Error(), tc.clientID,
				"the error must name the client, so a log line identifies which config entry")
		})
	}
}

// The value that did not match has to appear, or an operator debugging an
// interop failure is left guessing which of several configured URIs was
// expected. That was the whole of issue #709.
func TestAllowNamesTheRejectedValue(t *testing.T) {
	const attempted = "https://wallet.example.net/cb"
	_, err := mockClients.Allow("client_1", attempted, "ehic")
	require.Error(t, err)
	require.Contains(t, err.Error(), attempted, "the attempted redirect_uri must be in the message")
	require.Contains(t, err.Error(), "https://example.com/callback", "and what was allowed instead")

	_, err = mockClients.Allow("client_2", "https://example.com/callback", "nosuchscope")
	require.Error(t, err)
	require.Contains(t, err.Error(), "nosuchscope", "the rejected scope must be in the message")
	require.True(t, strings.Contains(err.Error(), "diploma") && strings.Contains(err.Error(), "elm"),
		"and the scopes that were allowed")
}
