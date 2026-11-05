package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIssuerMetadataAdvertisesTheNotificationEndpoint: the Notification Endpoint is
// registered on the same root as /nonce and /credential whatever the configuration
// says, so the metadata says so. Omitting it tells a wallet this issuer has none
// (OpenID4VCI 11), and a credential response that carries a notification_id - as a
// delivered auxiliary-data opening does, so the wallet can report a failed commitment
// check - would then name an identifier with nowhere to send it.
func TestIssuerMetadataAdvertisesTheNotificationEndpoint(t *testing.T) {
	const publicURL = "https://issuer.example"

	t.Run("derived from the public URL when unconfigured", func(t *testing.T) {
		md := &IssuerMetadata{}
		got, err := md.Generate(t.Context(), publicURL, nil)
		require.NoError(t, err)
		assert.Equal(t, publicURL+"/notification", got.NotificationEndpoint)
	})

	t.Run("a configured endpoint still wins", func(t *testing.T) {
		md := &IssuerMetadata{NotificationEndpoint: "https://elsewhere.example/notify"}
		got, err := md.Generate(t.Context(), publicURL, nil)
		require.NoError(t, err)
		assert.Equal(t, "https://elsewhere.example/notify", got.NotificationEndpoint)
	})
}
