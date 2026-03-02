package oauth2

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

var mockClients = Clients{
	"client_1": {
		Type:        "public",
		RedirectURI: "https://example.com/callback",
		Scopes:      []string{"ehic", "diploma"},
	},
	"client_2": {
		Type:        "confidential",
		RedirectURI: "https://example.com/callback",
		Scopes:      []string{"diploma", "elm"},
	},
}

func TestAllow(t *testing.T) {
	type want struct {
		client *Client
		err    error
	}
	tts := []struct {
		name        string
		clientID    string
		redirectURI string
		scope       string
		clients     Clients
		want        want
	}{
		{
			name:        "valid public client",
			clientID:    "client_1",
			redirectURI: "https://example.com/callback",
			scope:       "ehic",
			clients:     mockClients,
			want:        want{client: mockClients["client_1"], err: nil},
		},
		{
			name:        "valid confidential client",
			clientID:    "client_2",
			redirectURI: "https://example.com/callback",
			scope:       "diploma",
			clients:     mockClients,
			want:        want{client: mockClients["client_2"], err: nil},
		},
		{
			name:        "invalid scope",
			clientID:    "client_2",
			redirectURI: "https://example.com/callback",
			scope:       "el",
			clients:     mockClients,
			want:        want{client: nil, err: errors.New("requested scope is not allowed for this client")},
		},
		{
			name:        "client not in config",
			clientID:    "client_not_in_dataset",
			redirectURI: "https://example.com/callback",
			scope:       "openid",
			clients:     mockClients,
			want:        want{client: nil, err: errors.New("client not found in config")},
		},
		{
			name:        "redirect url trailing slash",
			clientID:    "client_1",
			redirectURI: "https://example.com/callback/",
			scope:       "ehic",
			clients:     mockClients,
			want:        want{client: nil, err: errors.New("redirect_url do not match")},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.clients.Allow(tt.clientID, tt.redirectURI, tt.scope)
			assert.Equal(t, tt.want.client, got)
			assert.Equal(t, tt.want.err, err)
		})
	}
}

func TestGet(t *testing.T) {
	t.Run("existing client", func(t *testing.T) {
		client, err := mockClients.Get("client_1")
		assert.NoError(t, err)
		assert.Equal(t, mockClients["client_1"], client)
	})

	t.Run("non-existing client", func(t *testing.T) {
		client, err := mockClients.Get("unknown")
		assert.Nil(t, client)
		assert.EqualError(t, err, "client not found in config")
	})
}
