package oauth2

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

var mockClients = Clients{
	"client_1": {
		Type:         "public",
		RedirectURIs: RedirectURIs{"https://example.com/callback"},
		Scopes:       []string{"ehic", "diploma"},
	},
	"client_2": {
		Type:         "confidential",
		RedirectURIs: RedirectURIs{"https://example.com/callback"},
		Scopes:       []string{"diploma", "elm"},
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
			want:        want{client: nil, err: errors.New("redirect_uri does not match any allowed URI")},
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

func TestRedirectURIsContains(t *testing.T) {
	tts := []struct {
		name     string
		uris     RedirectURIs
		check    string
		expected bool
	}{
		{
			name:     "exact match",
			uris:     RedirectURIs{"https://example.com/callback"},
			check:    "https://example.com/callback",
			expected: true,
		},
		{
			name:     "no match",
			uris:     RedirectURIs{"https://example.com/callback"},
			check:    "https://other.com/callback",
			expected: false,
		},
		{
			name:     "wildcard prefix match",
			uris:     RedirectURIs{"https://example.com/test/a/*"},
			check:    "https://example.com/test/a/some-alias/callback",
			expected: true,
		},
		{
			name:     "wildcard wrong host",
			uris:     RedirectURIs{"https://example.com/test/a/*"},
			check:    "https://evil.com/test/a/some-alias/callback",
			expected: false,
		},
		{
			name:     "wildcard wrong scheme",
			uris:     RedirectURIs{"https://example.com/test/a/*"},
			check:    "http://example.com/test/a/some-alias/callback",
			expected: false,
		},
		{
			name:     "multiple uris first matches",
			uris:     RedirectURIs{"https://example.com/cb", "https://other.com/cb"},
			check:    "https://example.com/cb",
			expected: true,
		},
		{
			name:     "multiple uris second matches",
			uris:     RedirectURIs{"https://example.com/cb", "https://other.com/cb"},
			check:    "https://other.com/cb",
			expected: true,
		},
		{
			name:     "fragment in URI rejected",
			uris:     RedirectURIs{"https://example.com/callback"},
			check:    "https://example.com/callback#frag",
			expected: false,
		},
		{
			name:     "fragment in wildcard URI rejected",
			uris:     RedirectURIs{"https://example.com/test/a/*"},
			check:    "https://example.com/test/a/cb#frag",
			expected: false,
		},
		{
			name:     "root wildcard matches deep path",
			uris:     RedirectURIs{"https://example.com/*"},
			check:    "https://example.com/any/path/here",
			expected: true,
		},
		{
			name:     "root wildcard matches root",
			uris:     RedirectURIs{"https://example.com/*"},
			check:    "https://example.com/",
			expected: true,
		},
		{
			name:     "wildcard path traversal rejected",
			uris:     RedirectURIs{"https://example.com/test/a/*"},
			check:    "https://example.com/test/a/../evil",
			expected: false,
		},
		{
			name:     "wildcard matches exact prefix path",
			uris:     RedirectURIs{"https://example.com/app/*"},
			check:    "https://example.com/app/",
			expected: true,
		},
		{
			name:     "wildcard matches prefix without trailing slash",
			uris:     RedirectURIs{"https://example.com/app/*"},
			check:    "https://example.com/app",
			expected: true,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.uris.Contains(tt.check))
		})
	}
}
