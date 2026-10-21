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
	"client_no_redirect": {
		Type:         "public",
		RedirectURIs: RedirectURIs{},
		Scopes:       []string{"ehic"},
	},
	"client_nil": nil,
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
			want:        want{client: nil, err: errors.New(`scope "el" is not allowed for client "client_2" (allowed: diploma, elm)`)},
		},
		{
			name:        "client not in config",
			clientID:    "client_not_in_dataset",
			redirectURI: "https://example.com/callback",
			scope:       "openid",
			clients:     mockClients,
			want:        want{client: nil, err: ErrClientNotFound},
		},
		{
			name:        "redirect url trailing slash",
			clientID:    "client_1",
			redirectURI: "https://example.com/callback/",
			scope:       "ehic",
			clients:     mockClients,
			want:        want{client: nil, err: errors.New(`redirect_uri "https://example.com/callback/" does not match any of the 1 URIs configured for client "client_1" (allowed: https://example.com/callback)`)},
		},
		{
			name:        "client with no redirect URIs configured",
			clientID:    "client_no_redirect",
			redirectURI: "https://example.com/callback",
			scope:       "ehic",
			clients:     mockClients,
			want:        want{client: nil, err: errors.New(`client "client_no_redirect" has no redirect_uri configured`)},
		},
		{
			name:        "nil client value in config",
			clientID:    "client_nil",
			redirectURI: "https://example.com/callback",
			scope:       "ehic",
			clients:     mockClients,
			want:        want{client: nil, err: ErrClientNotFound},
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
			name:     "wildcard path traversal via percent-encoded dot-segments",
			uris:     RedirectURIs{"https://example.com/test/a/*"},
			check:    "https://example.com/test/a/%2e%2e/evil",
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

func TestValidateRedirectURIScheme(t *testing.T) {
	tts := []struct {
		name        string
		redirectURI string
		wantErr     bool
	}{
		{name: "https is allowed", redirectURI: "https://example.com/callback", wantErr: false},
		{name: "http is allowed", redirectURI: "http://example.com/callback", wantErr: false},
		{
			// Native wallet deep-link schemes (RFC 8252) must keep working --
			// this is exactly the shape the EUDI reference wallet uses.
			name:        "custom app scheme is allowed",
			redirectURI: "eu.europa.ec.euidi://authorization",
			wantErr:     false,
		},
		{name: "javascript scheme is rejected", redirectURI: "javascript:alert(document.cookie)", wantErr: true},
		{name: "JAVASCRIPT scheme is rejected case-insensitively", redirectURI: "JAVASCRIPT:alert(1)", wantErr: true},
		{name: "data scheme is rejected", redirectURI: "data:text/html,<script>alert(1)</script>", wantErr: true},
		{name: "vbscript scheme is rejected", redirectURI: "vbscript:msgbox(1)", wantErr: true},
		{name: "file scheme is rejected", redirectURI: "file:///etc/passwd", wantErr: true},
		{name: "no scheme is rejected", redirectURI: "//example.com/callback", wantErr: true},
		{name: "empty string is rejected", redirectURI: "", wantErr: true},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRedirectURIScheme(tt.redirectURI)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// The Authorization Challenge Endpoint is browserless, so a registered
// wallet may have no callback at all - draft-ietf-oauth-first-party-apps
// makes redirect_uri optional on its request. Validating such a wallet
// through Allow refused it with a redirect_uri mismatch, and the only way
// past that was a wallet attestation the deployment may not use.
//
// The requirement is dropped; the check is not. A redirect_uri that IS
// sent must still match, because a wrong one is wrong on any endpoint.
func TestAllowWithoutRedirect(t *testing.T) {
	clients := Clients{"wallet-1": {
		RedirectURIs: RedirectURIs{"https://wallet.example/cb"},
		Scopes:       []string{"pid"},
	}}

	// The precondition that makes the rest meaningful: Allow really does
	// refuse this wallet when it sends no redirect_uri.
	if _, err := clients.Allow("wallet-1", "", "pid"); err == nil {
		t.Fatal("Allow must still require a redirect_uri; this test is about the variant that does not")
	}

	if _, err := clients.AllowWithoutRedirect("wallet-1", "", "pid"); err != nil {
		t.Fatalf("a browserless request from a registered wallet must be allowed: %v", err)
	}

	// Sent and correct.
	if _, err := clients.AllowWithoutRedirect("wallet-1", "https://wallet.example/cb", "pid"); err != nil {
		t.Fatalf("a matching redirect_uri must still be allowed: %v", err)
	}

	// Sent and wrong: still refused, which is the half that must not be
	// lost. Dropping the requirement is not dropping the check.
	if _, err := clients.AllowWithoutRedirect("wallet-1", "https://attacker.example/cb", "pid"); err == nil {
		t.Fatal("a redirect_uri that does not match must be refused even where one is optional")
	}

	// And the scope is validated either way.
	if _, err := clients.AllowWithoutRedirect("wallet-1", "", "not-allowed"); err == nil {
		t.Fatal("the scope check must survive")
	}
	if _, err := clients.AllowWithoutRedirect("unknown", "", "pid"); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("an unknown client must still be ErrClientNotFound, got %v", err)
	}
}
