package apiv1

import (
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDCAPIOrigin covers what gets bound into a DC API session transcript.
// It comes from configuration, never from the caller: the origin is the
// substance of that handover, so letting a caller supply it would be the
// same as not binding at all.
func TestDCAPIOrigin(t *testing.T) {
	client := func(publicURL string) *Client {
		return &Client{cfg: &model.Cfg{Verifier: &model.Verifier{PublicURL: publicURL}}}
	}

	for _, tc := range []struct {
		name      string
		publicURL string
		want      string
		wantErr   string
	}{
		{name: "scheme and host", publicURL: "https://verifier.example.com", want: "https://verifier.example.com"},
		{name: "a path is dropped", publicURL: "https://verifier.example.com/verification/x", want: "https://verifier.example.com"},
		{name: "a port is part of the origin", publicURL: "https://verifier.example.com:8443/", want: "https://verifier.example.com:8443"},

		// RFC 6454 §6.2. The wallet compares expected_origins against the
		// Origin the browser reports, as a plain string, so every spelling
		// configuration permits that a browser never emits has to be
		// normalised here or a correct deployment is refused. The default
		// port is the one that bites first: an operator writing :443 is
		// being precise, not wrong.
		{name: "the default https port is dropped, as a browser drops it", publicURL: "https://verifier.example.com:443/", want: "https://verifier.example.com"},
		{name: "the default http port is dropped too", publicURL: "http://verifier.example.com:80", want: "http://verifier.example.com"},
		{name: "a non-default port survives on http", publicURL: "http://verifier.example.com:8080", want: "http://verifier.example.com:8080"},
		{name: "the host is lowercased", publicURL: "https://Verifier.Example.COM", want: "https://verifier.example.com"},
		{name: "the scheme is lowercased", publicURL: "HTTPS://verifier.example.com", want: "https://verifier.example.com"},
		{name: "all three at once, the config that reads as valid and was refused", publicURL: "HTTPS://Verifier.Example.COM:443/ui", want: "https://verifier.example.com"},
		{name: "an IPv6 literal keeps its brackets", publicURL: "https://[2001:db8::1]:8443", want: "https://[2001:db8::1]:8443"},
		{name: "an IPv6 literal loses the default port, keeps the brackets", publicURL: "https://[2001:db8::1]:443", want: "https://[2001:db8::1]"},

		{name: "unset is refused", publicURL: "", wantErr: "not set"},
		{name: "no scheme is refused", publicURL: "verifier.example.com", wantErr: "no scheme or host"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := client(tc.publicURL).dcAPIOrigin()
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
