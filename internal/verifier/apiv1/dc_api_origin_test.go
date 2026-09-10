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
