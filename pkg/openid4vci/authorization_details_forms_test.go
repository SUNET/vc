package openid4vci

import (
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMergeNonStandardAuthorizationDetails(t *testing.T) {
	const pid = `{"type":"openid_credential","credential_configuration_id":"pid"}`
	const ehic = `{"type":"openid_credential","credential_configuration_id":"ehic"}`

	tts := []struct {
		name   string
		values url.Values
		want   string
		errStr string
	}{
		{
			name:   "no authorization_details leaves the request alone",
			values: url.Values{"client_id": {"wallet"}},
			want:   "",
		},
		{
			name:   "the specified single-array encoding passes through verbatim",
			values: url.Values{"authorization_details": {"[" + pid + "]"}},
			want:   "[" + pid + "]",
		},
		{
			name:   "repeated keys become one array, in order",
			values: url.Values{"authorization_details": {pid, ehic}},
			want:   "[" + pid + "," + ehic + "]",
		},
		{
			name:   "bracketed keys become one array, in order",
			values: url.Values{AuthorizationDetailsBracketKey: {pid, ehic}},
			want:   "[" + pid + "," + ehic + "]",
		},
		{
			name: "both spellings at once keep the plain key first",
			values: url.Values{
				"authorization_details":        {pid},
				AuthorizationDetailsBracketKey: {ehic},
			},
			want: "[" + pid + "," + ehic + "]",
		},
		{
			name:   "an array under a bracketed key is spliced, not nested",
			values: url.Values{AuthorizationDetailsBracketKey: {"[" + pid + "]", ehic}},
			want:   "[" + pid + "," + ehic + "]",
		},
		{
			name:   "a lone object is wrapped",
			values: url.Values{"authorization_details": {pid}},
			want:   "[" + pid + "]",
		},
		{
			name:   "a value that is not an object or array is refused",
			values: url.Values{AuthorizationDetailsBracketKey: {`"pid"`}},
			errStr: "must be a JSON object or array",
		},
		{
			name:   "a malformed object is refused",
			values: url.Values{AuthorizationDetailsBracketKey: {pid, `{"type":`}},
			errStr: "not valid JSON",
		},
		{
			name:   "a malformed array among several values is refused",
			values: url.Values{AuthorizationDetailsBracketKey: {`[` + pid, ehic}},
			errStr: "parse",
		},
		{
			// A single array is the specified encoding, so it is handed on
			// unchanged - including when it is malformed. The strict parser
			// downstream owns that error, and this keeps the two paths from
			// reporting the same problem differently.
			name:   "a single malformed array is left to the strict parser",
			values: url.Values{"authorization_details": {`[` + pid}},
			want:   `[` + pid,
		},
		{
			name:   "only empty values is refused",
			values: url.Values{AuthorizationDetailsBracketKey: {"", "  "}},
			errStr: "authorization_details is empty",
		},
		{
			name: "the size cap counts every value, not just the biggest",
			values: url.Values{AuthorizationDetailsBracketKey: {
				strings.Repeat("a", maxAuthorizationDetailsBytes/2+1),
				strings.Repeat("b", maxAuthorizationDetailsBytes/2+1),
			}},
			errStr: "exceeds",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			r := &PARRequest{}
			err := r.MergeNonStandardAuthorizationDetails(tt.values)
			if tt.errStr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errStr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, r.AuthorizationDetailsRaw)
		})
	}
}

// A request whose details a JSON binder already decoded is not re-read from
// the query string, so query parameters cannot override a JSON body.
func TestMergeNonStandardAuthorizationDetailsLeavesADecodedRequestAlone(t *testing.T) {
	r := &PARRequest{
		AuthorizationDetails: []AuthorizationDetailsParameter{
			{Type: "openid_credential", CredentialConfigurationID: "pid"},
		},
	}

	require.NoError(t, r.MergeNonStandardAuthorizationDetails(url.Values{
		AuthorizationDetailsBracketKey: {`{"type":"openid_credential","credential_configuration_id":"attacker"}`},
	}))

	require.Len(t, r.AuthorizationDetails, 1)
	assert.Equal(t, "pid", r.AuthorizationDetails[0].CredentialConfigurationID)
	assert.Empty(t, r.AuthorizationDetailsRaw)
}

// A nil receiver is a no-op rather than a panic, matching
// ParseAuthorizationDetails.
func TestMergeNonStandardAuthorizationDetailsNilReceiver(t *testing.T) {
	var r *PARRequest
	assert.NoError(t, r.MergeNonStandardAuthorizationDetails(url.Values{"authorization_details": {"[]"}}))
}
