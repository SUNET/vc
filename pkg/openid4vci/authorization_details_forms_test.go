package openid4vci

import (
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadAuthorizationDetailsLenient(t *testing.T) {
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
			err := r.ReadAuthorizationDetails(tt.values, true)
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
func TestReadAuthorizationDetailsLeavesADecodedRequestAlone(t *testing.T) {
	r := &PARRequest{
		AuthorizationDetails: []AuthorizationDetailsParameter{
			{Type: "openid_credential", CredentialConfigurationID: "pid"},
		},
	}

	require.NoError(t, r.ReadAuthorizationDetails(url.Values{
		AuthorizationDetailsBracketKey: {`{"type":"openid_credential","credential_configuration_id":"attacker"}`},
	}, true))

	require.Len(t, r.AuthorizationDetails, 1)
	assert.Equal(t, "pid", r.AuthorizationDetails[0].CredentialConfigurationID)
	assert.Empty(t, r.AuthorizationDetailsRaw)
}

// A nil receiver is a no-op rather than a panic, matching
// ParseAuthorizationDetails.
func TestReadAuthorizationDetailsNilReceiver(t *testing.T) {
	var r *PARRequest
	assert.NoError(t, r.ReadAuthorizationDetails(url.Values{"authorization_details": {"[]"}}, true))
}

// Strictly, a repeated parameter is refused rather than silently reduced to
// its first value: RFC 6749 §3.1 says a request parameter MUST NOT be
// included more than once, and gin binds only the first.
func TestReadAuthorizationDetailsStrict(t *testing.T) {
	const pid = `{"type":"openid_credential","credential_configuration_id":"pid"}`

	tts := []struct {
		name   string
		values url.Values
		errStr string
	}{
		{
			name:   "one value is accepted",
			values: url.Values{"authorization_details": {"[" + pid + "]"}},
		},
		{
			name:   "no value is accepted",
			values: url.Values{"client_id": {"wallet"}},
		},
		{
			// The case that used to slip through: the first value is a
			// well-formed array, so every later check passes and the second
			// value simply vanishes.
			name:   "a valid array followed by a second value is refused",
			values: url.Values{"authorization_details": {"[" + pid + "]", pid}},
			errStr: "more than once",
		},
		{
			name:   "two values are refused",
			values: url.Values{"authorization_details": {pid, pid}},
			errStr: "more than once",
		},
		{
			// Not a parameter this issuer defines, so OAuth says to ignore
			// it - which is what leaving AuthorizationDetailsRaw alone does.
			name:   "a bracketed key is ignored",
			values: url.Values{AuthorizationDetailsBracketKey: {pid, pid}},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			r := &PARRequest{}
			err := r.ReadAuthorizationDetails(tt.values, false)
			if tt.errStr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errStr)
				return
			}
			require.NoError(t, err)
			// Strictly, this function never writes: whatever gin bound stands.
			assert.Empty(t, r.AuthorizationDetailsRaw)
		})
	}
}
