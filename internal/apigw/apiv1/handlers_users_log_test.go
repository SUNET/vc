package apiv1

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/logger"
)

// An AuthorizationContext is not a log value.
//
// It carries live credentials - Token.AccessToken, AccessToken,
// RefreshToken, IDToken, Code, TXCode, VPToken - and the holder's
// verified claims. Handing the struct to the logger renders every
// exported field, so one `log.Debug("auth", ctx)` puts bearer tokens in
// the log of any deployment running at debug level.
//
// Asserted on what is actually WRITTEN rather than on the call site,
// because the failure is in the rendering: the call looks harmless.
func TestAnAuthorizationContextIsNeverLoggedWhole(t *testing.T) {
	dir := t.TempDir()
	log, err := logger.New("probe", dir, false)
	require.NoError(t, err)

	secrets := map[string]string{
		"access token":        "AT-eyJhbGciOiJFUzI1NiJ9",
		"nested access token": "TOKEN-xyzzy",
		"refresh token":       "RT-r3fr3sh",
		"id token":            "IDT-eyJ",
		"authorization code":  "CODE-abc123",
		"tx code":             "TX-998877",
		"vp token":            "VP-presented",
		"a verified claim":    "PAN-198001011234",
	}
	ctx := &cache.AuthorizationContext{
		SessionID:    "sess-1",
		AccessToken:  secrets["access token"],
		RefreshToken: secrets["refresh token"],
		IDToken:      secrets["id token"],
		Code:         secrets["authorization code"],
		TXCode:       secrets["tx code"],
		VPToken:      secrets["vp token"],
		Token:        &cache.Token{AccessToken: secrets["nested access token"]},
		VerifiedClaims: map[string]any{
			"personal_administrative_number": secrets["a verified claim"],
		},
	}

	// What the handler logs, written the way the handler writes it.
	log.Debug("UserLookup", "session_id", ctx.SessionID, "status", ctx.Status, "scopes", ctx.Scopes)

	written, err := os.ReadFile(filepath.Join(dir, "probe.log"))
	require.NoError(t, err)
	out := string(written)

	require.Contains(t, out, "sess-1", "the session id is the point of the line and must survive")
	for what, value := range secrets {
		require.NotContainsf(t, out, value, "the %s reached the log", what)
	}

	// The shape this replaced is now safe too, because
	// AuthorizationContext redacts itself (pkg/cache/authcontext_log.go).
	//
	// That is the stronger guarantee and the reason the redaction exists:
	// naming fields protects this call site, MarshalLog protects the ones
	// nobody has written yet. An earlier version of this test asserted
	// that the old shape still leaked, as proof it was testing something;
	// adding the redaction made that assertion fire, which is the guard
	// working rather than breaking.
	log.Debug("UserLookup", "auth", ctx)
	after, err := os.ReadFile(filepath.Join(dir, "probe.log"))
	require.NoError(t, err)
	for what, value := range secrets {
		require.NotContainsf(t, string(after), value,
			"the %s reached the log even through the redacting path", what)
	}
	require.True(t, strings.Contains(string(after), "has_access_token"),
		"the redacted form should still say whether a token existed")
}
