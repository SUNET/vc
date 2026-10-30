package cache_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/openid4vci"
)

// logAndRead logs kv at debug level and returns the written log file.
func logAndRead(t *testing.T, msg string, kv ...any) string {
	t.Helper()
	dir := t.TempDir()
	log, err := logger.New("probe", dir, false)
	require.NoError(t, err)
	log.Debug(msg, kv...)
	out, err := os.ReadFile(filepath.Join(dir, "probe.log"))
	require.NoError(t, err)
	return string(out)
}

func TestAnAuthorizationContextRedactsItselfInALog(t *testing.T) {
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
		SessionID: "sess-1", ClientID: "client-1",
		AccessToken: secrets["access token"], RefreshToken: secrets["refresh token"],
		IDToken: secrets["id token"], Code: secrets["authorization code"],
		TXCode: secrets["tx code"], VPToken: secrets["vp token"],
		Token:          &cache.Token{AccessToken: secrets["nested access token"]},
		VerifiedClaims: map[string]any{"personal_administrative_number": secrets["a verified claim"]},
	}

	// The whole struct, as several call sites log it.
	out := logAndRead(t, "ctx", "auth", ctx)

	for what, value := range secrets {
		require.NotContainsf(t, out, value, "the %s reached the log", what)
	}
	require.Contains(t, out, "sess-1", "the session id is what the line is for")
	require.Contains(t, out, "has_access_token", "whether a token exists is useful; its value is not")
	require.Contains(t, out, "personal_administrative_number",
		"the claim NAMES are useful and are not the holder's data; the values are")
}

func TestATokenResponseRedactsItselfInALog(t *testing.T) {
	reply := &openid4vci.TokenResponse{
		AccessToken: "AT-eyJhbGciOiJFUzI1NiJ9", TokenType: "DPoP", ExpiresIn: 3600,
		Scope: "nym_auth", CNonce: "NONCE-c0ffee", RefreshToken: "RT-r3fr3sh",
	}
	out := logAndRead(t, "Token endpoint", "reply", reply)

	require.NotContains(t, out, "AT-eyJhbGciOiJFUzI1NiJ9", "the access token reached the log")
	require.NotContains(t, out, "NONCE-c0ffee", "the c_nonce reached the log")
	require.NotContains(t, out, "RT-r3fr3sh", "the refresh token reached the log")
	require.Contains(t, out, "DPoP")
	require.Contains(t, out, "nym_auth")
}

// A nil pointer logs without panicking.
func TestRedactionHandlesNil(t *testing.T) {
	require.NotPanics(t, func() {
		logAndRead(t, "nil", "auth", (*cache.AuthorizationContext)(nil), "reply", (*openid4vci.TokenResponse)(nil))
	})
}
