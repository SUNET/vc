package apiv1

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/oauth2"
	"github.com/SUNET/vc/pkg/openid4vci"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// logEntry is one line of the production logger's JSON output. Only the
// fields this test asserts on are named; the rest are whatever the call site
// passed.
//
// There is no "warn" level to match on: logger.Log sits on logr, which has
// only Info and Error, so Warn is Info with a "WARN: " prefix on the message
// and Debug is V(1), which the production config drops entirely. Both halves
// of this test depend on that, so it is asserted rather than assumed - see
// TestWarnAndDebugAreDistinguishableInTheLog.
type logEntry struct {
	Level       string `json:"level"`
	Message     string `json:"msg"`
	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri"`
	Scope       string `json:"scope"`
	Reason      string `json:"reason"`
}

// parLoggingClient builds the smallest Client that can reach the rejection
// branch of OAuthPar, logging to a file so the test can read back what an
// operator would see. The production logger is deliberate: it emits JSON and
// drops Debug, which is exactly the threshold this behaviour is about.
func parLoggingClient(t *testing.T, clients oauth2.Clients) (*Client, func() []logEntry) {
	t.Helper()

	dir := t.TempDir()
	log, err := logger.New("partest", dir, true)
	require.NoError(t, err)

	cfg := &model.Cfg{
		Common: &model.Common{},
		APIGW: &model.APIGW{
			PublicURL: "https://issuer.example.com",
			Delivery: model.APIGWDelivery{
				OpenID4VCI: model.OAuthServer{Clients: clients},
			},
		},
	}

	read := func() []logEntry {
		t.Helper()
		f, err := os.Open(filepath.Join(dir, "partest.log"))
		if os.IsNotExist(err) {
			return nil
		}
		require.NoError(t, err)
		defer f.Close()

		var entries []logEntry
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			var entry logEntry
			require.NoError(t, json.Unmarshal(scanner.Bytes(), &entry), "line: %s", scanner.Text())
			entries = append(entries, entry)
		}
		require.NoError(t, scanner.Err())
		return entries
	}

	return &Client{cfg: cfg, log: log.New("apiv1")}, read
}

func warnings(entries []logEntry) []logEntry {
	var out []logEntry
	for _, e := range entries {
		if strings.HasPrefix(e.Message, "WARN: ") {
			out = append(out, e)
		}
	}
	return out
}

// The two assertions below rest on how logger.Log renders the two levels, so
// pin that here: a Warn is visible in the production log and a Debug is not.
// If this stops holding, the tests that follow would pass for the wrong
// reason.
func TestWarnAndDebugAreDistinguishableInTheLog(t *testing.T) {
	client, readLog := parLoggingClient(t, oauth2.Clients{})

	client.log.Warn("a warning", "k", "v")
	client.log.Debug("a debug line", "k", "v")

	entries := readLog()
	require.Len(t, entries, 1, "only the warning may reach a production log")
	assert.Equal(t, "WARN: a warning", entries[0].Message)
	require.Len(t, warnings(entries), 1)
}

// A client that IS configured and still fails is a mismatch somebody has to
// fix. Both outcomes fall through to wallet attestation, so if this is not
// reported here it is not reported at all.
func TestOAuthPar_WarnsWhenAConfiguredClientIsRejected(t *testing.T) {
	client, readLog := parLoggingClient(t, oauth2.Clients{
		"wallet-1": {
			Type:         oauth2.ClientTypePublic,
			RedirectURIs: oauth2.RedirectURIs{"https://wallet.example.com/cb"},
			Scopes:       []string{"pid"},
		},
	})

	_, err := client.OAuthPar(context.Background(), &openid4vci.PARRequest{
		ClientID:    "wallet-1",
		RedirectURI: "https://attacker.example.com/cb",
		Scope:       "pid",
	})
	require.Error(t, err)

	warned := warnings(readLog())
	require.Len(t, warned, 1, "a configured client that is refused must be reported once")
	assert.Equal(t, "wallet-1", warned[0].ClientID)
	assert.Equal(t, "https://attacker.example.com/cb", warned[0].RedirectURI)
	assert.Equal(t, "pid", warned[0].Scope)
	assert.Contains(t, warned[0].Reason, "https://wallet.example.com/cb",
		"the reason must name what was configured, or the operator is still guessing")
}

// An unknown client_id is the normal path for a wallet that authenticates by
// attestation. Reporting it at the same level would bury the case above in
// every deployment that uses attestation at all.
func TestOAuthPar_DoesNotWarnForAnUnknownClient(t *testing.T) {
	client, readLog := parLoggingClient(t, oauth2.Clients{})

	_, err := client.OAuthPar(context.Background(), &openid4vci.PARRequest{
		ClientID:    "some-attesting-wallet",
		RedirectURI: "https://wallet.example.com/cb",
		Scope:       "pid",
	})
	require.Error(t, err)

	assert.Empty(t, warnings(readLog()), "an unknown client_id belongs at Debug")
}

// The scope mismatch takes the same branch, and must name the scopes that
// were configured rather than only the one that was asked for.
func TestOAuthPar_WarnsWhenAConfiguredClientAsksForTheWrongScope(t *testing.T) {
	client, readLog := parLoggingClient(t, oauth2.Clients{
		"wallet-1": {
			Type:         oauth2.ClientTypePublic,
			RedirectURIs: oauth2.RedirectURIs{"https://wallet.example.com/cb"},
			Scopes:       []string{"pid"},
		},
	})

	_, err := client.OAuthPar(context.Background(), &openid4vci.PARRequest{
		ClientID:    "wallet-1",
		RedirectURI: "https://wallet.example.com/cb",
		Scope:       "ehic",
	})
	require.Error(t, err)

	warned := warnings(readLog())
	require.Len(t, warned, 1)
	assert.Contains(t, warned[0].Reason, "ehic")
	assert.Contains(t, warned[0].Reason, "allowed: pid")
}
