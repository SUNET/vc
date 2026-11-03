package apiv1

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	apigwcache "github.com/SUNET/vc/internal/apigw/cache"
	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/vcclient"
)

// Drives UserLookup and reads the written log back, because a leak shows
// only in the rendering.
func TestUserLookupLogsNoSecretsOrHolderData(t *testing.T) {
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
		"a document claim":    "DOC-19900115",
	}

	c := &Client{
		log: log,
		cfg: &model.Cfg{APIGW: &model.APIGW{PublicURL: "https://issuer.example"}},
		cacheService: &apigwcache.Service{
			AuthContext: apigwcache.NewTestMemoryStore(10 * time.Minute),
			Document:    apigwcache.NewTestMemoryCache[map[string]*model.CompleteDocument](10 * time.Minute),
		},
	}
	require.NoError(t, c.cacheService.AuthContext.Create(t.Context(), &cache.AuthorizationContext{
		SessionID:            "sess-1",
		RequestURI:           "urn:request:1",
		VerifierResponseCode: "resp-1",
		WalletURI:            "https://wallet.example/cb",
		AccessToken:          secrets["access token"],
		RefreshToken:         secrets["refresh token"],
		IDToken:              secrets["id token"],
		Code:                 secrets["authorization code"],
		TXCode:               secrets["tx code"],
		VPToken:              secrets["vp token"],
		Token:                &cache.Token{AccessToken: secrets["nested access token"], ExpiresAt: time.Now().Add(time.Hour).Unix()},
		VerifiedClaims:       map[string]any{"personal_administrative_number": secrets["a verified claim"]},
	}))
	c.cacheService.Document.Set(t.Context(), "sess-1", map[string]*model.CompleteDocument{
		"pid": {
			Meta:         &model.MetaData{AuthenticSource: "pid"},
			DocumentData: map[string]any{"birth_date": secrets["a document claim"]},
		},
	})

	_, err = c.UserLookup(t.Context(), &vcclient.UserLookupRequest{
		AuthProvider: model.AuthProviderOpenID4VP,
		RequestURI:   "urn:request:1",
		ResponseCode: "resp-1",
	})
	require.NoError(t, err)

	written, err := os.ReadFile(filepath.Join(dir, "probe.log"))
	require.NoError(t, err)
	out := string(written)

	require.Contains(t, out, "sess-1", "the session id is the point of the line and must survive")
	for what, value := range secrets {
		require.NotContainsf(t, out, value, "the %s reached the log", what)
	}
}
