package externalapi

import (
	"context"
	"testing"
	"time"

	pkgcache "github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/stretchr/testify/require"
)

// fetcher is what both data sources offer to the tests.
type fetcher interface {
	FetchAndStoreForVCI(ctx context.Context, personID, credentialType, vciSessionID string, params *pkgcache.ExternalAPIParams) error
}

// testRemote is a remote pointing at a fake provider whose token endpoint is at /oauth2/token.
func testRemote(typ model.RemoteType, serverURL, basePath string) model.Remote {
	return model.Remote{
		Type:         typ,
		BaseURL:      serverURL + basePath,
		TokenURL:     serverURL + "/oauth2/token",
		ClientID:     "vc",
		ClientSecret: "secret",
		Timeout:      5 * time.Second,
	}
}

func newTestLog(t *testing.T) *logger.Log {
	t.Helper()
	log, err := logger.New("test", "", false)
	require.NoError(t, err)
	return log
}

func newTestDocCache() pkgcache.Cache[map[string]*model.CompleteDocument] {
	return pkgcache.NewMemoryCache[map[string]*model.CompleteDocument](time.Hour)
}

// fetchStored fetches person p-1 and returns the stored document's data, or the fetch error.
func fetchStored(t *testing.T, src fetcher, docs pkgcache.Cache[map[string]*model.CompleteDocument], params *pkgcache.ExternalAPIParams) (map[string]any, error) {
	t.Helper()

	if err := src.FetchAndStoreForVCI(context.Background(), "p-1", "any", "session-1", params); err != nil {
		return nil, err
	}
	stored, ok := docs.Get(context.Background(), "session-1")
	require.True(t, ok)
	for _, d := range stored {
		return d.DocumentData, nil
	}
	return nil, nil
}
