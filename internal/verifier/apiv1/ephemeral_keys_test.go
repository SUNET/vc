package apiv1

import (
	"encoding/json"
	"sync"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"
)

// TestEphemeralEncryptionKeyConcurrent pins the one private key per kid rule.
//
// A request object can be built more than once for the same session, and the
// lookup and the store are separate cache operations. With a plain Set the
// last writer wins, so a wallet handed the first public key can no longer be
// decrypted for. Every caller must come back with the key that is stored.
func TestEphemeralEncryptionKeyConcurrent(t *testing.T) {
	client, _ := CreateTestClientWithMock(t, nil)
	ctx := t.Context()

	const kid = "session-under-contention"
	const callers = 16

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		private = make([]string, 0, callers)
		public  = make([]string, 0, callers)
	)

	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			priv, pub, err := client.ephemeralEncryptionKey(ctx, kid)
			if err != nil {
				mu.Lock()
				defer mu.Unlock()
				t.Error(err)
				return
			}
			privJSON, pubJSON := mustMarshalJWK(t, priv), mustMarshalJWK(t, pub)
			mu.Lock()
			defer mu.Unlock()
			private = append(private, privJSON)
			public = append(public, pubJSON)
		}()
	}
	wg.Wait()

	require.Len(t, private, callers)
	for i := range private {
		require.Equal(t, private[0], private[i], "caller %d got a different private key", i)
		require.Equal(t, public[0], public[i], "caller %d advertised a different public key", i)
	}

	stored, found := client.cacheService.EphemeralEncryptionKey.Get(ctx, kid)
	require.True(t, found)
	require.Equal(t, private[0], mustMarshalJWK(t, stored), "the cached key is not the one callers received")
}

func mustMarshalJWK(t testing.TB, key jwk.Key) string {
	t.Helper()
	b, err := json.Marshal(key)
	require.NoError(t, err)
	return string(b)
}
