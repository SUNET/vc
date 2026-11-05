package apiv1

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/multiformats/go-multibase"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type trustStub struct{ calls []string }

func (s *trustStub) ResolveKey(_ context.Context, vm string) (crypto.PublicKey, error) {
	s.calls = append(s.calls, vm)
	return nil, errors.New("resolution denied: no registry returned positive match")
}

// TestHolderKeyResolver: a holder's did:key is read from the identifier and
// never sent to the trust service; any other method still goes there.
func TestHolderKeyResolver(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	// did:key multikey: multicodec 0xed01 (ed25519-pub) + key, base58btc, 'z'.
	mk, err := multibase.Encode(multibase.Base58BTC, append([]byte{0xed, 0x01}, pub...))
	require.NoError(t, err)
	didKey := "did:key:" + mk

	stub := &trustStub{}
	r := newHolderKeyResolver(stub)

	got, err := r.ResolveKey(t.Context(), didKey+"#"+didKey[len("did:key:"):])
	require.NoError(t, err)
	assert.Equal(t, pub, got)
	assert.Empty(t, stub.calls, "a did:key is not sent to the trust service")

	_, err = r.ResolveKey(t.Context(), "did:web:example.com#key-1")
	require.Error(t, err)
	assert.Equal(t, []string{"did:web:example.com#key-1"}, stub.calls, "other methods keep going to the trust service")
}
