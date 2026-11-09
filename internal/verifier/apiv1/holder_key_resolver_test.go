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

// relationshipStub is a trust resolver that reports verification relationships.
type relationshipStub struct {
	trustStub
	key           crypto.PublicKey
	relationships []string
}

func (s *relationshipStub) ResolveKeyFor(_ context.Context, vm, relationship string) (crypto.PublicKey, error) {
	s.calls = append(s.calls, vm)
	s.relationships = append(s.relationships, relationship)
	return s.key, nil
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
	assert.Empty(t, stub.calls, "a resolver that cannot report relationships is not asked for a holder key")
	assert.Contains(t, err.Error(), "verification relationships")
}

// TestHolderKeyResolverAsksForAuthentication: any other method goes to the trust
// resolver as an authentication method, so a key the DID document lists without that
// authorization is not a holder's.
func TestHolderKeyResolverAsksForAuthentication(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	stub := &relationshipStub{key: pub}

	got, err := newHolderKeyResolver(stub).ResolveKey(t.Context(), "did:web:example.com#key-1")
	require.NoError(t, err)
	assert.Equal(t, pub, got)
	assert.Equal(t, []string{"authentication"}, stub.relationships)
}

// TestIssuerKeyResolverAsksForAssertionMethod: an issuer's key is the DID's to sign
// credentials with only when the DID document lists it under assertionMethod, and a trust
// resolver that cannot say so is refused rather than asked for a plain key.
func TestIssuerKeyResolverAsksForAssertionMethod(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	stub := &relationshipStub{key: pub}

	got, err := newIssuerKeyResolver(stub).ResolveKey(t.Context(), "did:web:issuer.example#key-1")
	require.NoError(t, err)
	assert.Equal(t, pub, got)
	assert.Equal(t, []string{"assertionMethod"}, stub.relationships)

	plain := &trustStub{}
	_, err = newIssuerKeyResolver(plain).ResolveKey(t.Context(), "did:web:issuer.example#key-1")
	require.Error(t, err)
	assert.Empty(t, plain.calls, "a resolver that cannot report relationships is not asked for an issuer key")
	assert.Contains(t, err.Error(), "verification relationships")
}
