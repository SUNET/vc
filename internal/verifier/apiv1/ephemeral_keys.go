package apiv1

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"

	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// ephemeralEncryptionKey returns the ephemeral encryption key pair for kid,
// reusing the stored private half when one exists.
//
// The keys live in the cache service, not in openid4vp's in-process cache,
// so that a deployment CAN share them between replicas: the request object is
// served by one replica and the response posted to whichever the load
// balancer picks, so a key held only by the issuing process would leave the
// wallet's encrypted response undecryptable. APIGW already resolves its
// ephemeral keys this way.
//
// Sharing is what common.ha.enable buys, not something the cache service does
// on its own - pkg/cache's factory returns a Mongo-backed store when HA is on
// and a per-process MemoryCache when it is off. So running more than one
// replica without HA has the same problem this move was made to avoid; the
// cache service is simply where that is fixable, and where APIGW already
// fixes it.
//
// The reuse guarantee below holds either way: SetNX is atomic in both
// backends - ttlcache's GetOrSet within a process, an InsertOne against a
// unique key across nodes.
//
// Reuse rather than regenerate: a request object can be built more than once
// for the same session, and replacing the private key under an unchanged kid
// would strand a wallet still holding the earlier one.
func (c *Client) ephemeralEncryptionKey(ctx context.Context, kid string) (privateKey jwk.Key, publicKey jwk.Key, err error) {
	if existing, ok := c.cacheService.EphemeralEncryptionKey.Get(ctx, kid); ok {
		return withPublicHalf(existing, kid)
	}

	privKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	privateJWK, err := jwk.Import(privKey)
	if err != nil {
		return nil, nil, err
	}
	if err := privateJWK.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, nil, err
	}

	// SetNX, not Set: the lookup above and this store are not one operation,
	// so two concurrent builds for the same kid both reach here. The loser
	// must not overwrite the private half its rival may already have
	// advertised to a wallet - it adopts the stored key instead.
	stored, err := c.cacheService.EphemeralEncryptionKey.SetNX(ctx, kid, privateJWK)
	if err != nil {
		return nil, nil, fmt.Errorf("storing ephemeral key for kid %q: %w", kid, err)
	}
	if !stored {
		winner, ok := c.cacheService.EphemeralEncryptionKey.Get(ctx, kid)
		if !ok {
			return nil, nil, fmt.Errorf("ephemeral key for kid %q was stored by a concurrent request and has already expired", kid)
		}
		return withPublicHalf(winner, kid)
	}

	return withPublicHalf(privateJWK, kid)
}

// withPublicHalf returns the private key alongside the public JWK the request
// object advertises for it.
func withPublicHalf(privateJWK jwk.Key, kid string) (jwk.Key, jwk.Key, error) {
	// PublicKey copies the key material but not every parameter, so the
	// advertised key is decorated the same way a freshly generated one is.
	publicJWK, err := privateJWK.PublicKey()
	if err != nil {
		return nil, nil, fmt.Errorf("deriving public key for kid %q: %w", kid, err)
	}
	if err := openid4vp.DecorateEncryptionKey(publicJWK, kid); err != nil {
		return nil, nil, err
	}
	return privateJWK, publicJWK, nil
}
