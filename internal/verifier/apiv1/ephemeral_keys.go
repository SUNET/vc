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
// The keys live in the cache service, not in openid4vp's in-process cache.
// That cache is per-process, so with more than one verifier replica a wallet's
// encrypted response could land on a node that never held the key and fail to
// decrypt - the request object is served by one replica and the response
// posted to whichever the load balancer picks. APIGW already resolves its
// ephemeral keys this way.
//
// Reuse rather than regenerate: a request object can be built more than once
// for the same session, and replacing the private key under an unchanged kid
// would strand a wallet still holding the earlier one.
func (c *Client) ephemeralEncryptionKey(ctx context.Context, kid string) (privateKey jwk.Key, publicKey jwk.Key, err error) {
	if existing, ok := c.cacheService.EphemeralEncryptionKey.Get(ctx, kid); ok {
		publicJWK, err := existing.PublicKey()
		if err != nil {
			return nil, nil, fmt.Errorf("deriving public key for kid %q: %w", kid, err)
		}
		if err := openid4vp.DecorateEncryptionKey(publicJWK, kid); err != nil {
			return nil, nil, err
		}
		return existing, publicJWK, nil
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

	c.cacheService.EphemeralEncryptionKey.Set(ctx, kid, privateJWK)

	publicJWK, err := jwk.Import(privKey.Public())
	if err != nil {
		return nil, nil, err
	}
	if err := openid4vp.DecorateEncryptionKey(publicJWK, kid); err != nil {
		return nil, nil, err
	}

	return privateJWK, publicJWK, nil
}
