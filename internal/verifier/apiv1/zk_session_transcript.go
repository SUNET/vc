package apiv1

import (
	"context"
	"crypto"
	"fmt"
	"net/url"

	"github.com/SUNET/vc/internal/verifier/cache"
	"github.com/SUNET/vc/pkg/mdoc"
)

// zkSessionTranscript builds the SessionTranscript a ZK proof must be
// verified against, choosing the handover by how the response arrived.
//
// The two handovers hash different things and a wallet only ever produced
// one of them, so picking the wrong one fails every proof from that channel
// with an opaque proof error rather than a wiring error (SUNET/vc#652,
// SUNET/vc#655). origin is used only on the DC API branch, and is resolved
// by the caller so that a link-delivered response never depends on the DC
// API origin being configurable at all.
//
// Extracted from VerificationDirectPost so the choice can be tested without
// a valid Vega proof: verifying one end to end needs the native prover, and
// the selection happens before verification, so a test that stopped at the
// transcript would still be the only thing covering this flag.
func zkSessionTranscript(dcAPI bool, origin, clientID, nonce, responseURI string, readerPubKeyThumbprint []byte) ([]byte, error) {
	if dcAPI {
		return mdoc.BuildOID4VPDCAPISessionTranscript(origin, nonce, readerPubKeyThumbprint)
	}
	return mdoc.BuildOID4VPSessionTranscript(clientID, nonce, responseURI, readerPubKeyThumbprint)
}

// readerKeyThumbprint is the JWK thumbprint of this session's
// ephemeral encryption key, or nil when the session had none.
//
// It is part of the SessionTranscript a wallet binds its proof to, so
// a MISS is fatal rather than nil: the key expired or was evicted
// between issuing the request and the wallet answering it, the wallet
// built ITS transcript with that key, and carrying on without it
// guarantees a mismatch - surfacing as an opaque proof failure rather
// than as the cache miss it actually is.
//
// The guard is on the key ID rather than on the response mode, so a
// future caller that leaves it unset gets a nil thumbprint rather
// than a wrong one.
//
// Extracted so the circuit_zk path and the mdoc ZK path cannot come
// to disagree about what the wallet hashed. Two copies of this would
// be two chances to get a transcript input wrong, and a wrong
// transcript input is indistinguishable from a bad proof.
func (c *Client) readerKeyThumbprint(ctx context.Context, authCtx *cache.AuthorizationContext, scope string) ([]byte, error) {
	if authCtx == nil || authCtx.EphemeralEncryptionKeyID == "" {
		return nil, nil
	}

	privKey, found := c.cacheService.EphemeralEncryptionKey.Get(ctx, authCtx.EphemeralEncryptionKeyID)
	if !found {
		c.log.Error(nil, "ephemeral encryption key missing from cache for ZK session transcript",
			"scope", scope, "key_id", authCtx.EphemeralEncryptionKeyID)
		return nil, fmt.Errorf("ephemeral encryption key %q is no longer cached, cannot rebuild the session transcript the wallet used for scope %s",
			authCtx.EphemeralEncryptionKeyID, scope)
	}

	pubKey, err := privKey.PublicKey()
	if err != nil {
		c.log.Error(err, "failed to derive public key for ZK session transcript", "scope", scope)
		return nil, fmt.Errorf("failed to derive public key for scope %s: %w", scope, err)
	}
	thumbprint, err := pubKey.Thumbprint(crypto.SHA256)
	if err != nil {
		c.log.Error(err, "failed to compute JWK thumbprint for ZK session transcript", "scope", scope)
		return nil, fmt.Errorf("failed to compute JWK thumbprint for scope %s: %w", scope, err)
	}
	return thumbprint, nil
}

// zkResponseURI is the response_uri a ZK session transcript binds to.
//
// It MUST equal the one actually sent to the wallet as
// requestObject.ResponseURI - "direct_post", not "oidc-direct_post",
// which belongs to a wholly separate OIDC RP flow with its own
// session and state namespace. Any difference changes handoverInfo's
// bytes, which changes its SHA-256, which changes the whole
// SessionTranscript the proof's Fiat-Shamir transcript was built
// against: a proof built over the real response_uri can never verify
// against a transcript recomputed with a different one, however
// correct the disclosed claims are.
//
// That is not hypothetical - it was observed live as the cause of an
// "InvalidSumcheckProof" rejection of a genuinely valid proof. One
// function, so a second presentation path cannot reintroduce it by
// deriving the URI slightly differently.
func (c *Client) zkResponseURI(scope string) (string, error) {
	responseURI, err := url.JoinPath(c.cfg.Verifier.PublicURL, "verification", "direct_post")
	if err != nil {
		c.log.Error(err, "failed to construct response URI for ZK session transcript", "scope", scope)
		return "", fmt.Errorf("failed to construct response URI for scope %s: %w", scope, err)
	}
	return responseURI, nil
}
