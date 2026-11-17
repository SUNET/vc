package statusserviceclient

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"time"

	"github.com/SUNET/vc/pkg/jose"
	"github.com/SUNET/vc/pkg/pki"
	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

// buildAssertion builds a fresh RFC 7523 client assertion for one token
// request: `iss` and `sub` both equal issuerID, `aud` is the token
// endpoint's exact URL, and the assertion's own signing key is embedded as
// a `jwk` header (RFC 7515 §4.1.3) - that embedded key is the entire proof
// of possession the status service's AS checks (see
// siros-status-service's internal/clientassertion.Verify), so nothing needs
// pre-registering.
//
// This mirrors siros-status-service's own reference client
// (tools/loadtest/identity.go) exactly, since it must match what that
// service's AS verifies: same claim set, same short lifetime, same ES256 +
// embedded-jwk-header construction.
//
// It signs through pki.Signer rather than a raw key, so the signing key can
// live in an HSM: the assertion is proof of possession, and possession is
// demonstrated by producing the signature, not by holding the bytes.
func buildAssertion(ctx context.Context, issuerID string, signer pki.Signer, audience string) (string, error) {
	pub, ok := signer.PublicKey().(*ecdsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("client assertion signer must hold an EC public key, got %T", signer.PublicKey())
	}

	jwk := josev4.JSONWebKey{Key: pub}
	raw, err := jwk.MarshalJSON()
	if err != nil {
		return "", fmt.Errorf("marshal client assertion jwk: %w", err)
	}
	var jwkMap map[string]any
	if err := json.Unmarshal(raw, &jwkMap); err != nil {
		return "", fmt.Errorf("unmarshal client assertion jwk: %w", err)
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": issuerID,
		"sub": issuerID,
		"aud": []string{audience},
		"iat": now.Unix(),
		"exp": now.Add(assertionLifetime).Unix(),
	}

	// jose.MakeJWT, not a direct SignedString: it is how everything else in
	// this repository signs a JWT, it takes a pki.Signer rather than raw key
	// material - so a PKCS#11 key works, the private half never having to
	// leave the device - and it converts an ASN.1 DER ECDSA signature to the
	// JWS P1363 form for backends that return DER. alg and kid come from the
	// signer.
	signed, err := jose.MakeJWT(ctx, jwt.MapClaims{"jwk": jwkMap}, claims, signer)
	if err != nil {
		return "", fmt.Errorf("sign client assertion: %w", err)
	}
	return signed, nil
}
