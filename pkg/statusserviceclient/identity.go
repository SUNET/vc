package statusserviceclient

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
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
func buildAssertion(issuerID string, key *ecdsa.PrivateKey, audience string) (string, error) {
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{
		Issuer:    issuerID,
		Subject:   issuerID,
		Audience:  jwt.ClaimStrings{audience},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(assertionLifetime)),
	})

	jwk := jose.JSONWebKey{Key: &key.PublicKey}
	raw, err := jwk.MarshalJSON()
	if err != nil {
		return "", fmt.Errorf("marshal client assertion jwk: %w", err)
	}
	var jwkMap map[string]any
	if err := json.Unmarshal(raw, &jwkMap); err != nil {
		return "", fmt.Errorf("unmarshal client assertion jwk: %w", err)
	}
	token.Header["jwk"] = jwkMap

	signed, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("sign client assertion: %w", err)
	}
	return signed, nil
}
