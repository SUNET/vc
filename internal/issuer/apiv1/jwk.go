package apiv1

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"
	"github.com/go-jose/go-jose/v4"
)

// createJWK builds the public JWK from the signer's key material and populates
// the proto structure used by the gRPC JWKS endpoint.
//
// Key design decisions:
//   - Uses go-jose (same library as pki.SignerConfig.GetJWK) for consistent JWK serialization
//   - Only serializes the PUBLIC key — no private key material flows over gRPC
//   - Kid is derived from the signer (same source as JWT header kid) to guarantee
//     that verifiers can match JWKS keys to JWT headers
func (c *Client) createJWK(ctx context.Context) error {
	_, cancel := context.WithDeadline(ctx, time.Now().Add(2*time.Second))
	defer cancel()

	// Build JWK from the signer's public key.
	// go-jose handles EC, RSA, and Ed25519 key types uniformly.
	jwk := jose.JSONWebKey{
		Key:       c.signer.PublicKey(),
		KeyID:     c.signer.KeyID(),
		Algorithm: c.signer.Algorithm(),
		Use:       "sig",
	}

	// Marshal to JSON (public key only — no private key material)
	jwkBytes, err := json.Marshal(jwk)
	if err != nil {
		return fmt.Errorf("failed to marshal JWK: %w", err)
	}

	// Populate proto for the gRPC JWKS endpoint
	if err := json.Unmarshal(jwkBytes, c.jwkProto); err != nil {
		return fmt.Errorf("failed to unmarshal JWK into proto: %w", err)
	}

	// The step above is lossy, and silently so - see checkNoJWKMembersDropped.
	if err := checkNoJWKMembersDropped(jwkBytes, c.jwkProto); err != nil {
		return err
	}

	return nil
}

// checkNoJWKMembersDropped fails when the proto could not carry every member
// go-jose produced.
//
// The proto is a hand-maintained mirror of a JWK, and the conversion into it
// is encoding/json, which discards members the target has no field for
// without any error. So a key type whose members the proto does not model
// serves a JWK that is well-formed JSON, correct as far as it goes, and
// missing the parts that make it usable.
//
// That is not hypothetical: RSA keys were served as {"kid":..,"kty":"RSA"}
// for months because the proto had no n or e (SUNET/vc#639, fixed by adding
// the fields in #403). EC keys were unaffected and hid it, and nothing
// failed - the endpoint kept answering 200 with a key nobody could verify
// against. Publishing a signing key is exactly the wrong place to be
// quietly approximate, so a drop is a startup error here rather than a
// surprise for whoever consumes /jwks.
func checkNoJWKMembersDropped(jwkBytes []byte, proto *apiv1_issuer.Jwk) error {
	var produced map[string]json.RawMessage
	if err := json.Unmarshal(jwkBytes, &produced); err != nil {
		return fmt.Errorf("failed to inspect marshalled JWK: %w", err)
	}

	roundTripped, err := json.Marshal(proto)
	if err != nil {
		return fmt.Errorf("failed to re-marshal JWK proto: %w", err)
	}
	var carried map[string]json.RawMessage
	if err := json.Unmarshal(roundTripped, &carried); err != nil {
		return fmt.Errorf("failed to inspect JWK proto: %w", err)
	}

	dropped := make([]string, 0, len(produced))
	for member := range produced {
		if _, ok := carried[member]; !ok {
			dropped = append(dropped, member)
		}
	}
	if len(dropped) == 0 {
		return nil
	}
	sort.Strings(dropped)

	return fmt.Errorf(
		"JWK member(s) %s cannot be represented by the jwk proto message and would be dropped from /jwks: add them to proto/v1-issuer.proto's jwk message (kty=%q)",
		strings.Join(dropped, ", "), proto.GetKty(),
	)
}
