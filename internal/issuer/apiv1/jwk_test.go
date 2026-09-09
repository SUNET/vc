package apiv1

import (
	"encoding/json"
	"testing"

	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"
	"github.com/SUNET/vc/pkg/logger"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateJWK(t *testing.T) {
	ctx := t.Context()
	client := mockNewClient(ctx, t, "ecdsa", logger.NewSimple("testing_apiv1"))

	err := client.createJWK(ctx)
	assert.NoError(t, err)

	// The JWK kid must match the signer's KeyID (what goes into JWT headers)
	expectedKid := client.signer.KeyID()
	assert.NotEmpty(t, expectedKid)

	// Verify proto is populated correctly (public key only)
	assert.Equal(t, expectedKid, client.jwkProto.Kid)
	assert.Equal(t, "EC", client.jwkProto.Kty)
	assert.Equal(t, "P-256", client.jwkProto.Crv)
	assert.NotEmpty(t, client.jwkProto.X)
	assert.NotEmpty(t, client.jwkProto.Y)

	// Private key component must NOT be present (public-key-only JWK)
	assert.Empty(t, client.jwkProto.D, "private key component 'd' must not be present")
}

func TestCreateJWK_RSA(t *testing.T) {
	ctx := t.Context()
	client := mockNewClient(ctx, t, "rsa", logger.NewSimple("testing_apiv1"))

	err := client.createJWK(ctx)
	assert.NoError(t, err)

	// kid must match the signer's KeyID
	assert.Equal(t, client.signer.KeyID(), client.jwkProto.Kid)
	assert.Equal(t, "RSA", client.jwkProto.Kty)

	// RSA public key components must be present
	assert.NotEmpty(t, client.jwkProto.N, "RSA modulus 'n' must be present")
	assert.NotEmpty(t, client.jwkProto.E, "RSA exponent 'e' must be present")

	// Private key component must NOT be present
	assert.Empty(t, client.jwkProto.D, "private key component 'd' must not be present")
}

func TestCreateJWK_KidMatchesSigner(t *testing.T) {
	ctx := t.Context()
	client := mockNewClient(ctx, t, "ecdsa", logger.NewSimple("testing_apiv1"))

	// Even when config has a different kid, the JWK uses the signer's kid
	// to ensure JWT headers and JWKS endpoint are consistent.
	client.cfg.Issuer.JWTAttribute.Kid = "config-value-ignored"

	err := client.createJWK(ctx)
	assert.NoError(t, err)

	// The JWK kid must match signer.KeyID(), not the config value
	expectedKid := client.signer.KeyID()
	assert.Equal(t, expectedKid, client.jwkProto.Kid)
}

// TestCheckNoJWKMembersDropped covers the guard directly, including the
// shape SUNET/vc#639 reported: an RSA key served as kid+kty only, because
// the proto had no n or e to unmarshal them into.
func TestCheckNoJWKMembersDropped(t *testing.T) {
	t.Run("a fully modelled EC key passes", func(t *testing.T) {
		src := []byte(`{"kty":"EC","kid":"k","crv":"P-256","x":"AA","y":"BB","alg":"ES256","use":"sig"}`)
		proto := &apiv1_issuer.Jwk{}
		require.NoError(t, json.Unmarshal(src, proto))
		assert.NoError(t, checkNoJWKMembersDropped(src, proto))
	})

	t.Run("a fully modelled RSA key passes", func(t *testing.T) {
		src := []byte(`{"kty":"RSA","kid":"k","n":"AQAB","e":"AQAB","alg":"RS256","use":"sig"}`)
		proto := &apiv1_issuer.Jwk{}
		require.NoError(t, json.Unmarshal(src, proto))
		assert.NoError(t, checkNoJWKMembersDropped(src, proto))
	})

	// The regression itself: n and e have nowhere to go, so the served key
	// is kid+kty and verifies nothing. Simulated by unmarshalling into a
	// proto that never sees them.
	t.Run("dropped RSA members are reported", func(t *testing.T) {
		src := []byte(`{"kty":"RSA","kid":"k","n":"AQAB","e":"AQAB"}`)
		proto := &apiv1_issuer.Jwk{Kty: "RSA", Kid: "k"} // as if n/e were unmodelled

		err := checkNoJWKMembersDropped(src, proto)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "e, n", "both dropped members should be named, sorted")
		assert.Contains(t, err.Error(), "proto/v1-issuer.proto", "the error should say where to fix it")
		assert.Contains(t, err.Error(), `kty="RSA"`, "the key type makes the report actionable")
	})

	t.Run("an unmodelled member of any kind is reported", func(t *testing.T) {
		// x5c is a legitimate JWK member the proto does not model; the point
		// is that the guard is not RSA-specific.
		src := []byte(`{"kty":"EC","kid":"k","crv":"P-256","x":"AA","y":"BB","x5c":["MII"]}`)
		proto := &apiv1_issuer.Jwk{}
		require.NoError(t, json.Unmarshal(src, proto))

		err := checkNoJWKMembersDropped(src, proto)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "x5c")
	})
}

// TestCreateJWKServesCompleteKey is the end-to-end assertion the issue was
// really about: whatever the key type, /jwks must carry every member needed
// to verify a signature with it. The apigw endpoint is a pass-through of
// this exact proto (JWKSResponse is an alias for it), so asserting here
// covers what a caller of /jwks receives.
func TestCreateJWKServesCompleteKey(t *testing.T) {
	for _, tc := range []struct {
		keyType  string
		wantKty  string
		required []string
	}{
		{keyType: "ecdsa", wantKty: "EC", required: []string{"crv", "x", "y"}},
		{keyType: "rsa", wantKty: "RSA", required: []string{"n", "e"}},
	} {
		t.Run(tc.keyType, func(t *testing.T) {
			ctx := t.Context()
			client := mockNewClient(ctx, t, tc.keyType, logger.NewSimple("testing_apiv1"))
			require.NoError(t, client.createJWK(ctx))

			served, err := json.Marshal(client.jwkProto)
			require.NoError(t, err)
			var members map[string]any
			require.NoError(t, json.Unmarshal(served, &members))

			assert.Equal(t, tc.wantKty, members["kty"])
			assert.NotEmpty(t, members["kid"])
			assert.Equal(t, "sig", members["use"])
			assert.NotEmpty(t, members["alg"], "alg is needed to pick a verification algorithm")
			for _, m := range tc.required {
				assert.NotEmpty(t, members[m], "%s key must carry %q", tc.wantKty, m)
			}
			assert.NotContains(t, members, "d", "no private key material on /jwks")
		})
	}
}
