package apiv1

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/SUNET/vc/pkg/jose"
	"github.com/SUNET/vc/pkg/tokenstatuslist"
)

func signingKeySetFixture() *jose.JWKS {
	return &jose.JWKS{
		Keys: []jose.JWKWithMetadata{{
			Kty: "EC",
			Crv: "P-256",
			Use: "sig",
			Kid: "status-list-signer",
			Alg: "ES256",
			X:   "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
			Y:   "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
		}},
	}
}

func TestStatusListJWKSServesTheSignersKeys(t *testing.T) {
	client, mock := newTestClient()
	mock.SetJWT(1, "eyJhbGciOiJFUzI1NiJ9.payload.signature")
	mock.jwks = signingKeySetFixture()

	reply, err := client.TokenStatusListJWKS(t.Context(), &TokenStatusListJWKSRequest{ID: 1})
	require.NoError(t, err)
	require.NotNil(t, reply)

	require.Len(t, reply.Keys, 1, "the list's signer must be published, or no registry can bind it")
	assert.Equal(t, "EC", reply.Keys[0].Kty)
	assert.Equal(t, "status-list-signer", reply.Keys[0].Kid)
	assert.Equal(t, "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", reply.Keys[0].X)
}

func TestStatusListJWKSRefusesAnUnknownSection(t *testing.T) {
	client, _ := newTestClient()

	// Nothing cached for 999: this registry serves no token for that list URI,
	// so it must not answer for that list URI's keys either.
	reply, err := client.TokenStatusListJWKS(t.Context(), &TokenStatusListJWKSRequest{ID: 999})
	require.Error(t, err)
	assert.ErrorIs(t, err, tokenstatuslist.ErrSectionNotFound)
	assert.Nil(t, reply)
}

func TestStatusListJWKSFailsClosedWhenTheKeySetCannotBeBuilt(t *testing.T) {
	client, mock := newTestClient()
	mock.SetJWT(1, "eyJhbGciOiJFUzI1NiJ9.payload.signature")
	mock.jwksErr = errors.New("status list signing key not loaded")

	reply, err := client.TokenStatusListJWKS(t.Context(), &TokenStatusListJWKSRequest{ID: 1})
	require.Error(t, err, "a key set that cannot be built must not come back as an empty one")
	assert.Nil(t, reply)
}
