package cache

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// didJWKP256 builds a did:jwk the way a wallet would: "did:jwk:" followed by
// the base64url encoding of the JWK. A P-256 key gives the shortest realistic
// DID of this shape, so if that one fits, the common cases do too.
func didJWKP256() string {
	jwk := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":%q,"y":%q}`,
		strings.Repeat("a", 43), strings.Repeat("b", 43))
	return "did:jwk:" + base64.RawURLEncoding.EncodeToString([]byte(jwk))
}

func authContextWithClientID(clientID string) *AuthorizationContext {
	return &AuthorizationContext{
		SessionID: "session-1",
		ClientID:  clientID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
}

// Storing the authorization context is where a long client_id used to be
// rejected, after the PAR endpoint had already accepted it (SUNET/vc#706).
func TestAuthorizationContextAcceptsADIDClientID(t *testing.T) {
	clientID := didJWKP256()
	require.Greater(t, len(clientID), 128, "test is pointless unless the DID is longer than the old limit")
	require.LessOrEqual(t, len(clientID), 512)

	assert.NoError(t, authContextWithClientID(clientID).Validate())

	walletCtx := authContextWithClientID("")
	walletCtx.WalletClientID = clientID
	assert.NoError(t, walletCtx.Validate())
}

func TestAuthorizationContextStillRefusesAnOverlongClientID(t *testing.T) {
	err := authContextWithClientID(strings.Repeat("x", 513)).Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client_id")
}
