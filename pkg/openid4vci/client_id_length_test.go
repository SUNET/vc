package openid4vci

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

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

// A wallet that identifies itself with a DID sends a client_id far longer than
// the 128 characters this used to allow (SUNET/vc#706).
func TestTokenRequestAcceptsADIDClientID(t *testing.T) {
	clientID := didJWKP256()
	require.Greater(t, len(clientID), 128, "test is pointless unless the DID is longer than the old limit")
	require.LessOrEqual(t, len(clientID), 512)

	req := &TokenRequest{
		GrantType:    "authorization_code",
		Code:         "abc123",
		ClientID:     clientID,
		CodeVerifier: strings.Repeat("v", 43),
	}

	assert.NoError(t, CheckSimple(req))
}

// The bound still exists; it just moved.
func TestTokenRequestStillRefusesAnOverlongClientID(t *testing.T) {
	req := &TokenRequest{
		GrantType: "authorization_code",
		Code:      "abc123",
		ClientID:  strings.Repeat("x", 513),
	}

	err := CheckSimple(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client_id")
}
