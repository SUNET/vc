package apiv1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	apigwcache "github.com/SUNET/vc/internal/apigw/cache"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/oauth2"
	"github.com/SUNET/vc/pkg/openid4vci"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const iaTokenEndpoint = "https://apigw.example.com/token"

// tokenDPoPProof mints a proof for the Token Endpoint.
func tokenDPoPProof(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"jti": fmt.Sprintf("jti-token-test-%d", challengeJTI.Add(1)),
		"iat": time.Now().Unix(),
		"htm": "POST",
		"htu": iaTokenEndpoint,
	})
	token.Header["typ"] = "dpop+jwt"

	publicJWK, err := jwk.Import(&key.PublicKey)
	require.NoError(t, err)
	jwkJSON, err := json.Marshal(publicJWK)
	require.NoError(t, err)
	var jwkMap map[string]any
	require.NoError(t, json.Unmarshal(jwkJSON, &jwkMap))
	token.Header["jwk"] = jwkMap

	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

// newIATokenClient stores one authorization code that came out of an
// Interactive Authorization exchange opened under boundKey.
func newIATokenClient(t *testing.T, boundThumbprint string) (*Client, string) {
	t.Helper()

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	store := apigwcache.NewTestMemoryStore(10 * time.Minute)
	const code = "ia-authorization-code"
	require.NoError(t, store.Save(t.Context(), &apigwcache.AuthorizationContext{
		SessionID:                 code,
		Code:                      code,
		CreatedAt:                 time.Now(),
		ExpiresAt:                 time.Now().Add(5 * time.Minute).Unix(),
		Scopes:                    []string{"pid"},
		AuthProvider:              model.AuthProviderOpenID4VP,
		DataSource:                string(model.DataSourceDatastore),
		WalletClientID:            "wallet-1",
		AuthSessionDPoPThumbprint: boundThumbprint,
	}))

	return &Client{
		log: log,
		cfg: &model.Cfg{
			APIGW: &model.APIGW{
				Delivery: model.APIGWDelivery{
					OpenID4VCI: model.OAuthServer{
						TokenEndpoint: iaTokenEndpoint,
						Clients: oauth2.Clients{
							"wallet-1": {
								Type:         oauth2.ClientTypeConfidential,
								RedirectURIs: oauth2.RedirectURIs{"https://wallet.example.com/cb"},
								Scopes:       []string{"pid"},
							},
						},
					},
				},
			},
		},
		cacheService: &apigwcache.Service{
			AuthContext: store,
			DPopJTI:     apigwcache.NewTestMemoryCache[bool](10 * time.Minute),
		},
	}, code
}

// thumbprintOf is what the challenge endpoint would have recorded.
func thumbprintOf(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	dpop, err := oauth2.ValidateAndParseDPoPJWT(tokenDPoPProof(t, key))
	require.NoError(t, err)
	return dpop.Thumbprint
}

// A code produced by an Interactive Authorization exchange must be
// redeemed with the key that exchange was opened under.
//
// Everything else at this endpoint binds the ACCESS TOKEN to whatever key
// signed the proof on this request, which says nothing about who obtained
// the authorization. Without this check, a flow opened with key A yields a
// code key B can spend - and the association OpenID4VCI 1.1 asks for
// between auth_session and a DPoP key is only worth having if the same key
// has to turn up in the token request.
func TestOAuthToken_IACodeIsBoundToTheExchangesKey(t *testing.T) {
	walletKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	thiefKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	bound := thumbprintOf(t, walletKey)

	t.Run("another key cannot redeem it", func(t *testing.T) {
		client, code := newIATokenClient(t, bound)

		reply, err := client.OAuthToken(t.Context(), &openid4vci.TokenRequest{
			GrantType:    "authorization_code",
			Code:         code,
			ClientID:     "wallet-1",
			RedirectURI:  "https://wallet.example.com/cb",
			CodeVerifier: "unused-but-present",
			DPOP:         tokenDPoPProof(t, thiefKey),
		})
		require.Error(t, err)
		assert.Nil(t, reply)

		var oauthErr *oauth2.OAuthError
		require.ErrorAs(t, err, &oauthErr)
		assert.Equal(t, oauth2.ErrCodeInvalidGrant, oauthErr.ErrorCode)
		assert.Contains(t, oauthErr.Error(), "key its authorization was obtained under")
	})

	t.Run("the key that opened the exchange gets past the binding", func(t *testing.T) {
		client, code := newIATokenClient(t, bound)

		_, err := client.OAuthToken(t.Context(), &openid4vci.TokenRequest{
			GrantType:    "authorization_code",
			Code:         code,
			ClientID:     "wallet-1",
			RedirectURI:  "https://wallet.example.com/cb",
			CodeVerifier: "unused-but-present",
			DPOP:         tokenDPoPProof(t, walletKey),
		})

		// It may still fail further on - this fixture has no documents to
		// issue against - but never on the binding, which is the assertion.
		if err != nil {
			assert.NotContains(t, err.Error(), "key its authorization was obtained under")
		}
	})

	// A code with no recorded exchange key is an ordinary one, and this
	// check must not start refusing those.
	t.Run("a code from no exchange is unaffected", func(t *testing.T) {
		client, code := newIATokenClient(t, "")

		_, err := client.OAuthToken(t.Context(), &openid4vci.TokenRequest{
			GrantType:    "authorization_code",
			Code:         code,
			ClientID:     "wallet-1",
			RedirectURI:  "https://wallet.example.com/cb",
			CodeVerifier: "unused-but-present",
			DPOP:         tokenDPoPProof(t, thiefKey),
		})
		if err != nil {
			assert.NotContains(t, err.Error(), "key its authorization was obtained under")
		}
	})
}
