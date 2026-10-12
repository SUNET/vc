package apiv1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	apigwcache "github.com/SUNET/vc/internal/apigw/cache"
	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/oauth2"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/pki"
	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	challengeIssuerURL = "https://issuer.example.com"
	challengeScope     = "pid"
	challengeAuthScope = "pid_auth"
)

// newChallengeClient builds an apigw client with Interactive Authorization
// on and one datastore scope whose Holder is established by an OpenID4VP
// presentation - the only shape the Authorization Challenge Endpoint
// serves.
func newChallengeClient(t *testing.T) *Client {
	t.Helper()

	log, err := logger.New("challengetest", t.TempDir(), true)
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer, err := pki.NewSoftwareSigner(key, "test-key")
	require.NoError(t, err)

	enabled := true
	cfg := &model.Cfg{
		Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				challengeAuthScope: {
					Format: openid4vp.FormatSDJWTVC,
					VCTM:   &sdjwtvc.VCTM{VCT: "urn:example:pid:1"},
				},
			},
		},
		APIGW: &model.APIGW{
			PublicURL: challengeIssuerURL,
			Delivery: model.APIGWDelivery{
				OpenID4VCI: model.OAuthServer{
					Clients: oauth2.Clients{
						"wallet-1": {
							Type:         oauth2.ClientTypeConfidential,
							RedirectURIs: oauth2.RedirectURIs{"https://wallet.example.com/cb"},
							Scopes:       []string{challengeScope},
						},
					},
				},
				InteractiveAuthorization: model.InteractiveAuthorization{Enable: &enabled},
			},
			DataSources: model.DataSources{
				Datastore: model.DatastoreConfig{Scopes: map[string]model.DatastoreScope{
					challengeScope: {
						AuthProvider:    model.AuthProviderOpenID4VP,
						AuthenticSource: "authentic-source",
						AuthScopes: map[string]model.AuthScopeEntry{
							challengeAuthScope: {AuthClaims: []string{"given_name", "family_name"}},
						},
					},
				}},
			},
		},
	}

	return &Client{
		log: log.New("apiv1"),
		cfg: cfg,
		cacheService: &apigwcache.Service{
			AuthContext:            apigwcache.NewTestMemoryStore(10 * time.Minute),
			EphemeralEncryptionKey: apigwcache.NewTestMemoryCache[jwk.Key](10 * time.Minute),
			DPopJTI:                apigwcache.NewTestMemoryCache[bool](10 * time.Minute),
		},
		pkiSigner: signer,
	}
}

// initialChallenge is the request a conformant wallet opens an exchange
// with, so that each test below can vary exactly one thing about it.
func initialChallenge() *AuthorizationChallengeRequest {
	return &AuthorizationChallengeRequest{
		ResponseType:              "code",
		ClientID:                  "wallet-1",
		Scope:                     challengeScope,
		RedirectURI:               "https://wallet.example.com/cb",
		InteractionTypesSupported: "urn:openid:dcp:ia:openid4vp_presentation,urn:openid:dcp:ia:auth_via_web",
	}
}

// challengeErr runs the endpoint and returns the Interactive Authorization
// error it produced, failing the test if it succeeded or produced another
// kind of error.
func challengeErr(t *testing.T, client *Client, req *AuthorizationChallengeRequest) *AuthorizationChallengeError {
	t.Helper()
	reply, err := client.OAuthAuthorizationChallenge(t.Context(), req)
	require.Error(t, err)
	assert.Nil(t, reply)

	var challengeErr *AuthorizationChallengeError
	require.ErrorAs(t, err, &challengeErr)
	return challengeErr
}

// oauthErrFromChallenge is the same for the ordinary OAuth errors.
func oauthErrFromChallenge(t *testing.T, client *Client, req *AuthorizationChallengeRequest) *oauth2.OAuthError {
	t.Helper()
	reply, err := client.OAuthAuthorizationChallenge(t.Context(), req)
	require.Error(t, err)
	assert.Nil(t, reply)

	var oauthErr *oauth2.OAuthError
	require.ErrorAs(t, err, &oauthErr)
	return oauthErr
}

// unsafeJWTClaims reads a compact JWS payload without verifying it. The
// signature is not what these tests are about - what the wallet is asked
// for is - and verifying it here would only re-test jose.MakeJWT.
func unsafeJWTClaims(t *testing.T, compact string) map[string]any {
	t.Helper()

	parts := strings.Split(compact, ".")
	require.Len(t, parts, 3, "a signed request object is a compact JWS")

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	claims := map[string]any{}
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims
}

// An initial request from a conformant wallet is answered with the
// Interaction Required Response: 403, insufficient_authorization, the
// interaction type, the auth_session, and the OpenID4VP request itself.
func TestAuthorizationChallenge_InitialRequestRequiresAPresentation(t *testing.T) {
	client := newChallengeClient(t)

	challengeErr := challengeErr(t, client, initialChallenge())

	assert.Equal(t, 403, challengeErr.HTTPStatus)
	assert.Equal(t, "insufficient_authorization", challengeErr.ErrorCode)
	assert.Equal(t, "urn:openid:dcp:ia:openid4vp_presentation", challengeErr.InteractionTypeRequired)
	require.NotEmpty(t, challengeErr.AuthSession)
	require.NotEmpty(t, challengeErr.OpenID4VPRequest)

	// The exchange is retrievable by the handle the wallet was given, and
	// nothing else about it is guessable from the request.
	authCtx, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{
		AuthSession: challengeErr.AuthSession,
	})
	require.NoError(t, err)
	require.NotNil(t, authCtx)
	assert.Equal(t, []string{challengeScope}, authCtx.Scopes)
	assert.Equal(t, "wallet-1", authCtx.WalletClientID)
	assert.Equal(t, model.AuthProviderOpenID4VP, authCtx.AuthProvider)
	assert.Equal(t, "authentic-source", authCtx.AuthenticSource)
	assert.NotEmpty(t, authCtx.Nonce)
	assert.NotEmpty(t, authCtx.Code, "the code the exchange ends with is minted up front, not handed out")

	// crypto.GenerateSecureToken(32, 0) is base64url of 32 bytes.
	assert.GreaterOrEqual(t, len(challengeErr.AuthSession), 43,
		"auth_session must carry the 256 bits the draft's security considerations ask for")
}

// The request inside the Interaction Required Response is the DC API shape
// the draft points at, answered at the Authorization Challenge Endpoint:
// signed, naming this server's origin, carrying no response_uri, and asking
// for the encrypted response mode.
func TestAuthorizationChallenge_PresentationRequestIsSignedAndBoundToTheEndpoint(t *testing.T) {
	client := newChallengeClient(t)

	challengeErr := challengeErr(t, client, initialChallenge())

	var envelope struct {
		Request string `json:"request"`
	}
	require.NoError(t, json.Unmarshal(challengeErr.OpenID4VPRequest, &envelope))
	require.NotEmpty(t, envelope.Request, "openid4vp_request must carry a signed request object")

	claims := unsafeJWTClaims(t, envelope.Request)
	assert.Equal(t, "ia_post.jwt", claims["response_mode"])
	assert.Equal(t, []any{"https://issuer.example.com"}, claims["expected_origins"],
		"a signed request must name the origin of the endpoint it is answered at")
	assert.NotContains(t, claims, "response_uri",
		"an Interactive Authorization response goes back to the challenge endpoint, not to a response_uri")
	assert.NotEmpty(t, claims["nonce"])
	require.NotNil(t, claims["dcql_query"])
}

// A wallet that cannot do the interaction this scope needs is told which
// type is missing, not refused with a generic error.
func TestAuthorizationChallenge_WalletWithoutThePresentationInteraction(t *testing.T) {
	client := newChallengeClient(t)

	req := initialChallenge()
	req.InteractionTypesSupported = "urn:openid:dcp:ia:auth_via_web"

	challengeErr := challengeErr(t, client, req)

	assert.Equal(t, 400, challengeErr.HTTPStatus)
	assert.Equal(t, "missing_interaction_type", challengeErr.ErrorCode)
	assert.Contains(t, challengeErr.ErrorDescription, "urn:openid:dcp:ia:openid4vp_presentation")
}

// And a scope this server cannot serve through a presentation is refused
// by naming the interaction it WOULD need, which this build does not
// implement - rather than by a message about the scope.
func TestAuthorizationChallenge_ScopeThatNeedsAWebInteraction(t *testing.T) {
	client := newChallengeClient(t)
	client.cfg.APIGW.DataSources.Datastore.Scopes[challengeScope] = model.DatastoreScope{
		AuthProvider:    model.AuthProviderOIDC,
		AuthenticSource: "authentic-source",
	}

	challengeErr := challengeErr(t, client, initialChallenge())

	assert.Equal(t, 400, challengeErr.HTTPStatus)
	assert.Equal(t, "missing_interaction_type", challengeErr.ErrorCode)
	assert.Contains(t, challengeErr.ErrorDescription, "urn:openid:dcp:ia:auth_via_web")
}

// A deployment that has narrowed interaction_types_supported refuses the
// type it no longer offers, with the same error code: from the wallet's
// side the two are the same situation.
func TestAuthorizationChallenge_DeploymentThatDoesNotOfferTheInteraction(t *testing.T) {
	client := newChallengeClient(t)
	client.cfg.APIGW.Delivery.InteractiveAuthorization.InteractionTypesSupported = []string{"auth_via_web"}

	challengeErr := challengeErr(t, client, initialChallenge())

	assert.Equal(t, "missing_interaction_type", challengeErr.ErrorCode)
}

// The endpoint does not exist unless it is configured on, and says so the
// way an unrouted path would rather than as an OAuth refusal.
func TestAuthorizationChallenge_DisabledDeployment(t *testing.T) {
	client := newChallengeClient(t)
	disabled := false
	client.cfg.APIGW.Delivery.InteractiveAuthorization.Enable = &disabled

	oauthErr := oauthErrFromChallenge(t, client, initialChallenge())
	assert.Equal(t, 404, oauthErr.HTTPStatus)
}

func TestAuthorizationChallenge_InitialRequestValidation(t *testing.T) {
	for name, mutate := range map[string]func(*AuthorizationChallengeRequest){
		"response_type must be code": func(r *AuthorizationChallengeRequest) {
			r.ResponseType = "token"
		},
		"response_type is required": func(r *AuthorizationChallengeRequest) {
			r.ResponseType = ""
		},
		"scope is required": func(r *AuthorizationChallengeRequest) {
			r.Scope = ""
		},
		"interaction_types_supported is required": func(r *AuthorizationChallengeRequest) {
			r.InteractionTypesSupported = ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			client := newChallengeClient(t)
			req := initialChallenge()
			mutate(req)

			oauthErr := oauthErrFromChallenge(t, client, req)
			assert.Equal(t, oauth2.ErrCodeInvalidRequest, oauthErr.ErrorCode)
			assert.Equal(t, 400, oauthErr.HTTPStatus)
		})
	}
}

// An auth_session nobody issued and one that has expired are the same
// answer, so that the endpoint cannot be asked which handles exist.
func TestAuthorizationChallenge_UnknownAndExpiredAuthSessionAreIndistinguishable(t *testing.T) {
	client := newChallengeClient(t)

	unknown := oauthErrFromChallenge(t, client, &AuthorizationChallengeRequest{
		AuthSession:       "no-such-session",
		OpenID4VPResponse: `{"response":"x"}`,
	})

	// Open a real exchange and age it past its deadline.
	opened := challengeErr(t, client, initialChallenge())
	authCtx, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{
		AuthSession: opened.AuthSession,
	})
	require.NoError(t, err)
	authCtx.ExpiresAt = time.Now().Add(-time.Second).Unix()
	require.NoError(t, client.cacheService.AuthContext.Update(t.Context(), authCtx))

	expired := oauthErrFromChallenge(t, client, &AuthorizationChallengeRequest{
		AuthSession:       opened.AuthSession,
		OpenID4VPResponse: `{"response":"x"}`,
	})

	assert.Equal(t, unknown.ErrorCode, expired.ErrorCode)
	assert.Equal(t, unknown.Error(), expired.Error())
	assert.Equal(t, oauth2.ErrCodeInvalidGrant, unknown.ErrorCode)
}

// §5.1: a client_id sent with an auth_session must be the client the
// session was opened for.
func TestAuthorizationChallenge_IntermediateRequestFromAnotherClient(t *testing.T) {
	client := newChallengeClient(t)
	opened := challengeErr(t, client, initialChallenge())

	oauthErr := oauthErrFromChallenge(t, client, &AuthorizationChallengeRequest{
		AuthSession:       opened.AuthSession,
		ClientID:          "wallet-2",
		OpenID4VPResponse: `{"response":"x"}`,
	})
	assert.Equal(t, oauth2.ErrCodeInvalidRequest, oauthErr.ErrorCode)
	// On the message, not just the code: every later guard on this path
	// also answers invalid_request, so a test that stopped at the code
	// would keep passing with this check deleted.
	assert.Contains(t, oauthErr.Error(), "client_id does not match")

	// And the client the session WAS opened for gets past this check, so
	// the assertion above is about the mismatch rather than about sending
	// a client_id at all.
	sameClient := oauthErrFromChallenge(t, client, &AuthorizationChallengeRequest{
		AuthSession:       opened.AuthSession,
		ClientID:          "wallet-1",
		OpenID4VPResponse: `{"response":"x"}`,
	})
	assert.NotContains(t, sameClient.Error(), "client_id does not match")
}

// The wallet's own refusal is passed through rather than replaced: its
// reason is the one that explains what happened.
func TestAuthorizationChallenge_WalletErrorIsPassedThrough(t *testing.T) {
	client := newChallengeClient(t)
	opened := challengeErr(t, client, initialChallenge())

	challengeErr := challengeErr(t, client, &AuthorizationChallengeRequest{
		AuthSession:       opened.AuthSession,
		OpenID4VPResponse: `{"error":"access_denied","error_description":"user declined"}`,
	})

	assert.Equal(t, "access_denied", challengeErr.ErrorCode)
	assert.Equal(t, "user declined", challengeErr.ErrorDescription)
	assert.Equal(t, 400, challengeErr.HTTPStatus)
}

// The request asked for an encrypted response, so an unencrypted one is
// refused. Accepting a bare vp_token here would let anything that can
// reach the endpoint strip the encryption the wallet was told to apply.
func TestAuthorizationChallenge_UnencryptedResponseToAnEncryptedRequest(t *testing.T) {
	client := newChallengeClient(t)
	opened := challengeErr(t, client, initialChallenge())

	oauthErr := oauthErrFromChallenge(t, client, &AuthorizationChallengeRequest{
		AuthSession:       opened.AuthSession,
		OpenID4VPResponse: `{"vp_token":{"pid_auth":["ey.."]}}`,
	})
	assert.Equal(t, oauth2.ErrCodeInvalidRequest, oauthErr.ErrorCode)
	assert.Contains(t, oauthErr.Error(), "encrypted")
}

func TestAuthorizationChallenge_IntermediateRequestNeedsAResponse(t *testing.T) {
	client := newChallengeClient(t)
	opened := challengeErr(t, client, initialChallenge())

	oauthErr := oauthErrFromChallenge(t, client, &AuthorizationChallengeRequest{
		AuthSession: opened.AuthSession,
	})
	assert.Equal(t, oauth2.ErrCodeInvalidRequest, oauthErr.ErrorCode)
	assert.Contains(t, oauthErr.Error(), "openid4vp_response")
}

func TestInteractionTypeOffered(t *testing.T) {
	const want = "urn:openid:dcp:ia:openid4vp_presentation"

	for name, tc := range map[string]struct {
		supported string
		offered   bool
	}{
		"the comma-separated form the draft defines": {
			supported: "urn:openid:dcp:ia:auth_via_web,urn:openid:dcp:ia:openid4vp_presentation",
			offered:   true,
		},
		"whitespace after the comma": {
			supported: "urn:openid:dcp:ia:auth_via_web, urn:openid:dcp:ia:openid4vp_presentation",
			offered:   true,
		},
		"the space-separated form a wallet may send by OAuth habit": {
			supported: "urn:openid:dcp:ia:auth_via_web urn:openid:dcp:ia:openid4vp_presentation",
			offered:   true,
		},
		"a single value": {supported: want, offered: true},
		"empty":          {supported: "", offered: false},
		"another type only": {
			supported: "urn:openid:dcp:ia:auth_via_web",
			offered:   false,
		},
		"a longer URN that merely starts with it": {
			supported: "urn:openid:dcp:ia:openid4vp_presentation_v2",
			offered:   false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.offered, interactionTypeOffered(tc.supported, want))
		})
	}
}

// challengeDPoPProof mints a DPoP proof for the Authorization Challenge
// Endpoint. jti varies per call because the endpoint burns it: a second
// proof reusing one is a replay, not a retry.
func challengeDPoPProof(t *testing.T, key *ecdsa.PrivateKey, jti string) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"jti": jti,
		"iat": time.Now().Unix(),
		"htm": "POST",
		"htu": challengeIssuerURL + "/authorize-challenge",
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

// OpenID4VCI 1.1 §5.2: when DPoP is in use the auth_session MUST be
// associated with the DPoP public key, so that a stolen auth_session alone
// gets a thief nowhere.
func TestAuthorizationChallenge_AuthSessionIsBoundToTheDPoPKey(t *testing.T) {
	walletKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	thiefKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	open := func(t *testing.T) (*Client, string) {
		t.Helper()
		client := newChallengeClient(t)
		req := initialChallenge()
		req.DPOP = challengeDPoPProof(t, walletKey, "jti-open-exchange")
		opened := challengeErr(t, client, req)

		authCtx, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{
			AuthSession: opened.AuthSession,
		})
		require.NoError(t, err)
		require.NotEmpty(t, authCtx.AuthSessionDPoPThumbprint,
			"an exchange opened with a DPoP proof must record the key it is bound to")
		return client, opened.AuthSession
	}

	t.Run("another key cannot continue it", func(t *testing.T) {
		client, authSession := open(t)

		oauthErr := oauthErrFromChallenge(t, client, &AuthorizationChallengeRequest{
			AuthSession:       authSession,
			DPOP:              challengeDPoPProof(t, thiefKey, "jti-thief-attempt"),
			OpenID4VPResponse: `{"response":"x"}`,
		})
		assert.Equal(t, oauth2.ErrCodeInvalidDPoPProof, oauthErr.ErrorCode)
	})

	t.Run("no proof at all cannot continue it", func(t *testing.T) {
		client, authSession := open(t)

		oauthErr := oauthErrFromChallenge(t, client, &AuthorizationChallengeRequest{
			AuthSession:       authSession,
			OpenID4VPResponse: `{"response":"x"}`,
		})
		assert.Equal(t, oauth2.ErrCodeInvalidDPoPProof, oauthErr.ErrorCode)
		// On the description too: handing the empty proof to the parser
		// also produces invalid_dpop_proof, so the code alone would not
		// notice the explicit refusal going away.
		assert.Equal(t, oauth2.OAuthErrDPoPRequired.ErrorDescription, oauthErr.ErrorDescription)
	})

	t.Run("the key that opened it gets past the binding check", func(t *testing.T) {
		client, authSession := open(t)

		// Past the binding and on to the response itself, which this test
		// deliberately does not supply - the point is which guard it
		// reaches, not that it succeeds.
		oauthErr := oauthErrFromChallenge(t, client, &AuthorizationChallengeRequest{
			AuthSession:       authSession,
			DPOP:              challengeDPoPProof(t, walletKey, "jti-continue-exchange"),
			OpenID4VPResponse: `{"vp_token":{}}`,
		})
		assert.Equal(t, oauth2.ErrCodeInvalidRequest, oauthErr.ErrorCode)
		assert.Contains(t, oauthErr.Error(), "encrypted")
	})
}
