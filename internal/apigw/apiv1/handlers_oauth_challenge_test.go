package apiv1

import (
	"context"
	stdcrypto "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	authproviders "github.com/SUNET/vc/internal/apigw/auth_providers"
	apigwcache "github.com/SUNET/vc/internal/apigw/cache"
	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/oauth2"
	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/pki"
	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// challengeWalletKey is the key every test exchange is opened with. DPoP
// is required on both legs, so a fixture without one tests nothing that
// can happen.
var (
	challengeWalletKey = func() *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		return key
	}()

	// The endpoint burns each jti, so a fixture that reused one would see
	// its second request refused as a replay.
	challengeJTI atomic.Int64
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
				// The scope being ISSUED, which the presentation pipeline
				// resolves first...
				challengeScope: {
					Format: openid4vp.FormatSDJWTVC,
					VCTM:   &sdjwtvc.VCTM{VCT: "urn:example:issued:1"},
				},
				// ...and the scope being PRESENTED to authenticate it,
				// which the DCQL query is built from. A deployment has both
				// and the two are not the same thing.
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
		// Both browser-mediated providers running, which is what makes the
		// Selector's choice between them and openid4vp the thing under
		// test rather than a property of what happened to be initialised.
		authProviderSelector: authproviders.NewSelector(true, true),
	}
}

// initialChallenge is the request a conformant wallet opens an exchange
// with, so that each test below can vary exactly one thing about it.
//
// It carries PKCE because it offers auth_via_web: a wallet that says it
// can be sent into a browser must send a code_challenge, whichever
// interaction this server then picks. A fixture without one would not be
// a request a conformant wallet makes.
func initialChallenge(t *testing.T) *AuthorizationChallengeRequest {
	t.Helper()
	return &AuthorizationChallengeRequest{
		ResponseType:              "code",
		ClientID:                  "wallet-1",
		Scope:                     challengeScope,
		RedirectURI:               "https://wallet.example.com/cb",
		InteractionTypesSupported: "urn:openid:dcp:ia:openid4vp_presentation,urn:openid:dcp:ia:auth_via_web",
		CodeChallenge:             strings.Repeat("c", 43),
		CodeChallengeMethod:       "S256",
		DPOP:                      walletProof(t),
	}
}

// walletProof mints a fresh proof from the shared wallet key.
func walletProof(t *testing.T) string {
	t.Helper()
	return challengeDPoPProof(t, challengeWalletKey, fmt.Sprintf("jti-challenge-test-%d", challengeJTI.Add(1)))
}

// continueExchange is an intermediate request carrying whatever the test
// wants to send back, signed with the key the exchange was opened under.
func continueExchange(t *testing.T, authSession, openID4VPResponse string) *AuthorizationChallengeRequest {
	t.Helper()
	return &AuthorizationChallengeRequest{
		AuthSession:       authSession,
		OpenID4VPResponse: openID4VPResponse,
		DPOP:              walletProof(t),
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

	challengeErr := challengeErr(t, client, initialChallenge(t))

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

	challengeErr := challengeErr(t, client, initialChallenge(t))

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

// The request the wallet actually receives says that holder binding is
// required, because this endpoint verifies it.
//
// buildIssuanceAuthDCQL sets require_cryptographic_holder_binding to false
// - that is the browser-mediated flow's behaviour, which does not verify
// the binding - and the Interactive Authorization request is built from
// the same query. Without the narrowing in WithInteractiveAuthorization a
// wallet is invited to select an unbound credential and refused for
// missing cnf or KB-JWT once it has, after the user has consented.
//
// Asserted on the SERVED request object rather than on the helper, so the
// wiring is covered too: the helper could be correct and this handler
// still hand out the unnarrowed query.
func TestAuthorizationChallenge_PresentationRequestRequiresHolderBinding(t *testing.T) {
	client := newChallengeClient(t)

	challengeErr := challengeErr(t, client, initialChallenge(t))

	var envelope struct {
		Request string `json:"request"`
	}
	require.NoError(t, json.Unmarshal(challengeErr.OpenID4VPRequest, &envelope))
	require.NotEmpty(t, envelope.Request)

	claims := unsafeJWTClaims(t, envelope.Request)
	query, ok := claims["dcql_query"].(map[string]any)
	require.True(t, ok, "the request must carry a dcql_query object")
	credentials, ok := query["credentials"].([]any)
	require.True(t, ok)
	require.NotEmpty(t, credentials, "a query with no credentials would make this test vacuous")

	for _, entry := range credentials {
		credential, ok := entry.(map[string]any)
		require.True(t, ok)
		id := credential["id"]
		require.Contains(t, credential, "require_cryptographic_holder_binding",
			"query %v: the requirement must be stated, not left to a default", id)
		assert.Equal(t, true, credential["require_cryptographic_holder_binding"],
			"query %v: this endpoint rejects an unbound credential, so the request must not permit one", id)
	}
}

// A wallet that cannot do the interaction this scope needs is told which
// type is missing, not refused with a generic error.
func TestAuthorizationChallenge_WalletWithoutThePresentationInteraction(t *testing.T) {
	client := newChallengeClient(t)

	req := initialChallenge(t)
	req.InteractionTypesSupported = "urn:openid:dcp:ia:auth_via_web"

	challengeErr := challengeErr(t, client, req)

	assert.Equal(t, 400, challengeErr.HTTPStatus)
	assert.Equal(t, "missing_interaction_type", challengeErr.ErrorCode)
	assert.Contains(t, challengeErr.ErrorDescription, "urn:openid:dcp:ia:openid4vp_presentation")
}

// A scope whose Holder is established in a browser is answered with the
// web interaction rather than a presentation request.
//
// The Wallet is handed a request_uri and builds an authorization request
// from it, which is the Pushed Authorization Request this server already
// implements reached through the challenge endpoint - so the browser leg,
// the consent screen and the redirect back are unchanged.
func TestAuthorizationChallenge_ScopeThatNeedsAWebInteraction(t *testing.T) {
	client := newChallengeClient(t)
	client.cfg.APIGW.DataSources.Datastore.Scopes[challengeScope] = model.DatastoreScope{
		AuthProvider:    model.AuthProviderOIDC,
		AuthenticSource: "authentic-source",
	}

	req := initialChallenge(t)
	req.CodeChallenge = strings.Repeat("c", 43)
	req.CodeChallengeMethod = "S256"

	challengeErr := challengeErr(t, client, req)

	assert.Equal(t, 403, challengeErr.HTTPStatus)
	assert.Equal(t, "insufficient_authorization", challengeErr.ErrorCode)
	assert.Equal(t, "urn:openid:dcp:ia:auth_via_web", challengeErr.InteractionTypeRequired)
	assert.Contains(t, challengeErr.RequestURI, "urn:ietf:params:oauth:request_uri:")
	assert.Equal(t, webInteractionTTLSeconds, challengeErr.ExpiresIn)

	// The draft requires auth_session to be ABSENT when request_uri is
	// present: the request_uri is itself what associates the browser leg
	// with this exchange, and two handles for one association is one more
	// than can be kept consistent.
	assert.Empty(t, challengeErr.AuthSession)
	assert.Empty(t, challengeErr.OpenID4VPRequest, "this interaction asks for no presentation")

	// And the exchange is resolvable by the handle it DID hand out, which
	// is what /authorize will look it up by.
	authCtx, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{
		RequestURI: challengeErr.RequestURI,
	})
	require.NoError(t, err)
	assert.Equal(t, []string{challengeScope}, authCtx.Scopes)
	assert.Empty(t, authCtx.AuthSession, "no auth_session was issued, so none is stored")
	assert.NotEmpty(t, authCtx.AuthSessionDPoPThumbprint,
		"the code this produces is still bound to the key the exchange was opened under")
}

// The draft says a Wallet listing auth_via_web includes code_challenge in
// the initial request, and it is not optional here for the same reason it
// is not at PAR: the code this produces is redeemed over a channel this
// endpoint cannot see, with a browser leg in between that an attacker can
// reach.
func TestAuthorizationChallenge_WebInteractionRequiresPKCE(t *testing.T) {
	client := newChallengeClient(t)
	client.cfg.APIGW.DataSources.Datastore.Scopes[challengeScope] = model.DatastoreScope{
		AuthProvider:    model.AuthProviderOIDC,
		AuthenticSource: "authentic-source",
	}

	req := initialChallenge(t)
	req.CodeChallenge = ""
	req.CodeChallengeMethod = ""

	oauthErr := oauthErrFromChallenge(t, client, req)
	assert.Equal(t, oauth2.OAuthErrPKCERequired.ErrorCode, oauthErr.ErrorCode)
}

// The rule is about what the WALLET OFFERED, not about which interaction
// the server went on to select - which is where it had a hole.
//
// A confidential client listing auth_via_web and asking for a
// presentation-backed scope never reaches requireWebInteraction, so the
// check there never ran: the exchange was opened with no code_challenge at
// all, and the code it ends with is redeemed over a channel this endpoint
// cannot see. The draft asks for the challenge on the initial request of
// any wallet that says it can be sent into a browser, and that is where it
// is now enforced.
func TestAuthorizationChallenge_OfferingAuthViaWebRequiresPKCE(t *testing.T) {
	t.Run("even when the server selects the presentation interaction", func(t *testing.T) {
		client := newChallengeClient(t)

		// A CONFIDENTIAL client, so the public-client PKCE rule above
		// does not apply and this is the only thing that can refuse it.
		require.Equal(t, oauth2.ClientTypeConfidential,
			client.cfg.APIGW.Delivery.OpenID4VCI.Clients["wallet-1"].Type)

		req := initialChallenge(t)
		req.CodeChallenge = ""
		req.CodeChallengeMethod = ""

		oauthErr := oauthErrFromChallenge(t, client, req)
		assert.Equal(t, oauth2.OAuthErrPKCERequired.ErrorCode, oauthErr.ErrorCode)
	})

	t.Run("a wallet that does not offer it is unaffected", func(t *testing.T) {
		client := newChallengeClient(t)

		req := initialChallenge(t)
		req.InteractionTypesSupported = "urn:openid:dcp:ia:openid4vp_presentation"
		req.CodeChallenge = ""
		req.CodeChallengeMethod = ""

		// Answered with the interaction, not refused for PKCE.
		challengeErr := challengeErr(t, client, req)
		assert.Equal(t, errInsufficientAuthorization, challengeErr.ErrorCode)
	})
}

// A pre-authorised scope is not a browser scope: a Wallet cannot initiate
// that flow at all, which /op/par also refuses.
func TestAuthorizationChallenge_PreAuthorizedScopeIsRefused(t *testing.T) {
	client := newChallengeClient(t)
	client.cfg.APIGW.DataSources.Datastore.Scopes[challengeScope] = model.DatastoreScope{
		AuthProvider:    model.AuthProviderPreAuth,
		AuthenticSource: "authentic-source",
	}

	req := initialChallenge(t)
	req.CodeChallenge = strings.Repeat("c", 43)
	req.CodeChallengeMethod = "S256"

	oauthErr := oauthErrFromChallenge(t, client, req)
	assert.Equal(t, oauth2.ErrCodeInvalidScope, oauthErr.ErrorCode)
	assert.Contains(t, oauthErr.Error(), "pre-authorized")
}

// A deployment that has narrowed interaction_types_supported refuses the
// type it no longer offers, with the same error code: from the wallet's
// side the two are the same situation.
func TestAuthorizationChallenge_DeploymentThatDoesNotOfferTheInteraction(t *testing.T) {
	client := newChallengeClient(t)
	client.cfg.APIGW.Delivery.InteractiveAuthorization.InteractionTypesSupported = []string{"auth_via_web"}

	challengeErr := challengeErr(t, client, initialChallenge(t))

	assert.Equal(t, "missing_interaction_type", challengeErr.ErrorCode)
}

// The endpoint does not exist unless it is configured on, and says so the
// way an unrouted path would rather than as an OAuth refusal.
func TestAuthorizationChallenge_DisabledDeployment(t *testing.T) {
	client := newChallengeClient(t)
	disabled := false
	client.cfg.APIGW.Delivery.InteractiveAuthorization.Enable = &disabled

	oauthErr := oauthErrFromChallenge(t, client, initialChallenge(t))
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
			req := initialChallenge(t)
			mutate(req)

			oauthErr := oauthErrFromChallenge(t, client, req)
			assert.Equal(t, oauth2.ErrCodeInvalidRequest, oauthErr.ErrorCode)
			assert.Equal(t, 400, oauthErr.HTTPStatus)
		})
	}
}

// An auth_session nobody issued and one that has expired are the same
// answer, so that the endpoint cannot be asked which handles exist.
//
// And that answer is invalid_session. draft-ietf-oauth-first-party-apps
// §5.2.2 defines it for exactly this - an auth session that is invalid,
// expired or revoked - and a wallet looking for it to decide that its
// exchange is over cannot recognise invalid_grant, which belongs to the
// Token Endpoint and to spent authorization codes.
func TestAuthorizationChallenge_UnknownAndExpiredAuthSessionAreIndistinguishable(t *testing.T) {
	client := newChallengeClient(t)

	unknown := challengeErr(t, client, continueExchange(t, "no-such-session", `{"response":"x"}`))

	// Open a real exchange and age it past its deadline.
	opened := challengeErr(t, client, initialChallenge(t))
	authCtx, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{
		AuthSession: opened.AuthSession,
	})
	require.NoError(t, err)
	authCtx.ExpiresAt = time.Now().Add(-time.Second).Unix()
	require.NoError(t, client.cacheService.AuthContext.Update(t.Context(), authCtx))

	expired := challengeErr(t, client, continueExchange(t, opened.AuthSession, `{"response":"x"}`))

	assert.Equal(t, unknown.ErrorCode, expired.ErrorCode)
	assert.Equal(t, unknown.Error(), expired.Error())
	assert.Equal(t, errInvalidSession, unknown.ErrorCode)
	assert.Equal(t, 400, unknown.HTTPStatus)

	// A handle already claimed is the same condition and gets the same
	// answer: the exchange it named is over either way.
	reopened := challengeErr(t, client, initialChallenge(t))
	_, err = client.cacheService.AuthContext.ClaimAuthSession(t.Context(), reopened.AuthSession)
	require.NoError(t, err)

	claimed := challengeErr(t, client, continueExchange(t, reopened.AuthSession, `{"response":"x"}`))
	assert.Equal(t, errInvalidSession, claimed.ErrorCode)
}

// A store that will not answer is OURS, and must not be reported as the
// wallet's dead session.
//
// The difference decides what the wallet does next. invalid_session says
// the exchange is over and a new challenge is needed, so a wallet that
// believes it throws away an auth_session that a retry a second later
// would have resolved; server_error says to retry. One MongoDB blip
// therefore becomes a lost issuance rather than a slow one.
func TestAuthorizationChallenge_StoreFailuresAreServerErrors(t *testing.T) {
	t.Run("resolving the handle", func(t *testing.T) {
		client := newChallengeClient(t)
		opened := challengeErr(t, client, initialChallenge(t))

		failing := &failingAuthContextStore{AuthContextStore: client.cacheService.AuthContext}
		client.cacheService.AuthContext = failing
		failing.getErr = errors.New("connection refused")

		oauthErr := oauthErrFromChallenge(t, client,
			continueExchange(t, opened.AuthSession, `{"response":"x"}`))
		assert.Equal(t, oauth2.ErrCodeServerError, oauthErr.ErrorCode)
		assert.Equal(t, 500, oauthErr.HTTPStatus)
	})

	t.Run("claiming the handle", func(t *testing.T) {
		client := newChallengeClient(t)
		opened := challengeErr(t, client, initialChallenge(t))

		failing := &failingAuthContextStore{AuthContextStore: client.cacheService.AuthContext}
		client.cacheService.AuthContext = failing
		failing.claimErr = errors.New("connection refused")

		oauthErr := oauthErrFromChallenge(t, client,
			continueExchange(t, opened.AuthSession, `{"response":"x"}`))
		assert.Equal(t, oauth2.ErrCodeServerError, oauthErr.ErrorCode)
		assert.Equal(t, 500, oauthErr.HTTPStatus)
	})
}

// failingAuthContextStore makes one store call fail the way an unreachable
// MongoDB does - an error that is not ErrNoDocuments - and leaves every
// other call to the real store.
type failingAuthContextStore struct {
	cache.AuthContextStore
	getErr   error
	claimErr error
}

func (s *failingAuthContextStore) Get(ctx context.Context, query *cache.AuthorizationContext) (*cache.AuthorizationContext, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	return s.AuthContextStore.Get(ctx, query)
}

func (s *failingAuthContextStore) ClaimAuthSession(ctx context.Context, authSession string) (*cache.AuthorizationContext, error) {
	if s.claimErr != nil {
		return nil, s.claimErr
	}
	return s.AuthContextStore.ClaimAuthSession(ctx, authSession)
}

// The ephemeral key the request was built around is the server's to keep.
// Losing it is not something a wallet can do anything about, and an
// untyped error here would leave the endpoint through the generic
// envelope rather than as the OAuth error response its contract promises.
func TestAuthorizationChallenge_MissingEphemeralKeyIsAServerError(t *testing.T) {
	client := newChallengeClient(t)
	opened := challengeErr(t, client, initialChallenge(t))

	authCtx, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{
		AuthSession: opened.AuthSession,
	})
	require.NoError(t, err)
	client.cacheService.EphemeralEncryptionKey.Delete(t.Context(), authCtx.EphemeralEncryptionKeyID)

	oauthErr := oauthErrFromChallenge(t, client,
		continueExchange(t, opened.AuthSession, `{"response":"not-a-jwe"}`))
	assert.Equal(t, oauth2.ErrCodeServerError, oauthErr.ErrorCode)
	assert.Equal(t, 500, oauthErr.HTTPStatus)
}

// A scope this server has never been configured with is invalid_scope, and
// not an invitation to implement an interaction that would not help.
//
// missing_interaction_type names auth_via_web, so answering it for an
// unknown scope tells a wallet that implementing a browser step would get
// it this credential. It would not: there is no such scope here under any
// interaction.
func TestAuthorizationChallenge_UnknownScopeIsInvalidScope(t *testing.T) {
	client := newChallengeClient(t)

	// Allowed to the client, so the request gets past client
	// authentication and reaches the lookup this test is about, and
	// configured as a credential source nowhere.
	const unconfigured = "no-such-scope"
	wallet := client.cfg.APIGW.Delivery.OpenID4VCI.Clients["wallet-1"]
	wallet.Scopes = append(wallet.Scopes, unconfigured)
	client.cfg.APIGW.Delivery.OpenID4VCI.Clients["wallet-1"] = wallet

	req := initialChallenge(t)
	req.Scope = unconfigured

	oauthErr := oauthErrFromChallenge(t, client, req)
	assert.Equal(t, oauth2.ErrCodeInvalidScope, oauthErr.ErrorCode)
	assert.Equal(t, 400, oauthErr.HTTPStatus)
}

// §5.1: a client_id sent with an auth_session must be the client the
// session was opened for.
func TestAuthorizationChallenge_IntermediateRequestFromAnotherClient(t *testing.T) {
	client := newChallengeClient(t)
	opened := challengeErr(t, client, initialChallenge(t))

	mismatched := continueExchange(t, opened.AuthSession, `{"response":"x"}`)
	mismatched.ClientID = "wallet-2"
	oauthErr := oauthErrFromChallenge(t, client, mismatched)
	assert.Equal(t, oauth2.ErrCodeInvalidRequest, oauthErr.ErrorCode)
	// On the message, not just the code: every later guard on this path
	// also answers invalid_request, so a test that stopped at the code
	// would keep passing with this check deleted.
	assert.Contains(t, oauthErr.Error(), "client_id does not match")

	// And the client the session WAS opened for gets past this check, so
	// the assertion above is about the mismatch rather than about sending
	// a client_id at all.
	matching := continueExchange(t, opened.AuthSession, `{"response":"x"}`)
	matching.ClientID = "wallet-1"
	sameClient := oauthErrFromChallenge(t, client, matching)
	assert.NotContains(t, sameClient.Error(), "client_id does not match")
}

// The wallet's own refusal is passed through rather than replaced: its
// reason is the one that explains what happened.
func TestAuthorizationChallenge_WalletErrorIsPassedThrough(t *testing.T) {
	client := newChallengeClient(t)
	opened := challengeErr(t, client, initialChallenge(t))

	challengeErr := challengeErr(t, client, continueExchange(t, opened.AuthSession,
		`{"error":"access_denied","error_description":"user declined"}`))

	assert.Equal(t, "access_denied", challengeErr.ErrorCode)
	assert.Equal(t, "user declined", challengeErr.ErrorDescription)
	assert.Equal(t, 400, challengeErr.HTTPStatus)
}

// The request asked for an encrypted response, so an unencrypted one is
// refused. Accepting a bare vp_token here would let anything that can
// reach the endpoint strip the encryption the wallet was told to apply.
func TestAuthorizationChallenge_UnencryptedResponseToAnEncryptedRequest(t *testing.T) {
	client := newChallengeClient(t)
	opened := challengeErr(t, client, initialChallenge(t))

	oauthErr := oauthErrFromChallenge(t, client, continueExchange(t, opened.AuthSession,
		`{"vp_token":{"pid_auth":["ey.."]}}`))
	assert.Equal(t, oauth2.ErrCodeInvalidRequest, oauthErr.ErrorCode)
	assert.Contains(t, oauthErr.Error(), "encrypted")
}

func TestAuthorizationChallenge_IntermediateRequestNeedsAResponse(t *testing.T) {
	client := newChallengeClient(t)
	opened := challengeErr(t, client, initialChallenge(t))

	oauthErr := oauthErrFromChallenge(t, client, &AuthorizationChallengeRequest{
		AuthSession: opened.AuthSession,
		DPOP:        walletProof(t),
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
	return challengeDPoPProofWithHTU(t, key, jti, challengeIssuerURL+"/authorize-challenge")
}

// challengeDPoPProofWithHTU is the same proof with the htu the caller
// wants, for the cases where the SPELLING of the endpoint is the point.
func challengeDPoPProofWithHTU(t *testing.T, key *ecdsa.PrivateKey, jti, htu string) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"jti": jti,
		"iat": time.Now().Unix(),
		"htm": "POST",
		"htu": htu,
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

// challengeDPoPProofClaiming is challengeDPoPProof with extra claims in
// the payload, for the cases where what the proof SAYS about itself is the
// point.
func challengeDPoPProofClaiming(t *testing.T, key *ecdsa.PrivateKey, jti string, extra map[string]any) string {
	t.Helper()

	claims := jwt.MapClaims{
		"jti": jti,
		"iat": time.Now().Unix(),
		"htm": "POST",
		"htu": challengeIssuerURL + "/authorize-challenge",
	}
	for name, value := range extra {
		claims[name] = value
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
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
	thiefKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	open := func(t *testing.T) (*Client, string) {
		t.Helper()
		client := newChallengeClient(t)
		opened := challengeErr(t, client, initialChallenge(t))

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

		thiefProof := challengeDPoPProof(t, thiefKey,
			fmt.Sprintf("jti-challenge-test-%d", challengeJTI.Add(1)))
		oauthErr := oauthErrFromChallenge(t, client, &AuthorizationChallengeRequest{
			AuthSession:       authSession,
			DPOP:              thiefProof,
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

	t.Run("another key cannot continue it by CLAIMING the bound thumbprint", func(t *testing.T) {
		client, authSession := open(t)

		// The exchange's own thumbprint, read from the store, so the
		// forgery carries the real target rather than a guess.
		authCtx, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{
			AuthSession: authSession,
		})
		require.NoError(t, err)
		bound := authCtx.AuthSessionDPoPThumbprint
		require.NotEmpty(t, bound)

		// A proof genuinely signed by the thief's key, asserting the
		// victim's thumbprint in its payload. The thumbprint comes from
		// the proof's jwk HEADER, so a payload claim must not reach it -
		// it did, and this proof continued an exchange bound to a key the
		// sender does not hold.
		proof := challengeDPoPProofClaiming(t, thiefKey,
			fmt.Sprintf("jti-challenge-test-%d", challengeJTI.Add(1)),
			map[string]any{"thumbprint": bound})

		oauthErr := oauthErrFromChallenge(t, client, &AuthorizationChallengeRequest{
			AuthSession:       authSession,
			DPOP:              proof,
			OpenID4VPResponse: `{"response":"x"}`,
		})
		assert.Equal(t, oauth2.ErrCodeInvalidDPoPProof, oauthErr.ErrorCode,
			"a payload claim must not stand in for possession of the key")
	})

	t.Run("the key that opened it gets past the binding check", func(t *testing.T) {
		client, authSession := open(t)

		// Past the binding and on to the response itself, which this test
		// deliberately does not supply - the point is which guard it
		// reaches, not that it succeeds.
		oauthErr := oauthErrFromChallenge(t, client,
			continueExchange(t, authSession, `{"vp_token":{}}`))
		assert.Equal(t, oauth2.ErrCodeInvalidRequest, oauthErr.ErrorCode)
		assert.Contains(t, oauthErr.Error(), "encrypted")
	})
}

// One exchange, one authorization code. The handle has to stop resolving
// the moment it is used, and the way that was first written could not do
// it: the memory store hands out the pointer it holds, so clearing the
// field reached the stored document before Update ran, Update's
// deleteIndices then saw an empty AuthSession, and the auth_session index
// survived. A replay resolved the same session.
//
// Asserted on the STORE, not on the handler's return: a handler that
// refuses the second request for some unrelated reason would hide a handle
// that is still resolvable.
func TestAuthorizationChallenge_AuthSessionStopsResolvingOnceUsed(t *testing.T) {
	client := newChallengeClient(t)
	opened := challengeErr(t, client, initialChallenge(t))

	// Reach the claim: past every request check, and far enough in that the
	// presentation is attempted. It fails - there is no real VP token here -
	// which is the harder case for this assertion, because a failed exchange
	// must consume the handle just as a successful one does.
	_, err := client.OAuthAuthorizationChallenge(t.Context(),
		continueExchange(t, opened.AuthSession, `{"response":"not-a-jwe"}`))
	require.Error(t, err)

	resolved, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{
		AuthSession: opened.AuthSession,
	})
	require.ErrorIs(t, err, cache.ErrNoDocuments,
		"the auth_session must stop resolving once it has been used")
	require.Nil(t, resolved)
}

// The claim is the thing that decides it, so it is also asserted directly:
// two callers racing for one handle, exactly one winner.
func TestClaimAuthSessionAdmitsExactlyOne(t *testing.T) {
	client := newChallengeClient(t)
	opened := challengeErr(t, client, initialChallenge(t))

	first, err := client.cacheService.AuthContext.ClaimAuthSession(t.Context(), opened.AuthSession)
	require.NoError(t, err)
	require.NotNil(t, first)
	assert.NotEmpty(t, first.AuthSessionDPoPThumbprint,
		"the claimant is handed the exchange as it was, so it can still check the DPoP binding")
	assert.Empty(t, first.AuthSession,
		"but not the handle - persisting this document must not put it back")

	second, err := client.cacheService.AuthContext.ClaimAuthSession(t.Context(), opened.AuthSession)
	require.ErrorIs(t, err, cache.ErrNoDocuments)
	require.Nil(t, second)
}

// Claiming must not take the session itself out of the store - the
// authorization code the exchange produced is redeemed against it at the
// Token Endpoint, after the handle is long gone.
func TestClaimAuthSessionLeavesTheSessionRedeemable(t *testing.T) {
	client := newChallengeClient(t)
	opened := challengeErr(t, client, initialChallenge(t))

	claimed, err := client.cacheService.AuthContext.ClaimAuthSession(t.Context(), opened.AuthSession)
	require.NoError(t, err)

	byCode, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{
		Code: claimed.Code,
	})
	require.NoError(t, err)
	require.NotNil(t, byCode)
	assert.Equal(t, claimed.SessionID, byCode.SessionID)
	assert.Empty(t, byCode.AuthSession, "the stored exchange no longer carries the handle")
}

// DPoP is required, not honoured-when-offered. This server's Token
// Endpoint refuses an authorization_code request without a proof, so an
// exchange opened without one could never be redeemed - and until it
// expired its auth_session would be a bearer handle anyone who learned it
// could continue under their own key.
func TestAuthorizationChallenge_DPoPIsRequiredOnBothLegs(t *testing.T) {
	t.Run("the initial request", func(t *testing.T) {
		client := newChallengeClient(t)
		req := initialChallenge(t)
		req.DPOP = ""

		oauthErr := oauthErrFromChallenge(t, client, req)
		assert.Equal(t, oauth2.ErrCodeInvalidDPoPProof, oauthErr.ErrorCode)
		assert.Equal(t, oauth2.OAuthErrDPoPRequired.ErrorDescription, oauthErr.ErrorDescription)
	})

	t.Run("the intermediate request", func(t *testing.T) {
		client := newChallengeClient(t)
		opened := challengeErr(t, client, initialChallenge(t))

		oauthErr := oauthErrFromChallenge(t, client, &AuthorizationChallengeRequest{
			AuthSession:       opened.AuthSession,
			OpenID4VPResponse: `{"response":"x"}`,
		})
		assert.Equal(t, oauth2.ErrCodeInvalidDPoPProof, oauthErr.ErrorCode)
		assert.Equal(t, oauth2.OAuthErrDPoPRequired.ErrorDescription, oauthErr.ErrorDescription)
	})
}

// The binding has to outlive the handle. The authorization code the
// exchange produces is redeemed at the Token Endpoint, which binds the
// access token to whatever key signed the proof on THAT request - which
// says nothing about who opened the exchange. So the thumbprint recorded
// at the challenge is what carries the association forward, and claiming
// the handle must not take it with it.
func TestClaimAuthSessionKeepsTheCodesDPoPBinding(t *testing.T) {
	client := newChallengeClient(t)
	opened := challengeErr(t, client, initialChallenge(t))

	claimed, err := client.cacheService.AuthContext.ClaimAuthSession(t.Context(), opened.AuthSession)
	require.NoError(t, err)
	require.NotEmpty(t, claimed.AuthSessionDPoPThumbprint)

	// And on the STORED context, which is what the Token Endpoint reads -
	// the claimant's copy keeping it would prove nothing.
	stored, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{
		Code: claimed.Code,
	})
	require.NoError(t, err)
	assert.Equal(t, claimed.AuthSessionDPoPThumbprint, stored.AuthSessionDPoPThumbprint,
		"the code must still carry the key its authorization was obtained under")
	assert.Empty(t, stored.AuthSession, "only the handle is consumed")
}

// require_interactive_authorization says the browser-mediated path is not
// accepted. A deployment that advertises it and keeps /op/par working is
// telling wallets something untrue - and a wallet that believed it gave up
// a flow that would have worked.
func TestPARIsRefusedWhenOnlyInteractiveAuthorizationIsAccepted(t *testing.T) {
	par := func(t *testing.T, client *Client) error {
		t.Helper()
		_, err := client.OAuthPar(t.Context(), &openid4vci.PARRequest{
			ResponseType:        "code",
			ClientID:            "wallet-1",
			RedirectURI:         "https://wallet.example.com/cb",
			Scope:               challengeScope,
			CodeChallenge:       strings.Repeat("c", 43),
			CodeChallengeMethod: "S256",
		})
		return err
	}

	t.Run("refused when required", func(t *testing.T) {
		client := newChallengeClient(t)
		required := true
		client.cfg.APIGW.Delivery.InteractiveAuthorization.RequireInteractiveAuthorization = &required

		err := par(t, client)
		require.Error(t, err)

		var oauthErr *oauth2.OAuthError
		require.ErrorAs(t, err, &oauthErr)
		assert.Contains(t, oauthErr.Error(), "only interactive authorization")
	})

	t.Run("untouched when it is merely offered", func(t *testing.T) {
		// The default. Interactive Authorization being available says
		// nothing about the browser path, and this check must not start
		// refusing every deployment that enables the endpoint.
		client := newChallengeClient(t)

		if err := par(t, client); err != nil {
			assert.NotContains(t, err.Error(), "only interactive authorization")
		}
	})

	t.Run("untouched when the mechanism is off entirely", func(t *testing.T) {
		// Required() is false without Enable, so a stray
		// require_interactive_authorization cannot take the browser path
		// away from a deployment that never exposed the endpoint.
		client := newChallengeClient(t)
		disabled, required := false, true
		client.cfg.APIGW.Delivery.InteractiveAuthorization.Enable = &disabled
		client.cfg.APIGW.Delivery.InteractiveAuthorization.RequireInteractiveAuthorization = &required

		if err := par(t, client); err != nil {
			assert.NotContains(t, err.Error(), "only interactive authorization")
		}
	})
}

// presentationState is the state the exchange minted, which a wallet reads
// off the request object it was handed.
func presentationState(t *testing.T, client *Client, authSession string) string {
	t.Helper()
	authCtx, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{
		AuthSession: authSession,
	})
	require.NoError(t, err)
	return authCtx.State
}

// encryptedVPResponse builds the openid4vp_response a wallet would send:
// a JWE to the exchange's own ephemeral key, so the request gets PAST
// decryption and into the presentation pipeline, which is where the
// failures under test actually happen.
func encryptedVPResponse(t *testing.T, client *Client, authSession, payload string) string {
	t.Helper()

	authCtx, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{
		AuthSession: authSession,
	})
	require.NoError(t, err)

	_, publicJWK, err := client.EphemeralEncryptionKey(t.Context(), authCtx.EphemeralEncryptionKeyID)
	require.NoError(t, err)

	encrypted, err := jwe.Encrypt([]byte(payload),
		jwe.WithKey(jwa.ECDH_ES(), publicJWK),
		jwe.WithContentEncryption(jwa.A256GCM()))
	require.NoError(t, err)

	envelope, err := json.Marshal(map[string]string{"response": string(encrypted)})
	require.NoError(t, err)
	return string(envelope)
}

// Every answer from this endpoint is an OAuth error with its own status.
// An untyped error would reach the wallet through the generic envelope as
// a 500 - telling a wallet whose presentation merely did not verify that
// the server broke, and inviting a retry that can never succeed.
func TestAuthorizationChallenge_PresentationFailuresAreOAuthErrors(t *testing.T) {
	t.Run("a presentation that does not satisfy the request is invalid_grant", func(t *testing.T) {
		client := newChallengeClient(t)
		opened := challengeErr(t, client, initialChallenge(t))

		// A properly encrypted response carrying a vp_token for a
		// credential query that was never asked for: through decryption,
		// into the pipeline, refused there.
		response := encryptedVPResponse(t, client, opened.AuthSession,
			`{"state":"`+presentationState(t, client, opened.AuthSession)+`","vp_token":{"not_asked_for":["ey.."]}}`)

		oauthErr := oauthErrFromChallenge(t, client,
			continueExchange(t, opened.AuthSession, response))
		assert.Equal(t, oauth2.ErrCodeInvalidGrant, oauthErr.ErrorCode)
		assert.Equal(t, 400, oauthErr.HTTPStatus)
	})

	t.Run("a fault of ours is server_error, not the wallet's fault", func(t *testing.T) {
		client := newChallengeClient(t)

		// Take the issued scope's metadata away AFTER the exchange is
		// opened, which is what a half-applied config change looks like
		// from in here: the pipeline can no longer resolve the scope it is
		// supposed to be authenticating. That is ours, not the wallet's.
		opened := challengeErr(t, client, initialChallenge(t))
		response := encryptedVPResponse(t, client, opened.AuthSession,
			`{"state":"`+presentationState(t, client, opened.AuthSession)+`","vp_token":{"`+challengeAuthScope+`":["ey.."]}}`)
		delete(client.cfg.Common.CredentialMetadata, challengeScope)

		oauthErr := oauthErrFromChallenge(t, client,
			continueExchange(t, opened.AuthSession, response))
		assert.Equal(t, oauth2.ErrCodeServerError, oauthErr.ErrorCode)
		assert.Equal(t, 500, oauthErr.HTTPStatus)
	})

	t.Run("the wallet is not told which reason it was", func(t *testing.T) {
		client := newChallengeClient(t)
		opened := challengeErr(t, client, initialChallenge(t))

		response := encryptedVPResponse(t, client, opened.AuthSession,
			`{"state":"`+presentationState(t, client, opened.AuthSession)+`","vp_token":{"not_asked_for":["ey.."]}}`)
		oauthErr := oauthErrFromChallenge(t, client,
			continueExchange(t, opened.AuthSession, response))

		// "no documents for this person", "this credential is not trusted"
		// and "no token for that query" must not be distinguishable from
		// the outside - the reasons go to the log.
		assert.NotContains(t, oauthErr.ErrorDescription, "document")
		assert.NotContains(t, oauthErr.ErrorDescription, "trust")
		assert.NotContains(t, oauthErr.ErrorDescription, "VP Token")
	})
}

// The state ties the response to the request that asked for it. A response
// carrying someone else's state is someone else's presentation, however
// well it verifies (OpenID4VP §14.1).
//
// It also has to EXIST: the Authorization Challenge Request has no state
// parameter to echo, and openid4vp.VPResponse refuses a response whose
// state is missing - so an exchange that minted none could never be
// completed at all.
func TestAuthorizationChallenge_PresentationStateMustMatch(t *testing.T) {
	t.Run("the exchange mints one", func(t *testing.T) {
		client := newChallengeClient(t)
		opened := challengeErr(t, client, initialChallenge(t))

		state := presentationState(t, client, opened.AuthSession)
		require.NotEmpty(t, state, "a request built without a state could never be answered")

		// And the wallet is told what it is, on the request it is handed.
		var envelope struct {
			Request string `json:"request"`
		}
		require.NoError(t, json.Unmarshal(opened.OpenID4VPRequest, &envelope))
		assert.Equal(t, state, unsafeJWTClaims(t, envelope.Request)["state"])
	})

	t.Run("another exchange's state is refused", func(t *testing.T) {
		client := newChallengeClient(t)
		opened := challengeErr(t, client, initialChallenge(t))

		// Well-formed, correctly encrypted, naming a credential query that
		// WAS asked for - and carrying a state this exchange never issued.
		response := encryptedVPResponse(t, client, opened.AuthSession,
			`{"state":"a-state-from-somewhere-else","vp_token":{"`+challengeAuthScope+`":["ey.."]}}`)

		oauthErr := oauthErrFromChallenge(t, client,
			continueExchange(t, opened.AuthSession, response))
		assert.Equal(t, oauth2.ErrCodeInvalidGrant, oauthErr.ErrorCode)
		// On the wrapped CAUSE, not the code and not the description:
		// "ey.." is not a credential either, so this response is refused
		// downstream too and with the same code, and a test stopping at
		// invalid_grant would keep passing with the state check deleted.
		// The description deliberately says none of this - see the
		// "not told which reason" subtest above - so the cause is where
		// the distinction lives.
		require.NotNil(t, oauthErr.Cause)
		assert.Contains(t, oauthErr.Cause.Error(), "state does not match the request it answers")
	})

	t.Run("the right state gets past the check", func(t *testing.T) {
		client := newChallengeClient(t)
		opened := challengeErr(t, client, initialChallenge(t))

		response := encryptedVPResponse(t, client, opened.AuthSession,
			`{"state":"`+presentationState(t, client, opened.AuthSession)+`","vp_token":{"`+challengeAuthScope+`":["ey.."]}}`)

		// It fails further in - "ey.." is not a credential - but never on
		// the state, which is the assertion.
		_, err := client.OAuthAuthorizationChallenge(t.Context(),
			continueExchange(t, opened.AuthSession, response))
		require.Error(t, err)

		var oauthErr *oauth2.OAuthError
		require.ErrorAs(t, err, &oauthErr)
		if oauthErr.Cause != nil {
			assert.NotContains(t, oauthErr.Cause.Error(), "state does not match")
		}
	})
}

// The claim is not enough on its own: anything downstream that persists
// the claimed document would write the handle straight back and re-create
// its index, making the exchange claimable a second time.
//
// This is not hypothetical. A presentation-sourced scope ends in
// finalisePresentationVerification, which calls AuthContext.Update with
// the very context the handler was given - so the handle it had just
// consumed came back.
func TestClaimedContextCannotResurrectTheHandle(t *testing.T) {
	client := newChallengeClient(t)
	opened := challengeErr(t, client, initialChallenge(t))

	claimed, err := client.cacheService.AuthContext.ClaimAuthSession(t.Context(), opened.AuthSession)
	require.NoError(t, err)

	// Exactly what finalisePresentationVerification does with it.
	require.NoError(t, client.cacheService.AuthContext.Update(t.Context(), claimed))

	resolved, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{
		AuthSession: opened.AuthSession,
	})
	require.ErrorIs(t, err, cache.ErrNoDocuments,
		"persisting the claimed context must not make the handle resolvable again")
	require.Nil(t, resolved)

	// And the binding the authorization code inherits survived that write.
	stored, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{
		Code: claimed.Code,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, stored.AuthSessionDPoPThumbprint)
}

// The Authorization Challenge Endpoint now supplies an mdoc session
// transcript, so an mdoc presentation is no longer refused by name - and
// the transcript it supplies is the Interactive Authorization one, which
// is a different structure from either of the browser flow's.
//
// Verifying against the wrong transcript fails device-auth with nothing to
// point at, so this asserts on the BYTES rather than on "mdoc is accepted
// now": the latter would pass just as well with the direct-post builder
// wired in by mistake.
func TestAuthorizationChallenge_SuppliesTheInteractiveAuthorizationTranscript(t *testing.T) {
	client := newChallengeClient(t)
	opened := challengeErr(t, client, initialChallenge(t))

	authCtx, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{
		AuthSession: opened.AuthSession,
	})
	require.NoError(t, err)

	privateEphemeralJWK, ok := client.cacheService.EphemeralEncryptionKey.Get(t.Context(), authCtx.EphemeralEncryptionKeyID)
	require.True(t, ok)

	ia := &client.cfg.APIGW.Delivery.InteractiveAuthorization
	build := client.interactiveAuthorizationSessionTranscript(ia, authCtx, privateEphemeralJWK)
	require.NotNil(t, build, "the challenge endpoint must supply a transcript, or mdoc is refused")

	got, err := build()
	require.NoError(t, err)

	// Rebuilt from the exchange's own values rather than compared to a
	// constant, so the test says which inputs are bound rather than only
	// that some bytes matched.
	ephemeralPublicJWK, err := privateEphemeralJWK.PublicKey()
	require.NoError(t, err)
	thumbprint, err := ephemeralPublicJWK.Thumbprint(stdcrypto.SHA256)
	require.NoError(t, err)

	want, err := mdoc.BuildOID4VCIIAESessionTranscript(
		"OpenID4VCIIAEHandover",
		challengeIssuerURL+"/authorize-challenge",
		authCtx.Nonce,
		thumbprint,
	)
	require.NoError(t, err)
	assert.Equal(t, want, got)

	// And it is NOT the browser flow's transcript, which is the mistake
	// that would otherwise go unnoticed.
	directPost, err := mdoc.BuildOID4VPSessionTranscript(
		authCtx.ClientID, authCtx.Nonce, challengeIssuerURL+"/verification/direct_post", thumbprint)
	require.NoError(t, err)
	assert.NotEqual(t, directPost, got)

	// The endpoint goes in unprefixed: the "ia:" that keeps an SD-JWT VC
	// audience out of an ordinary Verifier's namespace must not appear in
	// the handover.
	assert.NotContains(t, string(got), "ia:https://")
}

// CS01_07: the handover label is hashed into the transcript, so a
// deployment has to be able to follow the working group without a release.
func TestAuthorizationChallenge_TranscriptLabelFollowsConfiguration(t *testing.T) {
	client := newChallengeClient(t)
	client.cfg.APIGW.Delivery.InteractiveAuthorization.MdocHandoverLabel = "OpenID4VCIIAHandover"

	opened := challengeErr(t, client, initialChallenge(t))
	authCtx, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{
		AuthSession: opened.AuthSession,
	})
	require.NoError(t, err)

	privateEphemeralJWK, ok := client.cacheService.EphemeralEncryptionKey.Get(t.Context(), authCtx.EphemeralEncryptionKeyID)
	require.True(t, ok)

	got, err := client.interactiveAuthorizationSessionTranscript(
		&client.cfg.APIGW.Delivery.InteractiveAuthorization, authCtx, privateEphemeralJWK)()
	require.NoError(t, err)

	assert.Contains(t, string(got), "OpenID4VCIIAHandover")
	assert.NotContains(t, string(got), "OpenID4VCIIAEHandover")
}

// The request_uri has to be usable at /authorize, which is the entire
// point of this interaction: the Wallet opens a browser at an
// authorization request built from it, and from there the existing flow
// runs unchanged.
//
// Asserted by actually calling OAuthAuthorize rather than by inspecting
// the stored context, because what matters is that the endpoint can read
// what the challenge wrote - the scope it reports, the wallet it names,
// and the consent redirect the browser leg starts at.
//
// It does NOT establish that the context's own client_id is right: the
// store resolves this query by its request_uri index alone and never
// compares the client_id OAuthAuthorize puts in it. That is pre-existing
// and not this change's to fix, but it means a test asserting "the
// handoff works" proves less than it looks like it does, so the limit is
// written down rather than assumed away.
func TestAuthorizationChallenge_WebInteractionHandsOffToAuthorize(t *testing.T) {
	client := newChallengeClient(t)
	client.cfg.APIGW.DataSources.Datastore.Scopes[challengeScope] = model.DatastoreScope{
		AuthProvider:    model.AuthProviderOIDC,
		AuthenticSource: "authentic-source",
	}

	req := initialChallenge(t)
	req.CodeChallenge = strings.Repeat("c", 43)
	req.CodeChallengeMethod = "S256"
	opened := challengeErr(t, client, req)
	require.NotEmpty(t, opened.RequestURI)

	reply, err := client.OAuthAuthorize(t.Context(), &openid4vci.AuthorizeRequest{
		RequestURI: opened.RequestURI,
	})
	require.NoError(t, err, "the request_uri the challenge handed out must resolve at /authorize")
	require.NotNil(t, reply)

	assert.Equal(t, challengeScope, reply.Scope)
	assert.Equal(t, "wallet-1", reply.WalletClientID)
	assert.Equal(t, "/authorization/consent", reply.RedirectURL,
		"the browser leg starts at consent, exactly as it does from /op/par")
}

// A proof is for the ENDPOINT, not for one spelling of its URL.
//
// A wallet builds htu from the URL it requested; this deployment writes
// public_url in configuration. RFC 9449 §4.3 says to compare the two after
// URI normalization because they legitimately differ - an explicit :443,
// a host in a different case - and a byte comparison refuses proofs that
// are correct for the URL they were sent to, with nothing the wallet can
// do about it.
//
// The path is excluded from that tolerance: it is the only thing
// separating this endpoint from the Token Endpoint on the same host.
func TestAuthorizationChallenge_HTUIsComparedAfterNormalization(t *testing.T) {
	for _, tc := range []struct {
		name     string
		htu      string
		accepted bool
	}{
		{name: "the default port written out", htu: "https://issuer.example.com:443/authorize-challenge", accepted: true},
		{name: "an uppercase host", htu: "https://Issuer.Example.COM/authorize-challenge", accepted: true},
		{name: "another endpoint on the same host", htu: challengeIssuerURL + "/token", accepted: false},
		{name: "another host", htu: "https://attacker.example.com/authorize-challenge", accepted: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := newChallengeClient(t)

			req := initialChallenge(t)
			req.DPOP = challengeDPoPProofWithHTU(t, challengeWalletKey,
				fmt.Sprintf("jti-challenge-htu-%d", challengeJTI.Add(1)), tc.htu)

			_, err := client.OAuthAuthorizationChallenge(t.Context(), req)
			require.Error(t, err, "the endpoint answers an initial request with an interaction either way")

			var oauthErr *oauth2.OAuthError
			if tc.accepted {
				if errors.As(err, &oauthErr) {
					assert.NotEqual(t, oauth2.ErrCodeInvalidDPoPProof, oauthErr.ErrorCode,
						"a proof for this endpoint must not be refused over the spelling of its URL")
				}
				return
			}
			require.ErrorAs(t, err, &oauthErr)
			assert.Equal(t, oauth2.ErrCodeInvalidDPoPProof, oauthErr.ErrorCode)
		})
	}
}

// The whole point of the endpoint is the authorization code it ends with,
// and every other test here stops short of it: they all fail on purpose,
// during decryption or in the pipeline. So the one path a conformant
// wallet actually takes - open, present, receive a code - had no coverage
// at all, and the line that returns the code could have been deleted
// without a single test noticing.
//
// The pipeline itself is replaced (see Client.issuanceAuth), because what
// it would need to say yes - a signing authority, a trust deployment, a
// datastore with documents - is not what this test is about. Everything
// between the wallet and the pipeline is real: the exchange is opened
// through the endpoint, the response is encrypted to the key the endpoint
// published, and the endpoint decrypts it and hands back the code it
// stored.
func TestAuthorizationChallenge_SuccessfulPresentationYieldsTheCode(t *testing.T) {
	client := newChallengeClient(t)
	opened := challengeErr(t, client, initialChallenge(t))

	stored, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{
		AuthSession: opened.AuthSession,
	})
	require.NoError(t, err)

	var (
		seenVPToken map[string][]string
		seenBinding issuanceAuthBinding
		calls       int
	)
	client.issuanceAuth = func(_ context.Context, authCtx *cache.AuthorizationContext, vpResponse *openid4vp.VPResponse, binding issuanceAuthBinding) (*issuanceAuthOutcome, error) {
		calls++
		seenVPToken = vpResponse.VPToken
		seenBinding = binding
		return &issuanceAuthOutcome{Scope: authCtx.Scopes[0]}, nil
	}

	response := encryptedVPResponse(t, client, opened.AuthSession,
		`{"state":"`+stored.State+`","vp_token":{"`+challengeAuthScope+`":["ey.."]}}`)

	reply, err := client.OAuthAuthorizationChallenge(t.Context(),
		continueExchange(t, opened.AuthSession, response))
	require.NoError(t, err)
	require.NotNil(t, reply)

	// The code is the one this exchange was built around, not a fresh
	// value: it is what the authorization context is stored under, and the
	// Token Endpoint finds the context by it.
	assert.Equal(t, stored.Code, reply.AuthorizationCode)
	assert.NotEmpty(t, reply.AuthorizationCode)

	byCode, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{
		Code: reply.AuthorizationCode,
	})
	require.NoError(t, err, "the code handed back must resolve the exchange that produced it")
	assert.Equal(t, stored.SessionID, byCode.SessionID)
	assert.Equal(t, stored.AuthSessionDPoPThumbprint, byCode.AuthSessionDPoPThumbprint,
		"the binding the Token Endpoint checks has to survive the exchange")

	// And the endpoint really did the work on the way: it decrypted the
	// response to the key it published, and bound the presentation to this
	// endpoint and to the state this exchange minted.
	require.Equal(t, 1, calls)
	assert.Contains(t, seenVPToken, challengeAuthScope)

	audience, err := client.cfg.APIGW.Delivery.InteractiveAuthorization.PresentationAudience(challengeIssuerURL)
	require.NoError(t, err)
	assert.Equal(t, audience, seenBinding.Audience)
	assert.Equal(t, stored.State, seenBinding.ExpectedState)

	// And it asked the pipeline to verify WHO presented this, not merely
	// that a credential a trusted Issuer signed was sent. Without it, a
	// copied credential plus a proof the copier signs themselves opens an
	// exchange under their own DPoP key - which is the one thing this
	// endpoint exists to prevent.
	assert.True(t, seenBinding.VerifyHolderBinding,
		"an exchange that establishes who is asking cannot accept an unverified holder proof")

	// The handle is spent either way, so the code cannot be collected twice.
	again := challengeErr(t, client, continueExchange(t, opened.AuthSession, response))
	assert.Equal(t, errInvalidSession, again.ErrorCode)
	assert.Equal(t, 1, calls, "a spent auth_session must not reach the pipeline again")
}

// The transcript test above builds one directly, which says that the
// builder is right and nothing about whether the ENDPOINT uses it. Wiring
// the direct-post builder in by mistake - or nil, which refuses mdoc by
// name - would leave it green, and that substitution is exactly the
// mistake worth catching: verifying against the wrong transcript fails
// device-auth with nothing to point at.
//
// So this drives a real encrypted response through the endpoint and
// asserts on the transcript the pipeline is actually handed. The pipeline
// itself is replaced (Client.issuanceAuth): what it would need to accept a
// genuine DeviceResponse is an mdoc signed over this transcript by a
// trusted IACA, which is a fixture about mdoc verification rather than
// about this endpoint's wiring.
func TestAuthorizationChallenge_PassesTheInteractiveAuthorizationTranscriptToThePipeline(t *testing.T) {
	client := newChallengeClient(t)
	opened := challengeErr(t, client, initialChallenge(t))

	authCtx, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{
		AuthSession: opened.AuthSession,
	})
	require.NoError(t, err)

	privateEphemeralJWK, ok := client.cacheService.EphemeralEncryptionKey.Get(t.Context(), authCtx.EphemeralEncryptionKeyID)
	require.True(t, ok)

	var seen issuanceAuthBinding
	client.issuanceAuth = func(_ context.Context, ctxArg *cache.AuthorizationContext, _ *openid4vp.VPResponse, binding issuanceAuthBinding) (*issuanceAuthOutcome, error) {
		seen = binding
		return &issuanceAuthOutcome{Scope: ctxArg.Scopes[0]}, nil
	}

	response := encryptedVPResponse(t, client, opened.AuthSession,
		`{"state":"`+authCtx.State+`","vp_token":{"`+challengeAuthScope+`":["ey.."]}}`)
	_, err = client.OAuthAuthorizationChallenge(t.Context(),
		continueExchange(t, opened.AuthSession, response))
	require.NoError(t, err)

	// nil is what refused mdoc by name before this PR, so it is the first
	// thing to rule out.
	require.NotNil(t, seen.MdocSessionTranscript,
		"the endpoint must supply a transcript, or every mdoc presentation is refused")

	got, err := seen.MdocSessionTranscript()
	require.NoError(t, err)

	ephemeralPublicJWK, err := privateEphemeralJWK.PublicKey()
	require.NoError(t, err)
	thumbprint, err := ephemeralPublicJWK.Thumbprint(stdcrypto.SHA256)
	require.NoError(t, err)

	want, err := mdoc.BuildOID4VCIIAESessionTranscript(
		"OpenID4VCIIAEHandover",
		challengeIssuerURL+"/authorize-challenge",
		authCtx.Nonce,
		thumbprint,
	)
	require.NoError(t, err)
	assert.Equal(t, want, got, "the endpoint must pass the Interactive Authorization transcript")

	// And not the browser flow's, which is the substitution the direct
	// builder test could not see.
	directPost, err := mdoc.BuildOID4VPSessionTranscript(
		authCtx.ClientID, authCtx.Nonce, challengeIssuerURL+"/verification/direct_post", thumbprint)
	require.NoError(t, err)
	assert.NotEqual(t, directPost, got)
}

// The request advertises ECDH-ES with A256GCM and the compact form, and
// anything else is refused BEFORE it reaches the decrypter.
//
// jwe.Decrypt on its own is considerably more accommodating than the
// request was: other content-encryption algorithms, the JSON
// serialization, a compressed payload, critical header parameters it
// ignores. None of that is what a conformant wallet sends, so accepting it
// only widens what an attacker may hand the decrypter.
func TestAuthorizationChallenge_ResponseMustUseTheAdvertisedEncryption(t *testing.T) {
	encryptWith := func(t *testing.T, client *Client, authSession string, opts ...jwe.EncryptOption) string {
		t.Helper()
		authCtx, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{
			AuthSession: authSession,
		})
		require.NoError(t, err)
		_, publicJWK, err := client.EphemeralEncryptionKey(t.Context(), authCtx.EphemeralEncryptionKeyID)
		require.NoError(t, err)

		opts = append([]jwe.EncryptOption{jwe.WithKey(jwa.ECDH_ES(), publicJWK)}, opts...)
		encrypted, err := jwe.Encrypt(
			[]byte(`{"state":"`+authCtx.State+`","vp_token":{"`+challengeAuthScope+`":["ey.."]}}`), opts...)
		require.NoError(t, err)

		envelope, err := json.Marshal(map[string]string{"response": string(encrypted)})
		require.NoError(t, err)
		return string(envelope)
	}

	for _, tc := range []struct {
		name string
		opts []jwe.EncryptOption
	}{
		{
			name: "another content encryption algorithm",
			opts: []jwe.EncryptOption{jwe.WithContentEncryption(jwa.A128GCM())},
		},
		{
			name: "a compressed payload",
			opts: []jwe.EncryptOption{
				jwe.WithContentEncryption(jwa.A256GCM()),
				jwe.WithCompress(jwa.Deflate()),
			},
		},
		{
			name: "the JSON serialization",
			opts: []jwe.EncryptOption{
				jwe.WithContentEncryption(jwa.A256GCM()),
				jwe.WithJSON(),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := newChallengeClient(t)
			opened := challengeErr(t, client, initialChallenge(t))

			// The pipeline must never be reached: the point is that the
			// refusal happens before anything is decrypted.
			reached := false
			client.issuanceAuth = func(context.Context, *cache.AuthorizationContext, *openid4vp.VPResponse, issuanceAuthBinding) (*issuanceAuthOutcome, error) {
				reached = true
				return &issuanceAuthOutcome{Scope: challengeScope}, nil
			}

			response := encryptWith(t, client, opened.AuthSession, tc.opts...)
			oauthErr := oauthErrFromChallenge(t, client,
				continueExchange(t, opened.AuthSession, response))

			assert.Equal(t, oauth2.ErrCodeInvalidRequest, oauthErr.ErrorCode)
			assert.False(t, reached, "a response that is not the advertised JWE must not be decrypted")
		})
	}

	t.Run("the advertised encryption gets through", func(t *testing.T) {
		client := newChallengeClient(t)
		opened := challengeErr(t, client, initialChallenge(t))

		reached := false
		client.issuanceAuth = func(context.Context, *cache.AuthorizationContext, *openid4vp.VPResponse, issuanceAuthBinding) (*issuanceAuthOutcome, error) {
			reached = true
			return &issuanceAuthOutcome{Scope: challengeScope}, nil
		}

		response := encryptWith(t, client, opened.AuthSession, jwe.WithContentEncryption(jwa.A256GCM()))
		_, err := client.OAuthAuthorizationChallenge(t.Context(),
			continueExchange(t, opened.AuthSession, response))
		require.NoError(t, err)
		assert.True(t, reached, "the encryption the request asked for must be accepted")
	})
}

// The auth_session's deadline is not the authorization code's.
//
// Both are kept in one ExpiresAt and the Token Endpoint checks that same
// field, so without a handover the code a wallet receives expires whenever
// the EXCHANGE was going to - however long the holder actually took to
// answer. At the configured maximum the code and its context expire
// together, which is a code that was never redeemable.
func TestAuthorizationChallenge_SuccessfulPresentationStartsTheCodesLifetime(t *testing.T) {
	client := newChallengeClient(t)
	opened := challengeErr(t, client, initialChallenge(t))

	stored, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{
		AuthSession: opened.AuthSession,
	})
	require.NoError(t, err)

	// Age the exchange to a second before its deadline, which is what a
	// holder who took their time looks like from here.
	almostOver := time.Now().Add(time.Second).Unix()
	stored.ExpiresAt = almostOver
	require.NoError(t, client.cacheService.AuthContext.Update(t.Context(), stored))

	client.issuanceAuth = func(_ context.Context, authCtx *cache.AuthorizationContext, _ *openid4vp.VPResponse, _ issuanceAuthBinding) (*issuanceAuthOutcome, error) {
		return &issuanceAuthOutcome{Scope: authCtx.Scopes[0]}, nil
	}

	response := encryptedVPResponse(t, client, opened.AuthSession,
		`{"state":"`+stored.State+`","vp_token":{"`+challengeAuthScope+`":["ey.."]}}`)
	reply, err := client.OAuthAuthorizationChallenge(t.Context(),
		continueExchange(t, opened.AuthSession, response))
	require.NoError(t, err)

	byCode, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{
		Code: reply.AuthorizationCode,
	})
	require.NoError(t, err)
	assert.Greater(t, byCode.ExpiresAt, almostOver,
		"the code must get its own window, not inherit the exchange's remaining seconds")
	assert.GreaterOrEqual(t, byCode.ExpiresAt, time.Now().Add(authorizationCodeTTL-time.Minute).Unix(),
		"and that window is the authorization code's lifetime")
}

// The presentation state must not survive into an auth_via_web exchange.
//
// newChallengeAuthContext mints one so an OpenID4VP response has something
// to echo, and this interaction has no OpenID4VP response: the Wallet is
// never told the value and nothing ever checks it. Left on the context it
// comes back as `state` in the Token Response - a random value the Wallet
// never sent, which a Wallet correlating its own OAuth state is entitled
// to reject.
func TestAuthorizationChallenge_WebInteractionCarriesNoPresentationState(t *testing.T) {
	client := newChallengeClient(t)
	client.cfg.APIGW.DataSources.Datastore.Scopes[challengeScope] = model.DatastoreScope{
		AuthProvider:    model.AuthProviderOIDC,
		AuthenticSource: "authentic-source",
	}

	opened := challengeErr(t, client, initialChallenge(t))
	require.NotEmpty(t, opened.RequestURI)

	authCtx, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{
		RequestURI: opened.RequestURI,
	})
	require.NoError(t, err)
	assert.Empty(t, authCtx.State,
		"a browser leg the wallet gave no state for must not invent one")

	// The presentation interaction still mints one, so this is about the
	// web path rather than about the field being unused everywhere.
	presentation := newChallengeClient(t)
	presentationOpened := challengeErr(t, presentation, initialChallenge(t))
	presentationCtx, err := presentation.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{
		AuthSession: presentationOpened.AuthSession,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, presentationCtx.State)
}

// A dangerous redirect_uri scheme must be refused here, as it is at
// /op/par, and for a reason that only bites on this endpoint.
//
// A wallet authenticated by attestation has no redirect_uri allowlist to
// be checked against, so whatever it sends is recorded as WalletURI. The
// auth_via_web interaction then carries that context into the browser
// leg, and the consent page renders it as a template.URL - which
// deliberately turns off html/template's scheme sanitisation so custom
// wallet schemes survive. "javascript:" therefore becomes script
// execution in the APIGW's own origin once the user consents.
func TestAuthorizationChallenge_RefusesADangerousRedirectURI(t *testing.T) {
	for _, redirectURI := range []string{
		"javascript:alert(document.domain)//",
		"JavaScript:alert(1)",
		"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
	} {
		t.Run(redirectURI, func(t *testing.T) {
			client := newChallengeClient(t)

			req := initialChallenge(t)
			req.RedirectURI = redirectURI

			oauthErr := oauthErrFromChallenge(t, client, req)
			assert.Equal(t, oauth2.ErrCodeInvalidRequest, oauthErr.ErrorCode)
			assert.Contains(t, oauthErr.Error(), "invalid redirect_uri")
		})
	}

	// Refused before anything is stored, so there is no context carrying
	// the value for a later leg to render.
	t.Run("nothing is stored for a refused request", func(t *testing.T) {
		client := newChallengeClient(t)

		req := initialChallenge(t)
		req.RedirectURI = "javascript:alert(1)//"
		_, err := client.OAuthAuthorizationChallenge(t.Context(), req)
		require.Error(t, err)

		stored, err := client.cacheService.AuthContext.Get(t.Context(),
			&cache.AuthorizationContext{Code: ""})
		assert.Error(t, err)
		assert.Nil(t, stored)
	})
}

// A request_uri stays resolvable, so /authorize can be entered more than
// once - and each visit extended the deadline another authorizationCodeTTL
// from now. Visits at minutes 0, 4, 8 and 12 all pass the expiry check and
// the last pushes expiry to minute 17, past the retention MongoDB anchors
// to created_at. Beyond that the server advertises a code against a
// document already scheduled for deletion, and only in HA, where nothing
// else would notice.
func TestCodeDeadlineNeverOutlivesTheDocument(t *testing.T) {
	t.Run("a fresh context gets the full code lifetime", func(t *testing.T) {
		deadline := codeDeadlineWithin(time.Now())
		assert.InDelta(t, time.Now().Add(authorizationCodeTTL).Unix(), deadline, 2)
	})

	t.Run("a context near the end of its retention gets what is left", func(t *testing.T) {
		// Twelve minutes into a fifteen-minute retention: three minutes
		// left, not five.
		createdAt := time.Now().Add(-12 * time.Minute)
		deadline := codeDeadlineWithin(createdAt)

		assert.InDelta(t, createdAt.Add(apigwcache.AuthContextTTL).Unix(), deadline, 2)
		assert.Less(t, deadline, time.Now().Add(authorizationCodeTTL).Unix(),
			"the deadline must be cut short rather than run past the document")
	})

	t.Run("however many times it is extended", func(t *testing.T) {
		createdAt := time.Now().Add(-14 * time.Minute)
		retention := createdAt.Add(apigwcache.AuthContextTTL).Unix()
		for range 5 {
			assert.LessOrEqual(t, codeDeadlineWithin(createdAt), retention)
		}
	})

	// A context with no creation time recorded is left alone rather than
	// given a deadline in the past.
	t.Run("an unknown creation time is not a zero deadline", func(t *testing.T) {
		deadline := codeDeadlineWithin(time.Time{})
		assert.InDelta(t, time.Now().Add(authorizationCodeTTL).Unix(), deadline, 2)
	})
}
