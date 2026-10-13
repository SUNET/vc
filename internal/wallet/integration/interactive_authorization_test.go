//go:build integration

package integration

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"github.com/SUNET/vc/internal/wallet/config"
	"github.com/SUNET/vc/internal/wallet/credential"
	"github.com/SUNET/vc/pkg/openid4vp"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// interactiveAuthorizationRequest builds the openid4vp_request the mock
// issuer puts in its 403, advertising an encryption key so the wallet has
// something to encrypt its response to.
func (env *testEnvironment) interactiveAuthorizationRequest() map[string]any {
	env.mu.Lock()
	defer env.mu.Unlock()

	if env.challengeKey == nil {
		priv, err := ecdh.P256().GenerateKey(rand.Reader)
		require.NoError(env.t, err)
		key, err := jwk.Import(priv)
		require.NoError(env.t, err)
		require.NoError(env.t, key.Set(jwk.KeyIDKey, "ia-enc"))
		env.challengeKey = key
	}

	public, err := env.challengeKey.PublicKey()
	require.NoError(env.t, err)

	ro := map[string]any{
		"response_type": "vp_token",
		"response_mode": "ia_post.jwt",
		"client_id":     "x509_san_dns:issuer.example.com",
		"nonce":         "ia-nonce",
		"state":         "ia-state",
		"dcql_query": map[string]any{
			"credentials": []map[string]any{{
				"id":     "pid_auth",
				"format": "dc+sd-jwt",
				"meta":   map[string]any{"vct_values": []string{"https://credentials.example.com/identity_credential"}},
			}},
		},
		"client_metadata": map[string]any{
			"jwks": map[string]any{"keys": []any{publicJWKMap(env.t, public)}},
		},
	}
	return ro
}

func publicJWKMap(t *testing.T, key jwk.Key) map[string]any {
	t.Helper()
	raw, err := json.Marshal(key)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	return m
}

// decryptIAResponse opens what the wallet sent back, which is how these
// tests check that the encryption was real rather than merely present.
func (env *testEnvironment) decryptIAResponse(t *testing.T, envelope string) map[string]any {
	t.Helper()

	var wrapper struct {
		Response string `json:"response"`
	}
	require.NoError(t, json.Unmarshal([]byte(envelope), &wrapper))
	require.NotEmpty(t, wrapper.Response, "the wallet must encrypt its response for ia_post.jwt")

	decrypted, err := jwe.Decrypt([]byte(wrapper.Response), jwe.WithKey(jwa.ECDH_ES(), env.challengeKey))
	require.NoError(t, err, "the response must be encrypted to the key the request advertised")

	var payload map[string]any
	require.NoError(t, json.Unmarshal(decrypted, &payload))
	return payload
}

// The whole Interactive Authorization exchange, driven by the wallet
// against an issuer that asks for a presentation.
//
// This is the test the 1.1 work needed and did not have: everything else
// exercises our issuer against our own expectations, while this drives a
// wallet through the published protocol and checks what arrives on the
// wire at each step.
func TestVCI_InteractiveAuthorization(t *testing.T) {
	env := setupTestEnvironment(t, func(e *testEnvironment) {
		e.iaMetadataSpelling = "normative"
	})
	defer env.cleanup()

	env.seedPresentableCredential(t)
	env.addScenario(config.Scenario{
		Name: "interactive-authorization",
		Type: "vci",
		VCI: &config.VCIScenario{
			IssuerURL:                   env.issuerServer.URL,
			Scope:                       "pid",
			UseInteractiveAuthorization: true,
			CredentialConfigurationID:   "test_credential",
		},
	})

	result, err := env.wallet.RunScenario(t.Context(), "interactive-authorization")
	require.NoError(t, err)
	require.True(t, result.Success, "scenario failed: %s", result.Error)

	env.mu.Lock()
	requests := env.challengeRequests
	env.mu.Unlock()
	require.Len(t, requests, 2, "one initial challenge and one intermediate request")

	initial, intermediate := requests[0], requests[1]

	// The initial request says what the wallet can do and binds the
	// exchange to a key.
	assert.Equal(t, "code", initial.Get("response_type"))
	assert.Contains(t, initial.Get("interaction_types_supported"), "urn:openid:dcp:ia:openid4vp_presentation")
	assert.Equal(t, "S256", initial.Get("code_challenge_method"))
	assert.NotEmpty(t, initial.Get("code_challenge"))
	assert.Empty(t, initial.Get("auth_session"), "there is no exchange yet to continue")

	// The intermediate request continues the exchange and carries nothing
	// from the first but the handle.
	assert.Equal(t, "test-auth-session", intermediate.Get("auth_session"))
	assert.NotEmpty(t, intermediate.Get("openid4vp_response"))
	assert.Empty(t, intermediate.Get("response_type"), "an intermediate request is not a fresh authorization request")

	// And the response really is encrypted to the advertised key.
	payload := env.decryptIAResponse(t, intermediate.Get("openid4vp_response"))
	assert.Equal(t, "ia-state", payload["state"], "the response must echo the request's state")
	require.Contains(t, payload, "vp_token")

	// The code the exchange produced is what the wallet redeemed, with
	// the PKCE verifier for the challenge it came from.
	env.mu.Lock()
	tokenRequests := env.tokenRequestsReceived
	env.mu.Unlock()
	require.Len(t, tokenRequests, 1)
	assert.Equal(t, "test-ia-code", tokenRequests[0]["code"])
	assert.NotEmpty(t, tokenRequests[0]["code_verifier"], "PKCE is only worth anything if the verifier is sent")
}

// A wallet has to read whichever spelling the issuer published, because
// the draft's change log and its normative text disagree about both
// metadata members (openid/OpenID4VCI#811).
func TestVCI_InteractiveAuthorization_MetadataSpellings(t *testing.T) {
	for _, spelling := range []string{"normative", "changelog"} {
		t.Run(spelling, func(t *testing.T) {
			env := setupTestEnvironment(t, func(e *testEnvironment) {
				e.iaMetadataSpelling = spelling
				// Not asked for by the scenario: the wallet should take
				// this path because the issuer says it accepts nothing
				// else.
				e.iaRequireIA = true
			})
			defer env.cleanup()

			env.seedPresentableCredential(t)
			env.addScenario(config.Scenario{
				Name: "ia-discovery",
				Type: "vci",
				VCI: &config.VCIScenario{
					IssuerURL:                 env.issuerServer.URL,
					Scope:                     "pid",
					CredentialConfigurationID: "test_credential",
				},
			})

			result, err := env.wallet.RunScenario(t.Context(), "ia-discovery")
			require.NoError(t, err)
			require.True(t, result.Success, "scenario failed: %s", result.Error)

			env.mu.Lock()
			count := len(env.challengeRequests)
			env.mu.Unlock()
			assert.Equal(t, 2, count,
				"the wallet must find the challenge endpoint under the %s spelling", spelling)
		})
	}
}

// An issuer that needs an interaction the wallet did not offer answers
// missing_interaction_type, and the wallet reports it rather than looping.
func TestVCI_InteractiveAuthorization_MissingInteractionType(t *testing.T) {
	env := setupTestEnvironment(t, func(e *testEnvironment) {
		e.iaMetadataSpelling = "normative"
		e.iaInteractionType = "urn:openid:dcp:ia:auth_via_web"
	})
	defer env.cleanup()

	env.addScenario(config.Scenario{
		Name: "ia-missing-type",
		Type: "vci",
		VCI: &config.VCIScenario{
			IssuerURL:                   env.issuerServer.URL,
			Scope:                       "pid",
			UseInteractiveAuthorization: true,
			// Only the one this wallet implements.
			InteractionTypes:          []string{"urn:openid:dcp:ia:openid4vp_presentation"},
			CredentialConfigurationID: "test_credential",
		},
	})

	result, err := env.wallet.RunScenario(t.Context(), "ia-missing-type")
	require.NoError(t, err)
	require.False(t, result.Success)
	assert.Contains(t, result.Error, "missing_interaction_type")
}

// The Key Binding JWT's audience is the prefixed challenge endpoint
// origin, not the request's client_id. That binding is what stops a
// presentation made for one Authorization Server being relayed to
// another, so it is asserted on the token that actually went out.
func TestVCI_InteractiveAuthorization_KeyBindingAudience(t *testing.T) {
	env := setupTestEnvironment(t, func(e *testEnvironment) {
		e.iaMetadataSpelling = "normative"
	})
	defer env.cleanup()

	env.seedPresentableCredential(t)
	env.addScenario(config.Scenario{
		Name: "ia-audience",
		Type: "vci",
		VCI: &config.VCIScenario{
			IssuerURL:                   env.issuerServer.URL,
			Scope:                       "pid",
			UseInteractiveAuthorization: true,
			CredentialConfigurationID:   "test_credential",
		},
	})

	result, err := env.wallet.RunScenario(t.Context(), "ia-audience")
	require.NoError(t, err)
	require.True(t, result.Success, "scenario failed: %s", result.Error)

	env.mu.Lock()
	intermediate := env.challengeRequests[1]
	env.mu.Unlock()

	payload := env.decryptIAResponse(t, intermediate.Get("openid4vp_response"))
	tokens, ok := payload["vp_token"].(map[string]any)
	require.True(t, ok)
	presented := tokens["pid_auth"].([]any)[0].(string)

	wantAudience, err := openid4vp.CanonicalOrigin(env.oauth2Server.URL + "/authorize-challenge")
	require.NoError(t, err)

	assert.Contains(t, keyBindingAudience(t, presented), "ia:"+wantAudience)
}

// seedPresentableCredential puts a credential in the wallet that
// satisfies the mock issuer's DCQL query, so the presentation interaction
// has something to present.
func (env *testEnvironment) seedPresentableCredential(t *testing.T) {
	t.Helper()
	env.wallet.Store().Add(&credential.StoredCredential{
		RawCredential: createMockSDJWT(t),
		Format:        "dc+sd-jwt",
		VCT:           "https://credentials.example.com/identity_credential",
		IssuerURL:     "https://issuer.example.com",
		ScenarioName:  "setup",
	})
}

// keyBindingAudience reads the aud claim off the Key Binding JWT at the
// end of an SD-JWT presentation.
func keyBindingAudience(t *testing.T, presented string) string {
	t.Helper()

	parts := strings.Split(presented, "~")
	require.Greater(t, len(parts), 1, "an SD-JWT presentation ends with a key binding JWT")
	kbJWT := parts[len(parts)-1]
	require.NotEmpty(t, kbJWT, "the presentation carries no key binding JWT")

	claims := jwtv5.MapClaims{}
	_, _, err := jwtv5.NewParser().ParseUnverified(kbJWT, claims)
	require.NoError(t, err)

	audience, _ := claims["aud"].(string)
	return audience
}
