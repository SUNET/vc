//go:build integration

package integration

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SUNET/vc/internal/wallet/config"
	"github.com/SUNET/vc/internal/wallet/credential"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/sdjwtvc"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// iaRequestedVCT is the type the mock issuer's DCQL query asks for.
const iaRequestedVCT = "https://credentials.example.com/identity_credential"

// validateIAPresentation is the mock challenge endpoint's check of the
// openid4vp_response: decrypted with the advertised key, every presented
// credential of the requested type, and every Key Binding JWT signed by
// the key in that credential's cnf and bound to this exchange.
func (env *testEnvironment) validateIAPresentation(envelope string) error {
	env.mu.Lock()
	decryptionKey := env.challengeKey
	env.mu.Unlock()
	if decryptionKey == nil {
		return fmt.Errorf("no openid4vp_request was issued")
	}

	var wrapper struct {
		Response string `json:"response"`
	}
	if err := json.Unmarshal([]byte(envelope), &wrapper); err != nil || wrapper.Response == "" {
		return fmt.Errorf("openid4vp_response is not an encrypted response envelope")
	}
	decrypted, err := jwe.Decrypt([]byte(wrapper.Response), jwe.WithKey(jwa.ECDH_ES(), decryptionKey))
	if err != nil {
		return fmt.Errorf("decrypting openid4vp_response: %w", err)
	}

	var payload struct {
		VPToken map[string][]string `json:"vp_token"`
	}
	if err := json.Unmarshal(decrypted, &payload); err != nil {
		return fmt.Errorf("reading vp_token: %w", err)
	}
	presented := payload.VPToken["pid_auth"]
	if len(presented) == 0 {
		return fmt.Errorf("vp_token carries no presentation for pid_auth")
	}

	origin, err := openid4vp.CanonicalOrigin(env.oauth2Server.URL + "/authorize-challenge")
	if err != nil {
		return err
	}
	for _, p := range presented {
		if err := checkHolderBoundPresentation(p, iaRequestedVCT, "ia-nonce", "ia:"+origin); err != nil {
			return err
		}
	}
	return nil
}

// checkHolderBoundPresentation verifies an SD-JWT presentation's type and
// that its Key Binding JWT is signed by the credential's cnf key with the
// expected nonce, audience and sd_hash. The issuer signature is not
// checked: the mock issuer keys are throwaway.
func checkHolderBoundPresentation(presentation, wantVCT, wantNonce, wantAud string) error {
	issuerJWT, _, _ := strings.Cut(presentation, "~")
	issuerClaims := jwtv5.MapClaims{}
	if _, _, err := jwtv5.NewParser().ParseUnverified(issuerJWT, issuerClaims); err != nil {
		return fmt.Errorf("reading the issuer-signed JWT: %w", err)
	}
	if vct, _ := issuerClaims["vct"].(string); vct != wantVCT {
		return fmt.Errorf("presented vct %q, requested %q", vct, wantVCT)
	}

	// The production verifier: signature against cnf, typ, nonce, aud, iat,
	// and sd_hash under the credential's _sd_alg.
	return sdjwtvc.VerifyKeyBinding(presentation, issuerClaims, sdjwtvc.KeyBindingExpectations{
		Nonce:    wantNonce,
		Audience: wantAud,
	})
}

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
				"meta":   map[string]any{"vct_values": []string{iaRequestedVCT}},
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

	// Exactly, not Contains. The binding is the whole point of the
	// prefixed audience, and "ia:https://issuer.example" is a prefix of
	// "ia:https://issuer.example.evil" - a Contains assertion would pass
	// for a presentation bound to an attacker's origin.
	assert.Equal(t, "ia:"+wantAudience, keyBindingAudience(t, presented))
}

// seedPresentableCredential puts a credential in the wallet that
// satisfies the mock issuer's DCQL query, so the presentation interaction
// has something to present.
func (env *testEnvironment) seedPresentableCredential(t *testing.T) {
	t.Helper()
	env.wallet.Store().Add(&credential.StoredCredential{
		RawCredential: createMockSDJWTWithVCT(t, iaRequestedVCT, &env.holderKey.PublicKey),
		Format:        "dc+sd-jwt",
		VCT:           iaRequestedVCT,
		IssuerURL:     "https://issuer.example.com",
		ScenarioName:  "setup",
	})
}

// The mock challenge endpoint checks holder binding, so a credential bound
// to someone else's key cannot be redeemed for a code.
func TestVCI_InteractiveAuthorization_RejectsAForeignHolderBinding(t *testing.T) {
	env := setupTestEnvironment(t, func(e *testEnvironment) {
		e.iaMetadataSpelling = "normative"
	})
	defer env.cleanup()

	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	env.wallet.Store().Add(&credential.StoredCredential{
		RawCredential: createMockSDJWTWithVCT(t, iaRequestedVCT, &other.PublicKey),
		Format:        "dc+sd-jwt",
		VCT:           iaRequestedVCT,
		IssuerURL:     "https://issuer.example.com",
		ScenarioName:  "setup",
	})
	env.addScenario(config.Scenario{
		Name: "ia-foreign-holder",
		Type: "vci",
		VCI: &config.VCIScenario{
			IssuerURL:                   env.issuerServer.URL,
			Scope:                       "pid",
			UseInteractiveAuthorization: true,
			CredentialConfigurationID:   "test_credential",
		},
	})

	result, err := env.wallet.RunScenario(t.Context(), "ia-foreign-holder")
	require.NoError(t, err)
	require.False(t, result.Success, "a presentation with an invalid holder binding must not earn a code")

	env.mu.Lock()
	tokenRequests := env.tokenRequestsReceived
	env.mu.Unlock()
	assert.Empty(t, tokenRequests)
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

// An authorization code produced by the Authorization Challenge Endpoint
// is bound to the DPoP key the exchange was opened with, and the Token
// Endpoint refuses it unless the redemption proves the same key.
//
// The wallet used to send DPoP on this leg only when the scenario set
// use_dpop, which no Interactive Authorization scenario does - so the
// default flow obtained a code and could not spend it.
func TestVCI_InteractiveAuthorization_RedeemsTheCodeWithDPoP(t *testing.T) {
	env := setupTestEnvironment(t, func(e *testEnvironment) {
		e.iaMetadataSpelling = "normative"
	})
	defer env.cleanup()

	env.seedPresentableCredential(t)
	env.addScenario(config.Scenario{
		Name: "ia-dpop-redemption",
		Type: "vci",
		VCI: &config.VCIScenario{
			IssuerURL:                   env.issuerServer.URL,
			Scope:                       "pid",
			UseInteractiveAuthorization: true,
			CredentialConfigurationID:   "test_credential",
			// Deliberately not set: the binding is the protocol's, not
			// the scenario's, so it must not depend on this.
			UseDPoP: false,
		},
	})

	result, err := env.wallet.RunScenario(t.Context(), "ia-dpop-redemption")
	require.NoError(t, err)
	require.True(t, result.Success, "scenario failed: %s", result.Error)

	env.mu.Lock()
	tokenRequests := env.tokenRequestsReceived
	env.mu.Unlock()
	require.Len(t, tokenRequests, 1)
	assert.NotEmpty(t, tokenRequests[0]["dpop"],
		"a code from the challenge endpoint carries a DPoP binding the token request must prove")
}

// A prepared issuance hands out a fresh issuer_state every time its offer
// is fetched, and the handle is one-shot. A wallet that remembered the
// first one on the scenario configuration presented a spent handle on
// every later run.
func TestVCI_InteractiveAuthorization_IssuerStateIsPerRun(t *testing.T) {
	env := setupTestEnvironment(t, func(e *testEnvironment) {
		e.iaMetadataSpelling = "normative"
		e.offerIssuerState = true
	})
	defer env.cleanup()

	env.seedPresentableCredential(t)
	scenario := config.Scenario{
		Name: "ia-issuer-initiated",
		Type: "vci",
		VCI: &config.VCIScenario{
			CredentialOfferURI:          env.issuerServer.URL + "/credential-offer",
			Scope:                       "pid",
			UseInteractiveAuthorization: true,
			CredentialConfigurationID:   "test_credential",
		},
	}
	env.addScenario(scenario)

	for range 2 {
		result, err := env.wallet.RunScenario(t.Context(), "ia-issuer-initiated")
		require.NoError(t, err)
		require.True(t, result.Success, "scenario failed: %s", result.Error)
	}

	env.mu.Lock()
	served := env.offerStatesServed
	requests := env.challengeRequests
	env.mu.Unlock()

	require.Len(t, served, 2, "each run fetches its own offer")
	require.Len(t, requests, 4, "two runs, each an initial and an intermediate request")

	assert.Equal(t, served[0], requests[0].Get("issuer_state"),
		"the first run presents the handle its own offer carried")
	assert.Equal(t, served[1], requests[2].Get("issuer_state"),
		"the second run must present ITS offer's handle, not the first run's spent one")

	assert.Empty(t, scenario.VCI.IssuerState,
		"an offer-derived handle must not be written back to the shared scenario")
}

// A configured issuer_state is a deliberate instruction to drive a
// particular case, so an offer must not quietly replace it.
func TestVCI_InteractiveAuthorization_ConfiguredIssuerStateWins(t *testing.T) {
	env := setupTestEnvironment(t, func(e *testEnvironment) {
		e.iaMetadataSpelling = "normative"
		e.offerIssuerState = true
	})
	defer env.cleanup()

	env.seedPresentableCredential(t)
	env.addScenario(config.Scenario{
		Name: "ia-configured-state",
		Type: "vci",
		VCI: &config.VCIScenario{
			CredentialOfferURI:          env.issuerServer.URL + "/credential-offer",
			Scope:                       "pid",
			IssuerState:                 "configured-handle",
			UseInteractiveAuthorization: true,
			CredentialConfigurationID:   "test_credential",
		},
	})

	result, err := env.wallet.RunScenario(t.Context(), "ia-configured-state")
	require.NoError(t, err)
	require.True(t, result.Success, "scenario failed: %s", result.Error)

	env.mu.Lock()
	requests := env.challengeRequests
	env.mu.Unlock()
	require.NotEmpty(t, requests)
	assert.Equal(t, "configured-handle", requests[0].Get("issuer_state"))
}

// An inline credential_offer is the same document as one behind a
// credential_offer_uri, so its grants have to be read the same way. They
// were not: the inline branch inspected nothing, and an issuer-initiated
// inline offer reached the challenge endpoint with no issuer_state.
func TestVCI_InlineCredentialOffer_CarriesItsGrants(t *testing.T) {
	env := setupTestEnvironment(t, func(e *testEnvironment) {
		e.iaMetadataSpelling = "normative"
	})
	defer env.cleanup()

	env.seedPresentableCredential(t)

	offer := map[string]any{
		"credential_issuer":            env.issuerServer.URL,
		"credential_configuration_ids": []string{"test_credential"},
		"grants": map[string]any{
			"authorization_code": map[string]any{"issuer_state": "inline-issuer-state"},
		},
	}
	offerJSON, err := json.Marshal(offer)
	require.NoError(t, err)

	env.addScenario(config.Scenario{
		Name: "ia-inline-offer",
		Type: "vci",
		VCI: &config.VCIScenario{
			CredentialOffer:             string(offerJSON),
			Scope:                       "pid",
			UseInteractiveAuthorization: true,
			CredentialConfigurationID:   "test_credential",
		},
	})

	result, err := env.wallet.RunScenario(t.Context(), "ia-inline-offer")
	require.NoError(t, err)
	require.True(t, result.Success, "scenario failed: %s", result.Error)

	env.mu.Lock()
	requests := env.challengeRequests
	env.mu.Unlock()
	require.NotEmpty(t, requests)
	assert.Equal(t, "inline-issuer-state", requests[0].Get("issuer_state"),
		"an inline offer's issuer_state must reach the challenge endpoint")
}

// RunScenario copies the Scenario struct but reaches VCIScenario through
// a pointer, so two concurrent runs of one scenario name share it. A PKCE
// verifier kept there was therefore one run's secret being redeemed by
// the other, and the Token Endpoint saw a verifier that did not hash to
// the challenge it was sent with.
//
// The pairing is asserted as a set rather than per-run because the runs
// finish in no fixed order: what matters is that every verifier
// redeemed is the verifier for a challenge that was actually issued, and
// that no two runs used the same one.
func TestVCI_InteractiveAuthorization_PKCEVerifierIsPerRun(t *testing.T) {
	env := setupTestEnvironment(t, func(e *testEnvironment) {
		e.iaMetadataSpelling = "normative"
	})
	defer env.cleanup()

	env.seedPresentableCredential(t)
	env.addScenario(config.Scenario{
		Name: "ia-concurrent",
		Type: "vci",
		VCI: &config.VCIScenario{
			IssuerURL:                   env.issuerServer.URL,
			Scope:                       "pid",
			UseInteractiveAuthorization: true,
			CredentialConfigurationID:   "test_credential",
		},
	})

	const runs = 4
	var wg sync.WaitGroup
	for range runs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := env.wallet.RunScenario(t.Context(), "ia-concurrent")
			assert.NoError(t, err)
			if result != nil {
				assert.True(t, result.Success, "scenario failed: %s", result.Error)
			}
		}()
	}
	wg.Wait()

	env.mu.Lock()
	requests := env.challengeRequests
	tokenRequests := env.tokenRequestsReceived
	env.mu.Unlock()

	challenges := map[string]bool{}
	for _, r := range requests {
		if challenge := r.Get("code_challenge"); challenge != "" {
			challenges[challenge] = true
		}
	}
	require.Len(t, challenges, runs, "each run must mint its own PKCE challenge")

	require.Len(t, tokenRequests, runs)
	redeemed := map[string]bool{}
	for _, tr := range tokenRequests {
		verifier := tr["code_verifier"]
		require.NotEmpty(t, verifier)
		sum := sha256.Sum256([]byte(verifier))
		redeemed[base64.RawURLEncoding.EncodeToString(sum[:])] = true
	}

	assert.Equal(t, challenges, redeemed,
		"every redeemed verifier must be the verifier for a challenge this run issued")
}

// An Authorization Server registers a client against a fixed set of
// redirect URIs and refuses anything else, so every leg of one exchange
// has to send the same one.
//
// With no redirect_uri configured, the challenge request omitted the
// parameter entirely while the token request supplied a default. Against
// a server that validates it - which the production challenge endpoint
// does, through Clients.Allow - the omission reads as a redirect_uri no
// registered client has, and the wallet is refused before it ever
// receives a challenge.
func TestVCI_InteractiveAuthorization_SendsOneRedirectURIThroughout(t *testing.T) {
	for name, configured := range map[string]string{
		"defaulted":  "",
		"configured": "https://wallet.example.com/cb",
	} {
		t.Run(name, func(t *testing.T) {
			env := setupTestEnvironment(t, func(e *testEnvironment) {
				e.iaMetadataSpelling = "normative"
			})
			defer env.cleanup()

			env.seedPresentableCredential(t)
			env.addScenario(config.Scenario{
				Name: "ia-redirect-uri",
				Type: "vci",
				VCI: &config.VCIScenario{
					IssuerURL:                   env.issuerServer.URL,
					Scope:                       "pid",
					RedirectURI:                 configured,
					UseInteractiveAuthorization: true,
					CredentialConfigurationID:   "test_credential",
				},
			})

			result, err := env.wallet.RunScenario(t.Context(), "ia-redirect-uri")
			require.NoError(t, err)
			require.True(t, result.Success, "scenario failed: %s", result.Error)

			env.mu.Lock()
			requests := env.challengeRequests
			tokenRequests := env.tokenRequestsReceived
			env.mu.Unlock()

			require.NotEmpty(t, requests)
			require.Len(t, tokenRequests, 1)

			sent := requests[0].Get("redirect_uri")
			assert.NotEmpty(t, sent, "a registered client always has a redirect_uri")
			assert.Equal(t, tokenRequests[0]["redirect_uri"], sent,
				"the challenge and the token request must name the same redirect_uri")
			if configured != "" {
				assert.Equal(t, configured, sent)
			}
		})
	}
}

// An Authorization Challenge Request carrying neither a scope nor an
// issuer_state describes no authorization at all, and the endpoint
// refuses it. So a scenario that names only a credential configuration
// could not open an exchange - including when the wallet took this path
// because the Issuer's metadata says Interactive Authorization is the
// only thing it accepts, a case the scenario never asked for and cannot
// be expected to configure around.
//
// OpenID4VCI 1.0 §12.2.3 publishes which scope asks for which credential
// configuration, so there is nothing to guess.
func TestVCI_InteractiveAuthorization_UsesTheAdvertisedScope(t *testing.T) {
	env := setupTestEnvironment(t, func(e *testEnvironment) {
		e.iaMetadataSpelling = "normative"
		// Not requested by the scenario: the wallet takes this path
		// because the Issuer says it accepts nothing else.
		e.iaRequireIA = true
	})
	defer env.cleanup()

	env.seedPresentableCredential(t)
	env.addScenario(config.Scenario{
		Name: "ia-advertised-scope",
		Type: "vci",
		VCI: &config.VCIScenario{
			IssuerURL: env.issuerServer.URL,
			// No Scope and no IssuerState: everything this run needs to
			// name the authorization is in the Issuer's metadata.
			CredentialConfigurationID: "test_credential",
		},
	})

	result, err := env.wallet.RunScenario(t.Context(), "ia-advertised-scope")
	require.NoError(t, err)
	require.True(t, result.Success, "scenario failed: %s", result.Error)

	env.mu.Lock()
	requests := env.challengeRequests
	env.mu.Unlock()
	require.NotEmpty(t, requests)
	assert.Equal(t, "test_scope", requests[0].Get("scope"),
		"the scope the Issuer advertises for this configuration must reach the challenge endpoint")
}

// A scope the scenario names is the scenario's business and the metadata
// must not override it.
func TestVCI_InteractiveAuthorization_ConfiguredScopeWins(t *testing.T) {
	env := setupTestEnvironment(t, func(e *testEnvironment) {
		e.iaMetadataSpelling = "normative"
	})
	defer env.cleanup()

	env.seedPresentableCredential(t)
	env.addScenario(config.Scenario{
		Name: "ia-configured-scope",
		Type: "vci",
		VCI: &config.VCIScenario{
			IssuerURL:                   env.issuerServer.URL,
			Scope:                       "pid",
			UseInteractiveAuthorization: true,
			CredentialConfigurationID:   "test_credential",
		},
	})

	result, err := env.wallet.RunScenario(t.Context(), "ia-configured-scope")
	require.NoError(t, err)
	require.True(t, result.Success, "scenario failed: %s", result.Error)

	env.mu.Lock()
	requests := env.challengeRequests
	env.mu.Unlock()
	require.NotEmpty(t, requests)
	assert.Equal(t, "pid", requests[0].Get("scope"))
}

// The credential this wallet presents should be one it could actually
// have been issued.
//
// seedPresentableCredential writes the request's own "dc+sd-jwt" by hand,
// so every other test here sidesteps the question. Issuance records what
// detectFormat says instead, which is the legacy "vc+sd-jwt" - so a
// credential obtained through the wallet's own issuance flow could never
// satisfy a presentation request for the very type it is, and no test
// noticed because none of them presented an issued credential.
func TestVCI_InteractiveAuthorization_PresentsAnIssuedCredential(t *testing.T) {
	env := setupTestEnvironment(t, func(e *testEnvironment) {
		e.iaMetadataSpelling = "normative"
	})
	defer env.cleanup()

	// Exactly what issuance stores: the legacy format identifier, and no
	// vct recorded, because runVCIScenario does not read the credential.
	env.wallet.Store().Add(&credential.StoredCredential{
		RawCredential: createMockSDJWTWithVCT(t, iaRequestedVCT, &env.holderKey.PublicKey),
		Format:        "vc+sd-jwt",
		IssuerURL:     env.issuerServer.URL,
		ScenarioName:  "issued",
	})

	env.addScenario(config.Scenario{
		Name: "ia-issued-credential",
		Type: "vci",
		VCI: &config.VCIScenario{
			IssuerURL:                   env.issuerServer.URL,
			Scope:                       "pid",
			UseInteractiveAuthorization: true,
			CredentialConfigurationID:   "test_credential",
		},
	})

	result, err := env.wallet.RunScenario(t.Context(), "ia-issued-credential")
	require.NoError(t, err)
	require.True(t, result.Success, "scenario failed: %s", result.Error)

	env.mu.Lock()
	requests := env.challengeRequests
	env.mu.Unlock()
	require.Len(t, requests, 2)

	payload := env.decryptIAResponse(t, requests[1].Get("openid4vp_response"))
	tokens, ok := payload["vp_token"].(map[string]any)
	require.True(t, ok)
	assert.Len(t, tokens["pid_auth"], 1,
		"a credential this wallet issued itself must satisfy a request for its own type")
}

// interaction_types_supported exists so an Issuer knows what the wallet
// can do, and a scenario overriding it is asking to drive the case where
// the Issuer ignores that. Performing the interaction anyway would let
// such a server finish the exchange - and the scenario would report
// success for the very thing it was written to catch, after disclosing a
// credential to get there.
func TestVCI_InteractiveAuthorization_RefusesAnInteractionItDidNotOffer(t *testing.T) {
	env := setupTestEnvironment(t, func(e *testEnvironment) {
		e.iaMetadataSpelling = "normative"
		// The issuer asks for a presentation regardless of what the
		// wallet said it can do.
		e.iaInteractionType = "urn:openid:dcp:ia:openid4vp_presentation"
		e.iaIgnoreOfferedTypes = true
	})
	defer env.cleanup()

	env.seedPresentableCredential(t)
	env.addScenario(config.Scenario{
		Name: "ia-unoffered-interaction",
		Type: "vci",
		VCI: &config.VCIScenario{
			IssuerURL:                   env.issuerServer.URL,
			Scope:                       "pid",
			UseInteractiveAuthorization: true,
			CredentialConfigurationID:   "test_credential",
			// This wallet says it can only do the web leg.
			InteractionTypes: []string{"urn:openid:dcp:ia:auth_via_web"},
		},
	})

	result, err := env.wallet.RunScenario(t.Context(), "ia-unoffered-interaction")
	require.NoError(t, err)
	require.False(t, result.Success, "an issuer ignoring the advertised capabilities must not be allowed to finish")
	assert.Contains(t, result.Error, "did not offer")

	// And nothing was disclosed getting there.
	env.mu.Lock()
	requests := env.challengeRequests
	env.mu.Unlock()
	for _, r := range requests {
		assert.Empty(t, r.Get("openid4vp_response"), "no presentation may be sent for an interaction never offered")
	}
}

// A credential whose issuer chose a non-default _sd_alg must be bound
// under that hash, or the production verifier rejects a valid
// presentation.
func TestVCI_InteractiveAuthorization_KeyBindingUsesTheCredentialsSDAlg(t *testing.T) {
	for _, alg := range []string{"sha-384", "sha-512"} {
		t.Run(alg, func(t *testing.T) {
			env := setupTestEnvironment(t, func(e *testEnvironment) {
				e.iaMetadataSpelling = "normative"
			})
			defer env.cleanup()

			env.wallet.Store().Add(&credential.StoredCredential{
				RawCredential: createMockSDJWTWithClaims(t, iaRequestedVCT, &env.holderKey.PublicKey, map[string]any{"_sd_alg": alg}),
				Format:        "dc+sd-jwt",
				VCT:           iaRequestedVCT,
				ScenarioName:  "setup",
			})
			env.addScenario(config.Scenario{
				Name: "ia-sd-alg",
				Type: "vci",
				VCI: &config.VCIScenario{
					IssuerURL:                   env.issuerServer.URL,
					Scope:                       "pid",
					UseInteractiveAuthorization: true,
					CredentialConfigurationID:   "test_credential",
				},
			})

			result, err := env.wallet.RunScenario(t.Context(), "ia-sd-alg")
			require.NoError(t, err)
			require.True(t, result.Success, "scenario failed: %s", result.Error)
		})
	}
}

// Automatic selection skips an expired credential and presents its valid
// replacement, whatever order the store lists them in.
func TestVCI_InteractiveAuthorization_SkipsAnExpiredCredential(t *testing.T) {
	env := setupTestEnvironment(t, func(e *testEnvironment) {
		e.iaMetadataSpelling = "normative"
	})
	defer env.cleanup()

	expired := createMockSDJWTWithClaims(t, iaRequestedVCT, &env.holderKey.PublicKey, map[string]any{"exp": time.Now().Add(-time.Hour).Unix()})
	notYet := createMockSDJWTWithClaims(t, iaRequestedVCT, &env.holderKey.PublicKey, map[string]any{"nbf": time.Now().Add(time.Hour).Unix()})
	valid := createMockSDJWTWithClaims(t, iaRequestedVCT, &env.holderKey.PublicKey, map[string]any{"exp": time.Now().Add(time.Hour).Unix()})
	for id, raw := range map[string]string{"expired": expired, "not-yet-valid": notYet, "valid": valid} {
		env.wallet.Store().Add(&credential.StoredCredential{ID: id, RawCredential: raw, Format: "dc+sd-jwt", VCT: iaRequestedVCT})
	}
	env.addScenario(config.Scenario{
		Name: "ia-expired",
		Type: "vci",
		VCI: &config.VCIScenario{
			IssuerURL:                   env.issuerServer.URL,
			Scope:                       "pid",
			UseInteractiveAuthorization: true,
			CredentialConfigurationID:   "test_credential",
		},
	})

	// Map iteration is random, so several runs would expose an
	// order-dependent pick.
	for range 5 {
		result, err := env.wallet.RunScenario(t.Context(), "ia-expired")
		require.NoError(t, err)
		require.True(t, result.Success, "scenario failed: %s", result.Error)
	}

	validIssuerJWT, _, _ := strings.Cut(valid, "~")
	env.mu.Lock()
	requests := env.challengeRequests
	env.mu.Unlock()
	for i := 1; i < len(requests); i += 2 {
		payload := env.decryptIAResponse(t, requests[i].Get("openid4vp_response"))
		presented := payload["vp_token"].(map[string]any)["pid_auth"].([]any)[0].(string)
		presentedIssuerJWT, _, _ := strings.Cut(presented, "~")
		assert.Equal(t, validIssuerJWT, presentedIssuerJWT, "only the valid credential may be presented")
	}
}

// An explicitly named credential is presented even when expired, so a
// scenario can drive the Issuer's rejection of it.
func TestVCI_InteractiveAuthorization_PresentCredentialOverridesValidity(t *testing.T) {
	env := setupTestEnvironment(t, func(e *testEnvironment) {
		e.iaMetadataSpelling = "normative"
	})
	defer env.cleanup()

	env.wallet.Store().Add(&credential.StoredCredential{
		ID:            "expired",
		RawCredential: createMockSDJWTWithClaims(t, iaRequestedVCT, &env.holderKey.PublicKey, map[string]any{"exp": time.Now().Add(-time.Hour).Unix()}),
		Format:        "dc+sd-jwt",
		VCT:           iaRequestedVCT,
	})
	env.addScenario(config.Scenario{
		Name: "ia-named-expired",
		Type: "vci",
		VCI: &config.VCIScenario{
			IssuerURL:                   env.issuerServer.URL,
			Scope:                       "pid",
			UseInteractiveAuthorization: true,
			CredentialConfigurationID:   "test_credential",
			PresentCredential:           "expired",
		},
	})

	result, err := env.wallet.RunScenario(t.Context(), "ia-named-expired")
	require.NoError(t, err)
	require.True(t, result.Success, "scenario failed: %s", result.Error)

	env.mu.Lock()
	requests := env.challengeRequests
	env.mu.Unlock()
	require.Len(t, requests, 2)
	assert.NotEmpty(t, requests[1].Get("openid4vp_response"))
}

// A code must arrive with 200 and an interaction request with 403; a
// server answering otherwise is reported, not followed.
func TestVCI_InteractiveAuthorization_RequiresTheSpecifiedStatus(t *testing.T) {
	for name, tc := range map[string]struct {
		opt  envOption
		want string
	}{
		"code with 500": {
			opt:  func(e *testEnvironment) { e.iaCodeStatus = http.StatusInternalServerError },
			want: "authorization_code with HTTP 500",
		},
		"interaction with 200": {
			opt:  func(e *testEnvironment) { e.iaInteractionStatus = http.StatusOK },
			want: "insufficient_authorization with HTTP 200",
		},
	} {
		t.Run(name, func(t *testing.T) {
			env := setupTestEnvironment(t, func(e *testEnvironment) {
				e.iaMetadataSpelling = "normative"
			}, tc.opt)
			defer env.cleanup()

			env.seedPresentableCredential(t)
			env.addScenario(config.Scenario{
				Name: "ia-status",
				Type: "vci",
				VCI: &config.VCIScenario{
					IssuerURL:                   env.issuerServer.URL,
					Scope:                       "pid",
					UseInteractiveAuthorization: true,
					CredentialConfigurationID:   "test_credential",
				},
			})

			result, err := env.wallet.RunScenario(t.Context(), "ia-status")
			require.NoError(t, err)
			require.False(t, result.Success)
			assert.Contains(t, result.Error, tc.want)

			env.mu.Lock()
			tokenRequests := env.tokenRequestsReceived
			requests := env.challengeRequests
			env.mu.Unlock()
			assert.Empty(t, tokenRequests, "a nonconforming answer must not be redeemed")
			if name == "interaction with 200" {
				for _, r := range requests {
					assert.Empty(t, r.Get("openid4vp_response"), "no presentation for a nonconforming interaction request")
				}
			}
		})
	}
}

// A presentation challenge without auth_session cannot be continued, so
// answering it would disclose a credential for nothing.
func TestVCI_InteractiveAuthorization_RefusesToPresentWithoutAuthSession(t *testing.T) {
	env := setupTestEnvironment(t, func(e *testEnvironment) {
		e.iaMetadataSpelling = "normative"
		e.iaOmitAuthSession = true
	})
	defer env.cleanup()

	env.seedPresentableCredential(t)
	env.addScenario(config.Scenario{
		Name: "ia-no-auth-session",
		Type: "vci",
		VCI: &config.VCIScenario{
			IssuerURL:                   env.issuerServer.URL,
			Scope:                       "pid",
			UseInteractiveAuthorization: true,
			CredentialConfigurationID:   "test_credential",
		},
	})

	result, err := env.wallet.RunScenario(t.Context(), "ia-no-auth-session")
	require.NoError(t, err)
	require.False(t, result.Success)
	assert.Contains(t, result.Error, "auth_session")

	env.mu.Lock()
	requests := env.challengeRequests
	env.mu.Unlock()
	require.Len(t, requests, 1, "nothing is sent after a challenge that cannot be continued")
	for _, step := range result.Steps {
		assert.NotEqual(t, "openid4vp_presentation", step.Name, "no presentation may be built")
	}
}
