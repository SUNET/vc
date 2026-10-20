package apiv1

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	apigwcache "github.com/SUNET/vc/internal/apigw/cache"
	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A prepared issuance can only be redeemed at the Authorization Challenge
// Endpoint, which answers 404 while Interactive Authorization is off. So
// preparing one then is preparing an offer that cannot be completed - and
// it is a Credential Offer, so by the time anyone finds out it has been
// printed, mailed or put on a screen.
func TestPrepareIssuance_RefusedWhileInteractiveAuthorizationIsDisabled(t *testing.T) {
	client := newChallengeClient(t)
	disabled := false
	client.cfg.APIGW.Delivery.InteractiveAuthorization.Enable = &disabled

	_, err := client.PrepareIssuance(t.Context(), &PrepareIssuanceRequest{
		Scope:         challengeScope,
		IdentityMatch: portalMatch(),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not enabled",
		"preparing an unredeemable offer must be refused, not left to the holder to discover")
}

// ttl_seconds is bounded by the cache the prepared issuance lives in.
// Beyond it the reply's expires_at names a time the issuer_state will not
// survive to, and a large enough value overflows the duration arithmetic
// outright.
func TestPrepareIssuance_TTLIsBoundedByTheCacheThatHoldsIt(t *testing.T) {
	require.LessOrEqual(t, maxPreparedIssuanceTTLSeconds*int(time.Second), int(apigwcache.AuthContextTTL),
		"the accepted bound must not exceed the store's own lifetime")

	for _, tc := range []struct {
		name  string
		ttl   int
		allow bool
	}{
		{name: "the default", ttl: 0, allow: true},
		{name: "at the bound", ttl: maxPreparedIssuanceTTLSeconds, allow: true},
		{name: "one past it", ttl: maxPreparedIssuanceTTLSeconds + 1, allow: false},
		{name: "an hour", ttl: 3600, allow: false},
		{name: "enough to overflow the duration", ttl: 1 << 53, allow: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := newChallengeClient(t)
			reply, err := client.PrepareIssuance(t.Context(), &PrepareIssuanceRequest{
				Scope:         challengeScope,
				IdentityMatch: portalMatch(),
				TTLSeconds:    tc.ttl,
			})
			if !tc.allow {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "ttl_seconds must be at most")
				return
			}
			require.NoError(t, err)
			assert.Greater(t, reply.ExpiresAt, time.Now().Unix(),
				"an accepted ttl must produce an expiry in the future, not one the arithmetic wrapped")
			assert.LessOrEqual(t, reply.ExpiresAt,
				time.Now().Add(apigwcache.AuthContextTTL).Unix(),
				"and not one past the store's own lifetime")
		})
	}
}

// The DCQL a challenge produces asks only for the configured
// authentication scope's auth_claims, and a privacy-preserving wallet
// discloses what it was asked for and no more. A rule naming anything
// else can therefore never be satisfied by any holder.
func TestPrepareIssuance_RefusesAMatchTheRequestWillNeverAskFor(t *testing.T) {
	client := newChallengeClient(t)

	_, err := client.PrepareIssuance(t.Context(), &PrepareIssuanceRequest{
		Scope: challengeScope,
		IdentityMatch: &openid4vci.IdentityMatch{
			Claims: map[string]openid4vci.ClaimTest{
				// Configured auth_claims are given_name and family_name.
				"personal_administrative_number": {Equals: "198001011234"},
			},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "personal_administrative_number",
		"the error must name the claim that cannot be asked for")
	assert.Contains(t, err.Error(), "discloses every claim this rule matches on")
}

// One authentication scope covering the rule is enough: a deployment with
// several lets a holder authenticate with any, and a presentation that
// cannot carry the matched claim fails the match at redemption, which is
// the right outcome and not preparation's business.
func TestPrepareIssuance_AcceptsAMatchOneAuthScopeCanSatisfy(t *testing.T) {
	client := newChallengeClient(t)
	scopes := client.cfg.APIGW.DataSources.Datastore.Scopes[challengeScope]
	scopes.AuthScopes = map[string]model.AuthScopeEntry{
		challengeAuthScope: {AuthClaims: []string{"given_name", "family_name"}},
		"thin_auth":        {AuthClaims: []string{"given_name"}},
	}
	client.cfg.APIGW.DataSources.Datastore.Scopes[challengeScope] = scopes
	// The second auth scope needs credential metadata like any other: a
	// DCQL query is built per auth scope, and one with no format is not a
	// query. Without this the fixture is a configuration the server now
	// refuses outright, which would make this test pass or fail for a
	// reason that has nothing to do with the match.
	client.cfg.Common.CredentialMetadata["thin_auth"] = &model.CredentialMetadata{
		Format: openid4vp.FormatSDJWTVC,
		VCTM:   &sdjwtvc.VCTM{VCT: "urn:example:thin:1"},
	}

	_, err := client.PrepareIssuance(t.Context(), &PrepareIssuanceRequest{
		Scope:         challengeScope,
		IdentityMatch: portalMatch(),
	})
	require.NoError(t, err)
}

// Matching claim NAMES does not establish that a presentation request can
// be built from the scope at all.
//
// buildIssuanceAuthDCQL refuses an auth scope whose format it cannot
// query, and it is not reached until a wallet resumes the offer - so a
// configuration problem the caller could have been told about at
// preparation time instead became a failure in front of a Holder with a
// QR code open, with the prepared issuance already printed.
func TestPrepareIssuance_RefusesAScopeThatCannotBeAsked(t *testing.T) {
	t.Run("an auth scope with no credential metadata", func(t *testing.T) {
		client := newChallengeClient(t)
		scopes := client.cfg.APIGW.DataSources.Datastore.Scopes[challengeScope]
		scopes.AuthScopes = map[string]model.AuthScopeEntry{
			challengeAuthScope: {AuthClaims: []string{"given_name", "family_name"}},
			"unconfigured":     {AuthClaims: []string{"given_name"}},
		}
		client.cfg.APIGW.DataSources.Datastore.Scopes[challengeScope] = scopes

		_, err := client.PrepareIssuance(t.Context(), &PrepareIssuanceRequest{
			Scope:         challengeScope,
			IdentityMatch: portalMatch(),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "scope_not_presentable")
	})

	t.Run("the credential metadata of the auth scope going missing", func(t *testing.T) {
		client := newChallengeClient(t)
		delete(client.cfg.Common.CredentialMetadata, challengeAuthScope)

		_, err := client.PrepareIssuance(t.Context(), &PrepareIssuanceRequest{
			Scope:         challengeScope,
			IdentityMatch: portalMatch(),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "scope_not_presentable")
	})
}

// A prepared issuance is the product of someone authenticating at a
// portal and choosing what to be issued, and nothing re-prepares it. So a
// request that is going to be refused must be refused with the handle
// still intact: otherwise anyone who photographed the offer off a screen
// can destroy the issuance by sending one malformed request.
func TestIssuerInitiated_AFailedChallengeDoesNotBurnTheIssuerState(t *testing.T) {
	for _, tc := range []struct {
		name    string
		corrupt func(req *AuthorizationChallengeRequest)
	}{
		{
			name:    "an unknown client",
			corrupt: func(req *AuthorizationChallengeRequest) { req.ClientID = "not-a-configured-client" },
		},
		{
			name:    "no DPoP proof",
			corrupt: func(req *AuthorizationChallengeRequest) { req.DPOP = "" },
		},
		{
			name:    "a DPoP proof that is not a JWT",
			corrupt: func(req *AuthorizationChallengeRequest) { req.DPOP = "not-a-proof" },
		},
		{
			name: "an interaction type the wallet cannot perform",
			corrupt: func(req *AuthorizationChallengeRequest) {
				req.InteractionTypesSupported = "urn:example:something-else"
			},
		},
		{
			name:    "a bad code_challenge_method",
			corrupt: func(req *AuthorizationChallengeRequest) { req.CodeChallengeMethod = "plain" },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := newChallengeClient(t)
			issuerState := prepareIssuance(t, client, portalMatch())

			req := initialChallenge(t)
			req.Scope = ""
			req.IssuerState = issuerState
			req.CodeChallenge = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			req.CodeChallengeMethod = "S256"
			tc.corrupt(req)

			_, err := client.OAuthAuthorizationChallenge(t.Context(), req)
			require.Error(t, err, "the request under test has to actually be refused")

			survived, lookupErr := client.cacheService.AuthContext.Get(t.Context(),
				&cache.AuthorizationContext{IssuerState: issuerState})
			require.NoError(t, lookupErr,
				"a refused request must leave the prepared issuance resolvable")
			require.NotNil(t, survived)

			// And still usable: the legitimate wallet retries and gets in.
			good := initialChallenge(t)
			good.Scope = ""
			good.IssuerState = issuerState
			opened := challengeErr(t, client, good)
			assert.NotEmpty(t, opened.AuthSession, "the retry must open the exchange")
		})
	}
}

// Resuming a prepared issuance moves the physical lifetime as well as the
// advertised one. MongoDB expires these documents on a TTL index over
// created_at and MongoStore.Update replaces the whole document, so an
// offer resumed late would otherwise advertise an auth_session that
// outlives the document holding it.
func TestIssuerInitiated_ResumingResetsTheStoredLifetimeAnchor(t *testing.T) {
	client := newChallengeClient(t)
	issuerState := prepareIssuance(t, client, portalMatch())

	prepared, err := client.cacheService.AuthContext.Get(t.Context(),
		&cache.AuthorizationContext{IssuerState: issuerState})
	require.NoError(t, err)
	// Age it, as an offer left on a screen for a few minutes would be.
	prepared.CreatedAt = time.Now().Add(-4 * time.Minute)
	require.NoError(t, client.cacheService.AuthContext.Update(t.Context(), prepared))

	req := initialChallenge(t)
	req.Scope = ""
	req.IssuerState = issuerState
	opened := challengeErr(t, client, req)

	resumed, err := client.cacheService.AuthContext.Get(t.Context(),
		&cache.AuthorizationContext{AuthSession: opened.AuthSession})
	require.NoError(t, err)

	assert.WithinDuration(t, time.Now(), resumed.CreatedAt, 5*time.Second,
		"the exchange must be anchored to when it started, not to when the offer was prepared")
	assert.LessOrEqual(t, resumed.ExpiresAt, resumed.CreatedAt.Add(apigwcache.AuthContextTTL).Unix(),
		"and the advertised deadline must fit inside the lifetime that anchor gives it")
}

// The (authentic_source, scope) pair the authorization middleware checked
// has to be the pair preparation actually uses.
//
// SPOCP reads authentic_source out of the request body and authorizes the
// pair it finds there. Nothing compared that pair to the one the Selector
// resolves, so a caller permitted source A could name A, send a scope that
// resolves to B, and have the issuance prepared against B - authorized for
// a combination it never asked about.
func TestPrepareIssuance_RefusesAnAuthenticSourceSubstitution(t *testing.T) {
	t.Run("naming another source than the scope resolves to", func(t *testing.T) {
		client := newChallengeClient(t)

		_, err := client.PrepareIssuance(t.Context(), &PrepareIssuanceRequest{
			Scope:           challengeScope,
			AuthenticSource: "some-other-source",
			IdentityMatch:   portalMatch(),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "authentic_source_mismatch")
		// And it names both, so an operator reading the log or the
		// response can see which substitution was attempted.
		assert.Contains(t, err.Error(), "some-other-source")
		assert.Contains(t, err.Error(), "authentic-source")
	})

	t.Run("naming the source it does resolve to is accepted", func(t *testing.T) {
		client := newChallengeClient(t)

		_, err := client.PrepareIssuance(t.Context(), &PrepareIssuanceRequest{
			Scope:           challengeScope,
			AuthenticSource: "authentic-source",
			IdentityMatch:   portalMatch(),
		})
		require.NoError(t, err)
	})

	// Omitting it is still allowed: the pair then carries no source, and
	// the deployment's own rules decide what that means.
	t.Run("omitting it is unchanged", func(t *testing.T) {
		client := newChallengeClient(t)

		_, err := client.PrepareIssuance(t.Context(), &PrepareIssuanceRequest{
			Scope:         challengeScope,
			IdentityMatch: portalMatch(),
		})
		require.NoError(t, err)
	})
}

// Resuming an offer mints a FRESH ephemeral encryption key, rather than
// reusing the one minted when the issuance was prepared.
//
// The exchange a resume opens runs for a full auth_session lifetime from
// that moment, while the preparation's key entry was created when the
// offer was and reusing it does not renew its retention. An offer resumed
// near the end of its own life therefore opened an exchange that outlives
// the only key able to decrypt its answer - and the wallet's presentation
// then arrives correct, inside the exchange's advertised deadline, and
// undecryptable. Minting the key here makes the two lifetimes start
// together.
func TestIssuerInitiated_ResumingMintsAFreshEphemeralKey(t *testing.T) {
	client := newChallengeClient(t)
	issuerState := prepareIssuance(t, client, portalMatch())

	prepared, err := client.cacheService.AuthContext.Get(t.Context(),
		&cache.AuthorizationContext{IssuerState: issuerState})
	require.NoError(t, err)
	preparedKeyID := prepared.EphemeralEncryptionKeyID
	require.NotEmpty(t, preparedKeyID)

	req := initialChallenge(t)
	req.Scope = ""
	req.IssuerState = issuerState
	opened := challengeErr(t, client, req)

	resumed, err := client.cacheService.AuthContext.Get(t.Context(),
		&cache.AuthorizationContext{AuthSession: opened.AuthSession})
	require.NoError(t, err)

	assert.NotEqual(t, preparedKeyID, resumed.EphemeralEncryptionKeyID,
		"the exchange must not run on a key older than itself")
	assert.NotEmpty(t, resumed.EphemeralEncryptionKeyID)

	// And the key the WALLET was told to encrypt to is the one the opened
	// exchange records - otherwise the fresh id would just be a different
	// way to be undecryptable.
	var envelope struct {
		Request string `json:"request"`
	}
	require.NoError(t, json.Unmarshal(opened.OpenID4VPRequest, &envelope))
	claims := unsafeJWTClaims(t, envelope.Request)

	metadata, ok := claims["client_metadata"].(map[string]any)
	require.True(t, ok, "the signed request must carry client_metadata")
	jwks, ok := metadata["jwks"].(map[string]any)
	require.True(t, ok)
	keys, ok := jwks["keys"].([]any)
	require.True(t, ok)
	require.NotEmpty(t, keys)

	advertised, ok := keys[0].(map[string]any)["kid"].(string)
	require.True(t, ok)
	assert.Equal(t, resumed.EphemeralEncryptionKeyID, advertised,
		"the wallet encrypts to the kid in the signed request, so the exchange has to hold that key")

	// The key really is in the cache under that id, so the response can
	// actually be decrypted.
	_, ok = client.cacheService.EphemeralEncryptionKey.Get(t.Context(), resumed.EphemeralEncryptionKeyID)
	assert.True(t, ok, "the key the request advertises must be the one that was stored")
}

// Two wallets scanning the same offer must not be able to make the winner
// commit the loser's ephemeral key.
//
// The memory store hands out the document it holds, so both requests
// resolve the SAME object, and each mints an ephemeral key id onto it
// before either has claimed anything. Writing through that shared pointer
// lets B's id land after A has already signed a request advertising A's -
// and if A then wins the claim, the committed exchange names a key the
// winning wallet was never told to encrypt to. Its presentation is
// correct and undecryptable.
//
// The atomic claim does not prevent this: it decides who wins, not what
// the winner is carrying by the time it wins.
func TestIssuerInitiated_ConcurrentResumesDoNotCrossTheirKeys(t *testing.T) {
	for range 20 {
		client := newChallengeClient(t)
		issuerState := prepareIssuance(t, client, portalMatch())

		const contenders = 4
		var (
			start    sync.WaitGroup
			finished sync.WaitGroup
			mu       sync.Mutex
			winners  []*AuthorizationChallengeError
		)
		start.Add(1)
		finished.Add(contenders)

		for range contenders {
			go func() {
				defer finished.Done()
				req := initialChallenge(t)
				req.Scope = ""
				req.IssuerState = issuerState
				start.Wait()

				_, err := client.OAuthAuthorizationChallenge(t.Context(), req)
				var challengeErr *AuthorizationChallengeError
				if errors.As(err, &challengeErr) && challengeErr.AuthSession != "" {
					mu.Lock()
					winners = append(winners, challengeErr)
					mu.Unlock()
				}
			}()
		}
		start.Done()
		finished.Wait()

		// Exactly one, which is the one-shot guarantee.
		require.Len(t, winners, 1, "an issuance prepared for one Holder opens one exchange")
		won := winners[0]

		committed, err := client.cacheService.AuthContext.Get(t.Context(),
			&cache.AuthorizationContext{AuthSession: won.AuthSession})
		require.NoError(t, err)

		// The key the winning wallet was told to encrypt to has to be the
		// key the committed exchange holds.
		var envelope struct {
			Request string `json:"request"`
		}
		require.NoError(t, json.Unmarshal(won.OpenID4VPRequest, &envelope))
		claims := unsafeJWTClaims(t, envelope.Request)

		metadata := claims["client_metadata"].(map[string]any)
		keys := metadata["jwks"].(map[string]any)["keys"].([]any)
		advertised := keys[0].(map[string]any)["kid"].(string)

		require.Equal(t, committed.EphemeralEncryptionKeyID, advertised,
			"the winning exchange must hold the key its own request advertised")

		_, ok := client.cacheService.EphemeralEncryptionKey.Get(t.Context(), advertised)
		require.True(t, ok, "and that key must be in the cache to decrypt with")
	}
}

// The offer names the scope as its credential_configuration_id; without
// metadata for it the exchange is spent before matchScope refuses.
func TestPrepareIssuance_RefusesAScopeWithNoCredentialMetadata(t *testing.T) {
	client := newChallengeClient(t)
	delete(client.cfg.Common.CredentialMetadata, challengeScope)

	_, err := client.PrepareIssuance(t.Context(), &PrepareIssuanceRequest{
		Scope:         challengeScope,
		IdentityMatch: portalMatch(),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown_credential_configuration")
}

// For an mdoc auth scope, auth_claims "family_name" and the qualified
// "org.iso.18013.5.1.family_name" are the same DCQL path.
func TestPrepareIssuance_NormalisesMDocClaimPaths(t *testing.T) {
	client := newChallengeClient(t)
	client.cfg.Common.CredentialMetadata[challengeAuthScope] = &model.CredentialMetadata{
		Format:  openid4vp.FormatMsoMdoc,
		Doctype: "org.iso.18013.5.1.mDL",
	}
	scopes := client.cfg.APIGW.DataSources.Datastore.Scopes[challengeScope]
	scopes.AuthScopes = map[string]model.AuthScopeEntry{
		challengeAuthScope: {AuthClaims: []string{"family_name"}},
	}
	client.cfg.APIGW.DataSources.Datastore.Scopes[challengeScope] = scopes

	_, err := client.PrepareIssuance(t.Context(), &PrepareIssuanceRequest{
		Scope: challengeScope,
		IdentityMatch: &openid4vci.IdentityMatch{Claims: map[string]openid4vci.ClaimTest{
			"org.iso.18013.5.1.family_name": {Equals: "Andersson"},
		}},
	})
	require.NoError(t, err)

	_, err = client.PrepareIssuance(t.Context(), &PrepareIssuanceRequest{
		Scope: challengeScope,
		IdentityMatch: &openid4vci.IdentityMatch{Claims: map[string]openid4vci.ClaimTest{
			"org.example.ns.family_name": {Equals: "Andersson"},
		}},
	})
	require.Error(t, err, "another namespace is a different path")
}
