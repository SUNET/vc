package apiv1

import (
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

	// The second auth scope needs credential metadata like any other: the
	// presentation request names every configured auth scope, so one with
	// nothing to constrain it is a request that cannot be built at all.
	// Without this the configuration describes a deployment whose
	// challenge exchange could never open, which preparation now refuses -
	// and refusing it is the point, so the fixture has to be a deployment
	// that would work rather than one that would not.
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
