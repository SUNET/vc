package apiv1

import (
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/oauth2"
	"github.com/SUNET/vc/pkg/openid4vci"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// portalMatch is the rule a portal would supply: the person it
// authenticated, named by the claims it authenticated them under.
func portalMatch() *openid4vci.IdentityMatch {
	return &openid4vci.IdentityMatch{
		Claims: map[string]openid4vci.ClaimTest{
			"given_name":  {Equals: "Anna"},
			"family_name": {Equals: "Andersson"},
		},
	}
}

// prepareIssuance runs the portal's half and returns the issuer_state the
// Credential Offer carries.
func prepareIssuance(t *testing.T, client *Client, match *openid4vci.IdentityMatch) string {
	t.Helper()

	reply, err := client.PrepareIssuance(t.Context(), &PrepareIssuanceRequest{
		Scope:         challengeScope,
		IdentityMatch: match,
	})
	require.NoError(t, err)
	require.NotNil(t, reply)
	require.NotEmpty(t, reply.IssuerState)
	return reply.IssuerState
}

// The offer a prepared issuance produces carries the authorization_code
// grant and no pre-authorized code.
//
// That is the substance of the change rather than a detail: a
// pre-authorized code is a bearer secret, so whoever holds it redeems it,
// and the only binding available is a transaction code typed by whoever
// is holding the phone. This offer hands out no secret at all.
func TestPrepareIssuance_OffersAnAuthorizationCodeGrant(t *testing.T) {
	client := newChallengeClient(t)

	reply, err := client.PrepareIssuance(t.Context(), &PrepareIssuanceRequest{
		Scope:         challengeScope,
		IdentityMatch: portalMatch(),
	})
	require.NoError(t, err)

	require.Contains(t, reply.CredentialOffer.Grants, openid4vci.GrantTypeAuthorizationCode)
	assert.NotContains(t, reply.CredentialOffer.Grants, openid4vci.GrantTypePreAuthorizedCode,
		"a prepared issuance must not hand out a bearer code")

	grant, ok := reply.CredentialOffer.Grants[openid4vci.GrantTypeAuthorizationCode].(openid4vci.GrantAuthorizationCode)
	require.True(t, ok)
	assert.Equal(t, reply.IssuerState, grant.IssuerState,
		"the offer must carry the handle this issuance is indexed by")

	// 256 bits, like every other handle in this flow.
	assert.GreaterOrEqual(t, len(reply.IssuerState), 43)
	assert.Greater(t, reply.ExpiresAt, int64(0))
}

// A rule is required, and an empty one is not a rule.
//
// Omitting it would make the offer completable by anybody's wallet, which
// is what the pre-authorized grant already provides - so a caller that
// wants that has to ask for it by name rather than by leaving a field out.
func TestPrepareIssuance_RequiresAMatchRule(t *testing.T) {
	client := newChallengeClient(t)

	for name, match := range map[string]*openid4vci.IdentityMatch{
		"absent": nil,
		"empty":  {Claims: map[string]openid4vci.ClaimTest{}},
		"a claim with no comparison": {Claims: map[string]openid4vci.ClaimTest{
			"given_name": {},
		}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := client.PrepareIssuance(t.Context(), &PrepareIssuanceRequest{
				Scope:         challengeScope,
				IdentityMatch: match,
			})
			require.Error(t, err)
		})
	}
}

// The wallet takes the issuer_state to the Challenge Endpoint and is told
// to present a credential - the prepared issuance decides the scope, and
// the wallet supplies its own half.
func TestIssuerInitiated_ChallengeResumesThePreparedIssuance(t *testing.T) {
	client := newChallengeClient(t)
	issuerState := prepareIssuance(t, client, portalMatch())

	req := initialChallenge(t)
	req.Scope = "" // the prepared issuance names it
	req.IssuerState = issuerState

	opened := challengeErr(t, client, req)

	assert.Equal(t, 403, opened.HTTPStatus)
	assert.Equal(t, "insufficient_authorization", opened.ErrorCode)
	assert.Equal(t, "urn:openid:dcp:ia:openid4vp_presentation", opened.InteractionTypeRequired)
	require.NotEmpty(t, opened.AuthSession)
	require.NotEmpty(t, opened.OpenID4VPRequest)

	authCtx, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{
		AuthSession: opened.AuthSession,
	})
	require.NoError(t, err)
	assert.Equal(t, []string{challengeScope}, authCtx.Scopes, "the prepared issuance decides the scope")
	assert.Equal(t, "wallet-1", authCtx.WalletClientID, "the wallet supplies its own identity")
	assert.NotEmpty(t, authCtx.AuthSessionDPoPThumbprint)
	require.NotNil(t, authCtx.IdentityMatch, "the caller's rule must survive onto the exchange")
	assert.Equal(t, []string{"family_name", "given_name"}, authCtx.IdentityMatch.ClaimPaths())
}

// The issuer_state is spent when it is used. It was the Issuer's handle
// on an issuance nobody had claimed; leaving it resolvable would let a
// second wallet open a second exchange against the same prepared
// issuance.
func TestIssuerInitiated_IssuerStateIsSingleUse(t *testing.T) {
	client := newChallengeClient(t)
	issuerState := prepareIssuance(t, client, portalMatch())

	first := initialChallenge(t)
	first.Scope = ""
	first.IssuerState = issuerState
	challengeErr(t, client, first)

	second := initialChallenge(t)
	second.Scope = ""
	second.IssuerState = issuerState
	oauthErr := oauthErrFromChallenge(t, client, second)
	assert.Equal(t, "invalid_grant", oauthErr.ErrorCode)

	resolved, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{
		IssuerState: issuerState,
	})
	require.ErrorIs(t, err, cache.ErrNoDocuments)
	require.Nil(t, resolved)
}

// A wallet asking for a different credential than the one prepared is
// refused rather than quietly served the prepared one, so a mismatch is
// visible to whoever wrote the wallet.
func TestIssuerInitiated_ScopeMustMatchThePreparedIssuance(t *testing.T) {
	client := newChallengeClient(t)
	issuerState := prepareIssuance(t, client, portalMatch())

	req := initialChallenge(t)
	req.Scope = "some-other-scope"
	req.IssuerState = issuerState

	oauthErr := oauthErrFromChallenge(t, client, req)
	assert.Equal(t, "invalid_scope", oauthErr.ErrorCode)
}

// An unknown issuer_state and an expired one are one answer, so the
// endpoint cannot be asked which handles exist.
func TestIssuerInitiated_UnknownIssuerStateIsIndistinguishableFromExpired(t *testing.T) {
	client := newChallengeClient(t)

	unknown := initialChallenge(t)
	unknown.Scope = ""
	unknown.IssuerState = strings.Repeat("a", 43)
	unknownErr := oauthErrFromChallenge(t, client, unknown)

	issuerState := prepareIssuance(t, client, portalMatch())
	authCtx, err := client.cacheService.AuthContext.Get(t.Context(), &cache.AuthorizationContext{
		IssuerState: issuerState,
	})
	require.NoError(t, err)
	authCtx.ExpiresAt = 1
	require.NoError(t, client.cacheService.AuthContext.Update(t.Context(), authCtx))

	expiredReq := initialChallenge(t)
	expiredReq.Scope = ""
	expiredReq.IssuerState = issuerState
	expiredErr := oauthErrFromChallenge(t, client, expiredReq)

	assert.Equal(t, unknownErr.ErrorCode, expiredErr.ErrorCode)
	assert.Equal(t, unknownErr.Error(), expiredErr.Error())
}

// The rule is evaluated against the verified claims of the presented
// credential, and this is what the whole mechanism exists for: a wallet
// that presents a perfectly valid credential belonging to somebody else
// does not get the issuance.
func TestIdentityMatch_DecidesOnTheVerifiedClaims(t *testing.T) {
	client := newChallengeClient(t)

	for name, tc := range map[string]struct {
		presented  map[string]any
		wantErr    bool
		wantReason string
	}{
		"the person it was prepared for": {
			presented: map[string]any{"given_name": "Anna", "family_name": "Andersson"},
		},
		"somebody else entirely": {
			presented: map[string]any{"given_name": "Bo", "family_name": "Bergstrom"},
			wantErr:   true,
		},
		"the right family, the wrong person": {
			presented: map[string]any{"given_name": "Bo", "family_name": "Andersson"},
			wantErr:   true,
		},
		"a claim the credential does not carry": {
			presented: map[string]any{"given_name": "Anna"},
			wantErr:   true,
			// Asserted on the message because a missing claim and a
			// differing one both fail: without this, bypassing the
			// presence check still refuses - claimValueMatches says no to
			// a nil value - and the two branches become
			// indistinguishable.
			wantReason: "is not present",
		},
		"extra claims are not a reason to refuse": {
			presented: map[string]any{"given_name": "Anna", "family_name": "Andersson", "birth_date": "1970-01-01"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := client.matchPresentedIdentity("dc+sd-jwt", tc.presented, portalMatch())
			if !tc.wantErr {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.ErrorIs(t, err, errIdentityMismatch)
			if tc.wantReason != "" {
				assert.Contains(t, err.Error(), tc.wantReason)
			}
		})
	}
}

// The refusal names the claim but never the values.
//
// It is handed back to whoever is holding the wallet, so telling them
// which of several candidate identities the issuance was prepared for
// would turn a failed match into an oracle for the portal session's
// contents. The values go to the log.
func TestIdentityMatch_DoesNotLeakTheExpectedValues(t *testing.T) {
	client := newChallengeClient(t)

	// Only given_name differs, so the claim the message names is
	// deterministic - paths are evaluated in sorted order, which is why a
	// case where both differ would name family_name instead.
	err := client.matchPresentedIdentity("dc+sd-jwt",
		map[string]any{"given_name": "Bo", "family_name": "Andersson"}, portalMatch())
	require.Error(t, err)

	assert.Contains(t, err.Error(), "given_name", "the claim that failed is useful to a wallet author")
	assert.NotContains(t, err.Error(), "Anna", "the value it was compared against is not")
	assert.NotContains(t, err.Error(), "Bo", "nor the value that was presented")
}

// mdoc keeps namespace-qualified claims as one literal dotted key while
// SD-JWT VC nests them, so the rule is resolved the way the presented
// credential's own format resolves paths - a caller writes the same path
// it would write anywhere else in this API.
func TestIdentityMatch_ResolvesPathsByFormat(t *testing.T) {
	client := newChallengeClient(t)

	match := &openid4vci.IdentityMatch{
		Claims: map[string]openid4vci.ClaimTest{
			"org.iso.18013.5.1.family_name": {Equals: "Andersson"},
		},
	}

	mdocClaims := map[string]any{"org.iso.18013.5.1.family_name": "Andersson"}
	require.NoError(t, client.matchPresentedIdentity("mso_mdoc", mdocClaims, match))

	// The same literal key is not a nested path, so SD-JWT resolution of
	// it must not accidentally succeed against a flat key.
	nested := map[string]any{"org": map[string]any{"iso": map[string]any{"18013": map[string]any{"5": map[string]any{"1": map[string]any{"family_name": "Andersson"}}}}}}
	require.NoError(t, client.matchPresentedIdentity("dc+sd-jwt", nested, match))
}

// An array claim matches when any element does, which is how the rest of
// this API treats array claims.
func TestIdentityMatch_ArrayClaims(t *testing.T) {
	client := newChallengeClient(t)

	match := &openid4vci.IdentityMatch{
		Claims: map[string]openid4vci.ClaimTest{"roles": {Equals: "legal_representative"}},
	}

	require.NoError(t, client.matchPresentedIdentity("dc+sd-jwt",
		map[string]any{"roles": []any{"employee", "legal_representative"}}, match))

	require.Error(t, client.matchPresentedIdentity("dc+sd-jwt",
		map[string]any{"roles": []any{"employee"}}, match))
}

// No rule means no check. That is only safe because preparing an issuance
// REQUIRES one - see TestPrepareIssuance_RequiresAMatchRule - so a nil
// rule here is an issuance that was never prepared this way, such as the
// ordinary wallet-initiated flow.
func TestIdentityMatch_NilRuleIsNotAFailure(t *testing.T) {
	client := newChallengeClient(t)
	require.NoError(t, client.matchPresentedIdentity("dc+sd-jwt", map[string]any{}, nil))
}

// Resuming a prepared offer applies the same request guards as starting
// an exchange from scratch. The two had drifted, in three ways.
//
// A Wallet that OFFERS auth_via_web must send a code_challenge whichever
// interaction the server then picks - the resume checked PKCE only for a
// PUBLIC client, so a confidential or attestation-authenticated wallet
// advertising that interaction could resume with none at all, while the
// same request without an issuer_state was refused. It also skipped the
// redirect_uri scheme check, which exists because the auth_via_web
// consent page renders WalletURI as a template.URL with scheme
// sanitisation deliberately off; and it still required a callback the
// browserless endpoint does not need.
//
// All three now run through one helper, so a guard added to the endpoint
// cannot reach only one of its two entrances.
func TestIssuerInitiated_ResumeAppliesTheSameRequestGuards(t *testing.T) {
	t.Run("a confidential wallet offering auth_via_web needs PKCE", func(t *testing.T) {
		client := newChallengeClient(t)
		issuerState := prepareIssuance(t, client, portalMatch())

		req := initialChallenge(t)
		req.Scope = ""
		req.IssuerState = issuerState
		req.CodeChallenge = ""
		req.InteractionTypesSupported = "urn:openid:dcp:ia:openid4vp_presentation,urn:openid:dcp:ia:auth_via_web"

		oauthErr := oauthErrFromChallenge(t, client, req)
		assert.Equal(t, oauth2.OAuthErrPKCERequired.ErrorCode, oauthErr.ErrorCode,
			"the wallet said it is prepared to be sent into a browser; the code is redeemed where this endpoint cannot see")
	})

	t.Run("a dangerous redirect_uri is refused", func(t *testing.T) {
		client := newChallengeClient(t)
		issuerState := prepareIssuance(t, client, portalMatch())

		req := initialChallenge(t)
		req.Scope = ""
		req.IssuerState = issuerState
		req.RedirectURI = "javascript:alert(1)"

		oauthErr := oauthErrFromChallenge(t, client, req)
		assert.Equal(t, oauth2.ErrCodeInvalidRequest, oauthErr.ErrorCode)
		assert.Contains(t, oauthErr.ErrorDescription, "redirect_uri")
	})

	t.Run("and a wallet with no callback can still resume", func(t *testing.T) {
		client := newChallengeClient(t)
		issuerState := prepareIssuance(t, client, portalMatch())

		req := initialChallenge(t)
		req.Scope = ""
		req.IssuerState = issuerState
		req.RedirectURI = ""

		opened := challengeErr(t, client, req)
		assert.Equal(t, 403, opened.HTTPStatus)
		assert.Equal(t, "insufficient_authorization", opened.ErrorCode)
		require.NotEmpty(t, opened.AuthSession)
	})

	// The interaction this scope actually needs is a presentation, so the
	// PKCE refusal above is about what the WALLET offered rather than what
	// the server picked - without this, that subtest could be passing for
	// the wrong reason.
	t.Run("the same wallet NOT offering auth_via_web resumes without PKCE", func(t *testing.T) {
		client := newChallengeClient(t)
		issuerState := prepareIssuance(t, client, portalMatch())

		req := initialChallenge(t)
		req.Scope = ""
		req.IssuerState = issuerState
		req.CodeChallenge = ""
		req.InteractionTypesSupported = "urn:openid:dcp:ia:openid4vp_presentation"

		opened := challengeErr(t, client, req)
		assert.Equal(t, 403, opened.HTTPStatus)
		assert.Equal(t, "insufficient_authorization", opened.ErrorCode)
	})
}
