package apiv1

import (
	"testing"

	"github.com/SUNET/vc/pkg/credential/primitives"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/oauth2"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ageDerivingScope is the shape that makes this reachable: a required
// birthdate and a derivation computing age from it. The birthdate comes
// from the presented credential, so its value is the Holder's rather than
// the configuration's.
func ageDerivingScope() model.PresentationScope {
	return model.PresentationScope{
		From: map[string]model.PresentedCredential{
			"eduid": {
				RequiredClaims: map[string][]string{"birthdate": nil},
				Derivations: []primitives.Derivation{{
					AgeOverThresholds: &primitives.AgeOverThresholdsArgs{
						Input: "birthdate", Thresholds: []int{18},
					},
				}},
			},
		},
	}
}

func presentedWithBirthdate(birthdate any) map[string]any {
	return map[string]any{
		"vct":       "urn:credential:eduid:1",
		"birthdate": birthdate,
	}
}

// What the wallet is told decides what it does next, and by the time a
// presentation is being turned into claims the auth_session has already
// been consumed - so "try again" and "this cannot work" are not
// interchangeable.
//
// A birthdate that is malformed or in the future passes every check
// before the derivation and fails inside it. That value is the Holder's
// data: reporting server_error tells the wallet to retry something no
// retry can fix, and there is nothing left to retry with.
func TestFinalisePresentationVerification_AnUnusableBirthdateIsNotAServerFault(t *testing.T) {
	// Every shape the credential can carry that the derivation cannot
	// use. With no allow-list configured, all of them pass the
	// required-claim check and fail inside the derivation - including the
	// two that never reach AgeOverThresholds at all.
	for name, birthdate := range map[string]any{
		"malformed":            "not-a-date",
		"in the future":        "2099-01-01",
		"present but empty":    "",
		"present but a number": 19901014,
		"present but a list":   []any{"1990-10-14"},
	} {
		t.Run(name, func(t *testing.T) {
			c := newPresentationTestClient(t)
			authCtx := seedAuthCtx(t, c, "sess-"+name)

			err := c.finalisePresentationVerification(
				t.Context(), authCtx, ageDerivingScope(), "eduid", presentedWithBirthdate(birthdate))
			require.Error(t, err)
			assert.NotErrorIs(t, err, ErrIssuanceAuthServerFault,
				"the credential's own birthdate is not something the server got wrong")

			// And the answer the wallet actually receives for it.
			challengeClient := newChallengeClient(t)
			oauthErr := &oauth2.OAuthError{}
			require.ErrorAs(t, challengeClient.interactiveAuthorizationFailure(err), &oauthErr)
			assert.Equal(t, oauth2.ErrCodeInvalidGrant, oauthErr.ErrorCode)
			assert.Equal(t, 400, oauthErr.HTTPStatus)
		})
	}
}

// The other half, so the classification cannot pass by calling everything
// the Holder's fault: a derivation that no presentation could satisfy is
// ours, and has to stay a 500 rather than be written off as the wallet's
// problem.
func TestFinalisePresentationVerification_AMisconfiguredDerivationIsAServerFault(t *testing.T) {
	c := newPresentationTestClient(t)
	authCtx := seedAuthCtx(t, c, "sess-misconfigured")

	pScope := ageDerivingScope()
	pScope.From["eduid"].Derivations[0].AgeOverThresholds.Input = "not_a_claim_this_scope_requires"

	err := c.finalisePresentationVerification(
		t.Context(), authCtx, pScope, "eduid", presentedWithBirthdate("1990-10-14"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrIssuanceAuthServerFault,
		"a derivation naming a claim nothing provides is a configuration fault - ABSENT is the "+
			"one case here that is not the Holder's, which is why it is not enough to mark every "+
			"derivation failure as theirs")

	challengeClient := newChallengeClient(t)
	oauthErr := &oauth2.OAuthError{}
	require.ErrorAs(t, challengeClient.interactiveAuthorizationFailure(err), &oauthErr)
	assert.Equal(t, oauth2.ErrCodeServerError, oauthErr.ErrorCode)
	assert.Equal(t, 500, oauthErr.HTTPStatus)
}

// And a usable birthdate still goes all the way through, so neither
// branch is passing by refusing everything.
func TestFinalisePresentationVerification_AUsableBirthdateSucceeds(t *testing.T) {
	c := newPresentationTestClient(t)
	authCtx := seedAuthCtx(t, c, "sess-usable")

	require.NoError(t, c.finalisePresentationVerification(
		t.Context(), authCtx, ageDerivingScope(), "eduid", presentedWithBirthdate("1990-10-14")))
}
