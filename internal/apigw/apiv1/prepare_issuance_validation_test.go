package apiv1

import (
	"testing"

	"github.com/SUNET/vc/pkg/claimpath"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A prepared issuance is printed and handed to somebody. Returning one
// whose challenge exchange can never open moves a configuration error
// from the operator, who can fix it, to a Holder standing in front of a
// wallet that will not finish.
//
// buildIssuanceAuthDCQL refuses to build a request for an authentication
// scope whose format this flow cannot verify - a W3C credential, which
// issuance auth has never been taught to read - so preparation asks it
// the question before answering.
func TestPrepareIssuance_RefusesAScopeWhoseRequestCannotBeBuilt(t *testing.T) {
	for name, metadata := range map[string]*model.CredentialMetadata{
		"a W3C authentication credential": {
			Format: openid4vp.FormatLdpVC,
			VCTM:   &sdjwtvc.VCTM{VCT: "urn:example:w3c:1"},
		},
		"no usable meta constraint": {
			Format: openid4vp.FormatSDJWTVC,
		},
	} {
		t.Run(name, func(t *testing.T) {
			client := newChallengeClient(t)
			client.cfg.Common.CredentialMetadata[challengeAuthScope] = metadata

			reply, err := client.PrepareIssuance(t.Context(), &PrepareIssuanceRequest{
				Scope:         challengeScope,
				IdentityMatch: portalMatch(),
			})
			require.Error(t, err, "an offer nobody can redeem must not be handed out")
			assert.Nil(t, reply)
			assert.Contains(t, err.Error(), "cannot be turned into a presentation request")
		})
	}
}

// An mdoc's claims are namespace-qualified, and buildIssuanceAuthDCQL
// expands a bare auth_claims entry into that form because DCQL requires
// it. A rule written the qualified way - the way it must be written to
// match an mdoc's literal key - was therefore reported as asking for a
// claim the request does not disclose, even though the request asks for
// exactly that claim under its expanded name.
func TestPrepareIssuance_MatchesAnMdocClaimUnderEitherSpelling(t *testing.T) {
	for name, ruleClaim := range map[string]string{
		"written bare":                "family_name",
		"written namespace-qualified": "org.iso.18013.5.1.family_name",
	} {
		t.Run(name, func(t *testing.T) {
			client := newChallengeClient(t)

			// An mdoc authentication credential, whose bare auth claim
			// "family_name" the loader reads as the element of
			// org.iso.18013.5.1.
			client.cfg.Common.CredentialMetadata[challengeAuthScope] = &model.CredentialMetadata{
				Format:  openid4vp.FormatMsoMdoc,
				Doctype: "org.iso.18013.5.1.mDL",
			}
			scopes := client.cfg.APIGW.DataSources.Datastore.Scopes[challengeScope]
			scopes.AuthScopes = map[string]model.AuthScopeEntry{
				challengeAuthScope: {AuthClaims: []claimpath.Pointer{claimpath.Keys("org.iso.18013.5.1", "family_name")}},
			}
			client.cfg.APIGW.DataSources.Datastore.Scopes[challengeScope] = scopes

			reply, err := client.PrepareIssuance(t.Context(), &PrepareIssuanceRequest{
				Scope: challengeScope,
				IdentityMatch: &openid4vci.IdentityMatch{
					Claims: openid4vci.ClaimMatches{{Path: dottedPath(ruleClaim), ClaimTest: openid4vci.ClaimTest{Equals: "Andersson"}}},
				},
			})
			require.NoError(t, err, "the request asks for this claim, however the rule spells it")
			require.NotNil(t, reply)
			assert.NotEmpty(t, reply.IssuerState)
		})
	}
}

// The normalisation must not make unrelated claims equal: a rule naming
// something the request never asks for is still unaskable.
func TestPrepareIssuance_StillRefusesAClaimTheRequestDoesNotAsk(t *testing.T) {
	client := newChallengeClient(t)

	reply, err := client.PrepareIssuance(t.Context(), &PrepareIssuanceRequest{
		Scope: challengeScope,
		IdentityMatch: &openid4vci.IdentityMatch{
			Claims: openid4vci.ClaimMatches{{Path: dottedPath("nationality"), ClaimTest: openid4vci.ClaimTest{Equals: "SE"}}},
		},
	})
	require.Error(t, err)
	assert.Nil(t, reply)
	assert.Contains(t, err.Error(), "nationality")
}
