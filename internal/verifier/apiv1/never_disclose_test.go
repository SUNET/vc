package apiv1

import (
	"testing"

	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ndPath(segments ...string) []*string {
	out := make([]*string, len(segments))
	for i := range segments {
		s := segments[i]
		out[i] = &s
	}
	return out
}

// The request object is where every query this verifier sends is built,
// whatever produced it - so a never-disclose claim must not survive it
// even when an operator's preset or a caller asked for one.
//
// Asserted on what CreateRequestObject produces rather than on the filter
// helper: the helper being correct is not what stops the leak, calling it
// here is, and an operator configuring a preset that asks for ssc is the
// case this exists for.
func TestCreateRequestObject_DropsNeverDiscloseClaims(t *testing.T) {
	ctx := t.Context()
	client := newSigningTestClient(t)

	query := &openid4vp.DCQL{
		Credentials: []openid4vp.CredentialQuery{{
			ID:     "pid",
			Format: "dc+sd-jwt",
			Meta:   openid4vp.MetaQuery{VCTValues: []string{"urn:eudi:pid:1"}},
			Claims: []openid4vp.ClaimQuery{
				{Path: ndPath("given_name")},
				{Path: ndPath("ssc")},
			},
		}},
	}

	_, err := client.CreateRequestObject(ctx, "session-1", query, "nonce-1", nil)
	require.NoError(t, err)

	// The query the caller handed in is what goes on to be stored and
	// matched against, so it is the one that must have been filtered.
	require.Len(t, query.Credentials, 1)
	require.Len(t, query.Credentials[0].Claims, 1,
		"the never-disclose claim must not survive into the request")
	assert.Equal(t, "given_name", *query.Credentials[0].Claims[0].Path[0])
}

// A query asking for nothing but a never-disclose claim is dropped
// entirely. Leaving it with no claims would mean "any claims" in DCQL -
// turning a request for one forbidden attribute into a request for every
// attribute the credential has.
func TestCreateRequestObject_DropsAQueryItWouldOtherwiseWiden(t *testing.T) {
	ctx := t.Context()
	client := newSigningTestClient(t)

	query := &openid4vp.DCQL{
		Credentials: []openid4vp.CredentialQuery{{
			ID:     "nym",
			Format: "mso_mdoc",
			Meta:   openid4vp.MetaQuery{DoctypeValue: "eu.europa.ec.eudi.nym_auth.1"},
			Claims: []openid4vp.ClaimQuery{
				{Path: ndPath("eu.europa.ec.eudi.nym_auth.1", "ssc")},
			},
		}},
	}

	_, err := client.CreateRequestObject(ctx, "session-2", query, "nonce-2", nil)
	require.NoError(t, err)

	assert.Empty(t, query.Credentials,
		"a query left with no claims would ask for all of them")
}

// A deployment that clears the list has said so deliberately, and gets
// what it asked for. This is the control for the two tests above: without
// it they would pass even if the filter blocked everything.
func TestCreateRequestObject_ClearedListFiltersNothing(t *testing.T) {
	ctx := t.Context()
	client := newSigningTestClient(t)
	client.cfg.Common.NeverDisclose = []string{}

	query := &openid4vp.DCQL{
		Credentials: []openid4vp.CredentialQuery{{
			ID:     "pid",
			Format: "dc+sd-jwt",
			Meta:   openid4vp.MetaQuery{VCTValues: []string{"urn:eudi:pid:1"}},
			Claims: []openid4vp.ClaimQuery{{Path: ndPath("ssc")}},
		}},
	}

	_, err := client.CreateRequestObject(ctx, "session-3", query, "nonce-3", nil)
	require.NoError(t, err)
	require.Len(t, query.Credentials, 1)
	assert.Len(t, query.Credentials[0].Claims, 1)
}

// A service built without a Common block still gets the control. A config
// shape that silently turned the filter off would be the worst of both
// worlds: the protection is absent exactly where nobody configured
// anything.
func TestNeverDiscloseDefaultsWhenUnconfigured(t *testing.T) {
	client := newSigningTestClient(t)
	client.cfg.Common = nil

	n := client.cfg.NeverDisclose()
	assert.True(t, n.BlocksName("ssc"))
	assert.True(t, n.BlocksName("psc"))
}
