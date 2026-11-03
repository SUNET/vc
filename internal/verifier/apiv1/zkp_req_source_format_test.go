package apiv1

import (
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// meta.source_format names the stored attestation the proof is made over,
// and the matcher's planner refuses a zkp_req meta without one
// (invalid_meta) before it looks at anything else. A request built without
// it is one no wallet can answer, and the refusal reads as the wallet's.
//
// It is derived, never configured: the scope's own credential_metadata
// format is the credential the wallet holds, and a second place to state
// it is a second place for the two to disagree.
func TestZkpReqPresetPublishesSourceFormat(t *testing.T) {
	cfg := circuitZkPresetConfig(t, &model.VerificationPresetScope{
		Format: openid4vp.FormatZkpReq,
		Req:    nymReq,
	}, nil)
	client, _ := CreateTestClientWithMock(t, cfg)
	client.cfg = cfg

	reply, err := client.UIMetadata(t.Context())
	require.NoError(t, err)
	preset := reply.Presets["Nym"]
	require.NotNil(t, preset)
	require.Len(t, preset.Credentials, 1)

	assert.Equal(t, "mso_mdoc", preset.Credentials[0].Meta.SourceFormat,
		"the scope stores an mso_mdoc, so that is what a proof over it is made over")
}

// The DCQL comes back from the browser, so the preset above is only half
// the path: a client that rebuilds the query from the fields it knows
// drops a member it has never heard of, and the request goes out
// unanswerable again. The server fills it rather than trusting the round
// trip.
func TestUIInteractionFillsSourceFormatForAZkpReqQuery(t *testing.T) {
	cfg := circuitZkPresetConfig(t, &model.VerificationPresetScope{
		Format: openid4vp.FormatZkpReq,
		Req:    nymReq,
	}, nil)
	cfg.Verifier.PublicURL = "https://verifier.example.com"
	client, _ := CreateTestClientWithMock(t, cfg)
	client.cfg = cfg

	query := &openid4vp.DCQL{
		Credentials: []openid4vp.CredentialQuery{{
			ID:     "nym",
			Format: openid4vp.FormatZkpReq,
			Meta:   openid4vp.MetaQuery{DoctypeValue: "eu.europa.ec.eudi.nym_auth.1"},
			Req:    nymReq,
		}},
	}
	_, err := client.UIInteraction(t.Context(), &UIInteractionRequest{DCQLQuery: query})
	require.NoError(t, err)

	assert.Equal(t, "mso_mdoc", query.Credentials[0].Meta.SourceFormat,
		"the scope's credential_metadata format is what the proof is made over")
}

// A client that does send one is not overruled: source_format is the
// wallet's side of the request, and a deliberate value - a negative test
// aimed at a wallet, say - has to survive a verifier whose whole purpose
// is testing wallets.
func TestUIInteractionKeepsAClientSuppliedSourceFormat(t *testing.T) {
	cfg := circuitZkPresetConfig(t, &model.VerificationPresetScope{
		Format: openid4vp.FormatZkpReq,
		Req:    nymReq,
	}, nil)
	cfg.Verifier.PublicURL = "https://verifier.example.com"
	client, _ := CreateTestClientWithMock(t, cfg)
	client.cfg = cfg

	query := &openid4vp.DCQL{
		Credentials: []openid4vp.CredentialQuery{{
			ID:     "nym",
			Format: openid4vp.FormatZkpReq,
			Meta: openid4vp.MetaQuery{
				DoctypeValue: "eu.europa.ec.eudi.nym_auth.1",
				SourceFormat: "bbs_cd",
			},
			Req: nymReq,
		}},
	}
	_, err := client.UIInteraction(t.Context(), &UIInteractionRequest{DCQLQuery: query})
	require.NoError(t, err)

	assert.Equal(t, "bbs_cd", query.Credentials[0].Meta.SourceFormat)
}

// With no scope to derive it from there is nothing to fill in, and a
// request that goes out without one cannot be answered. Refuse at the
// verifier, where the operator sees it, rather than at a wallet.
func TestUIInteractionRefusesAZkpReqQueryWithNoScopeToDeriveFrom(t *testing.T) {
	cfg := circuitZkPresetConfig(t, &model.VerificationPresetScope{
		Format: openid4vp.FormatZkpReq,
		Req:    nymReq,
	}, nil)
	cfg.Verifier.PublicURL = "https://verifier.example.com"
	client, _ := CreateTestClientWithMock(t, cfg)
	client.cfg = cfg

	_, err := client.UIInteraction(t.Context(), &UIInteractionRequest{DCQLQuery: &openid4vp.DCQL{
		Credentials: []openid4vp.CredentialQuery{{
			ID:     "no_such_scope",
			Format: openid4vp.FormatZkpReq,
			Meta:   openid4vp.MetaQuery{DoctypeValue: "eu.europa.ec.eudi.nym_auth.1"},
			Req:    nymReq,
		}},
	}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "meta.source_format")
}
