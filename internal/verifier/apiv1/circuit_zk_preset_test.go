package apiv1

import (
	"testing"

	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/sdjwtvc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func circuitZkPresetConfig(t *testing.T, scopeCfg *model.VerificationPresetScope, vctm *sdjwtvc.VCTM) *model.Cfg {
	t.Helper()
	schema := &mdoc.MDDLSchema{
		Format:  "mso_mdoc",
		DocType: "eu.europa.ec.eudi.nym_auth.1",
		Claims: map[string]mdoc.NamespaceClaims{
			"eu.europa.ec.eudi.nym_auth.1": {
				"secret_seed_commitment": {Mandatory: true, ValueType: "bstr"},
			},
		},
	}
	return &model.Cfg{
		Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				"nym": {Format: "mso_mdoc", MDDL: schema, Attributes: schema.Attributes(), VCTM: vctm},
			},
		},
		Verifier: &model.Verifier{
			Presets: map[string]model.PresetDefinition{
				"Nym": {Credentials: model.VerificationPreset{"nym": scopeCfg}},
			},
		},
	}
}

var nymNamespace = func() *string { s := "eu.europa.ec.eudi.nym_auth.1"; return &s }()

var nymReq = []openid4vp.ReqItem{{
	ID:     openid4vp.FunctionPseudonym,
	Return: "nym-123",
	Params: map[string]any{"config": "known-offender-matching-ssc", "verifier_id_type": "x509_san_dns"},
}}

// The picker builds the DCQL query in the browser and posts it back, so
// anything the query needs has to reach it. A circuit_zk query discloses
// nothing - every value it yields is the output of a function named in
// req - so a req left server-side produces a request asking for nothing,
// which a wallet answers with nothing, and the failure reads as the
// wallet's.
func TestCircuitZkPresetPublishesReq(t *testing.T) {
	cfg := circuitZkPresetConfig(t, &model.VerificationPresetScope{
		Format: openid4vp.FormatCircuitZk,
		Req:    nymReq,
	}, nil)
	client, _ := CreateTestClientWithMock(t, cfg)
	client.cfg = cfg

	reply, err := client.UIMetadata(t.Context())
	require.NoError(t, err)
	preset := reply.Presets["Nym"]
	require.NotNil(t, preset)
	require.Len(t, preset.Credentials, 1)

	credential := preset.Credentials[0]
	assert.Equal(t, openid4vp.FormatCircuitZk, credential.Format)
	assert.Equal(t, "eu.europa.ec.eudi.nym_auth.1", credential.Meta.DoctypeValue,
		"circuit_zk is matched on doctype_value, like the mdoc it proves over")
	require.Equal(t, nymReq, credential.Req)
}

// The claims fall-back exists for formats whose claims ARE the query.
// Applied to circuit_zk it attaches every attribute in the document to a
// request whose whole point is to disclose none of them - and the UI
// would then post that query back, so it is not cosmetic.
func TestCircuitZkPresetCarriesNoClaims(t *testing.T) {
	for _, tc := range []struct {
		name   string
		claims []model.VerificationPresetClaim
		vctm   *sdjwtvc.VCTM
	}{
		{"with claims configured, which for this format is a mistake", []model.VerificationPresetClaim{
			{Path: []string{"eu.europa.ec.eudi.nym_auth.1", "secret_seed_commitment"}},
		}, nil},
		// The fall-back reads GetVCTM(), which an mdoc scope normally has
		// nothing in - so this case gives it one. Not idle: the fall-back
		// is keyed on the document, not on the format, and a scope
		// carrying both documents is a configuration an operator can
		// write today.
		{"with none, where the metadata document would supply them", nil, &sdjwtvc.VCTM{
			VCT: "urn:eudi:nym_auth:1",
			Claims: []sdjwtvc.Claim{
				{Path: []*string{nymNamespace}},
			},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := circuitZkPresetConfig(t, &model.VerificationPresetScope{
				Format: openid4vp.FormatCircuitZk,
				Req:    nymReq,
				Claims: tc.claims,
			}, tc.vctm)
			client, _ := CreateTestClientWithMock(t, cfg)
			client.cfg = cfg

			reply, err := client.UIMetadata(t.Context())
			require.NoError(t, err)
			require.Len(t, reply.Presets["Nym"].Credentials, 1)
			assert.Empty(t, reply.Presets["Nym"].Credentials[0].Claims)
		})
	}
}

// Same shape of guard the mso_mdoc_zk override already has: publish a
// preset the format cannot satisfy and the operator sees a button that
// returns nothing, with no error anywhere.
func TestCircuitZkPresetWithoutReqIsOmitted(t *testing.T) {
	cfg := circuitZkPresetConfig(t, &model.VerificationPresetScope{Format: openid4vp.FormatCircuitZk}, nil)
	client, _ := CreateTestClientWithMock(t, cfg)
	client.cfg = cfg

	reply, err := client.UIMetadata(t.Context())
	require.NoError(t, err)
	if preset := reply.Presets["Nym"]; preset != nil {
		assert.Empty(t, preset.Credentials,
			"a circuit_zk preset with no req asks for nothing and must not be published")
	}
}

// An override may not change what the credential is matched BY.
// circuit_zk matches on doctype_value, so it can be asked of an mdoc
// scope and not of an SD-JWT one - pairing it with vct_values would send
// a query no wallet can satisfy.
func TestCircuitZkOverrideKeepsTheConstraintFamily(t *testing.T) {
	assert.True(t, sameConstraintFamily(openid4vp.FormatMsoMdoc, openid4vp.FormatCircuitZk))
	assert.False(t, sameConstraintFamily(openid4vp.FormatSDJWTVC, openid4vp.FormatCircuitZk))
}
