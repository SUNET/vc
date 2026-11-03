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
			// A circuit_zk query is answered with a proof, and which
			// circuits this verifier accepts one from lives here. Without
			// it the preset is not published at all, which is the subject
			// of TestCircuitZkPresetNeedsTheFormatAdvertised.
			PreferredVPFormats: &openid4vp.VPFormatsSupported{
				MsoMdoc: &openid4vp.MsoMdocFormat{},
				ZkpReq:  &openid4vp.ZkpReqFormat{},
			},
			Presets: map[string]model.PresetDefinition{
				"Nym": {Credentials: model.VerificationPreset{"nym": scopeCfg}},
			},
		},
	}
}

var nymNamespace = func() *string { s := "eu.europa.ec.eudi.nym_auth.1"; return &s }()

var nymReq = []openid4vp.ReqItem{{
	FnID:   openid4vp.FunctionPseudonym,
	Return: "nym-123",
	Params: map[string]any{"config": "known-offender-matching-ssc"},
}}

// The picker builds the DCQL query in the browser and posts it back, so
// anything the query needs has to reach it. A circuit_zk query discloses
// nothing - every value it yields is the output of a function named in
// req - so a req left server-side produces a request asking for nothing,
// which a wallet answers with nothing, and the failure reads as the
// wallet's.
func TestCircuitZkPresetPublishesReq(t *testing.T) {
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

	credential := preset.Credentials[0]
	assert.Equal(t, openid4vp.FormatZkpReq, credential.Format)
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
				Format: openid4vp.FormatZkpReq,
				Req:    nymReq,
				Claims: tc.claims,
			}, tc.vctm)
			client, _ := CreateTestClientWithMock(t, cfg)
			client.cfg = cfg

			reply, err := client.UIMetadata(t.Context())
			require.NoError(t, err)
			preset := reply.Presets["Nym"]
			require.NotNil(t, preset)
			require.Len(t, preset.Credentials, 1)
			assert.Empty(t, preset.Credentials[0].Claims)
		})
	}
}

// Same shape of guard the mso_mdoc_zk override already has: publish a
// preset the format cannot satisfy and the operator sees a button that
// returns nothing, with no error anywhere.
func TestCircuitZkPresetWithoutReqIsOmitted(t *testing.T) {
	cfg := circuitZkPresetConfig(t, &model.VerificationPresetScope{Format: openid4vp.FormatZkpReq}, nil)
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
	assert.True(t, sameConstraintFamily(openid4vp.FormatMsoMdoc, openid4vp.FormatZkpReq))
	assert.False(t, sameConstraintFamily(openid4vp.FormatSDJWTVC, openid4vp.FormatZkpReq))
}

// The circuit filter - which proof systems and circuits this verifier
// will accept a proof from - lives in
// client_metadata.vp_formats_supported.circuit_zk and nowhere else.
// vpFormatsOrDefault's default names only dc+sd-jwt and mso_mdoc, so a
// deployment that never configured preferred_vp_formats would publish
// this preset and then send the query alongside metadata declaring no
// support for its format at all.
//
// No default is invented: those identifiers are deployment-specific, and
// guessing one would pin this verifier to whichever implementation
// happened to be in front of whoever wrote it. An EMPTY circuit_zk object
// is a perfectly good answer - the shared vectors read a missing filter
// as "any circuit" - but it has to be the operator's answer.
func TestCircuitZkPresetNeedsTheFormatAdvertised(t *testing.T) {
	for _, tc := range []struct {
		name    string
		formats *openid4vp.VPFormatsSupported
		publish bool
	}{
		{"nothing configured, so the default applies and names no circuit_zk", nil, false},
		{"configured, but without circuit_zk", &openid4vp.VPFormatsSupported{
			MsoMdoc: &openid4vp.MsoMdocFormat{},
		}, false},
		{"an empty circuit_zk, which means any circuit", &openid4vp.VPFormatsSupported{
			ZkpReq: &openid4vp.ZkpReqFormat{},
		}, true},
		{"and one naming a filter", &openid4vp.VPFormatsSupported{
			ZkpReq: &openid4vp.ZkpReqFormat{
				ProofSystemValues: []string{"longfellow-libzk-v1"},
			},
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := circuitZkPresetConfig(t, &model.VerificationPresetScope{
				Format: openid4vp.FormatZkpReq,
				Req:    nymReq,
			}, nil)
			cfg.Verifier.PreferredVPFormats = tc.formats

			client, _ := CreateTestClientWithMock(t, cfg)
			client.cfg = cfg
			reply, err := client.UIMetadata(t.Context())
			require.NoError(t, err)

			preset := reply.Presets["Nym"]
			if !tc.publish {
				if preset != nil {
					assert.Empty(t, preset.Credentials,
						"a wallet would be asked for a proof the request declares no support for")
				}
				return
			}
			require.NotNil(t, preset)
			require.Len(t, preset.Credentials, 1)
		})
	}
}

// The circuit_zk requirement must not reach any other format. My first
// version of that guard was not gated on the format at all, so it dropped
// every preset carrying ANY format override whenever circuit_zk was
// unadvertised - which the existing mso_mdoc_zk test caught. This keeps
// the two apart on purpose rather than by accident.
func TestTheCircuitZkRequirementDoesNotTouchOtherFormats(t *testing.T) {
	schema := &mdoc.MDDLSchema{Format: "mso_mdoc", DocType: "eu.europa.ec.eudi.pid.1"}
	cfg := &model.Cfg{
		Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				"pid": {Format: "mso_mdoc", MDDL: schema, Attributes: schema.Attributes()},
			},
		},
		Verifier: &model.Verifier{
			// Deliberately no circuit_zk.
			PreferredVPFormats: &openid4vp.VPFormatsSupported{MsoMdoc: &openid4vp.MsoMdocFormat{}},
			Presets: map[string]model.PresetDefinition{
				"ZK": {Credentials: model.VerificationPreset{"pid": &model.VerificationPresetScope{
					Format:       openid4vp.FormatMsoMdocZk,
					ZKSystemType: []openid4vp.ZKSystemTypeSpec{{ID: "circuit-1", System: "longfellow"}},
				}}},
				"Plain": {Credentials: model.VerificationPreset{"pid": nil}},
			},
		},
	}
	client, _ := CreateTestClientWithMock(t, cfg)
	client.cfg = cfg

	reply, err := client.UIMetadata(t.Context())
	require.NoError(t, err)
	require.Contains(t, reply.Presets, "ZK")
	require.Len(t, reply.Presets["ZK"].Credentials, 1,
		"mso_mdoc_zk declares its circuits in meta.zk_system_type, not in vp_formats_supported.circuit_zk")
	require.Contains(t, reply.Presets, "Plain")
	require.Len(t, reply.Presets["Plain"].Credentials, 1)
}

// A preset is a NAMED REQUEST. Dropping only the unusable credential
// publishes "PID + Pseudonym" as PID-only: a button that silently asks
// for something other than what it says, which is worse than no button -
// and the configuration reference says the preset is omitted.
func TestAMixedPresetIsNotPublishedWithoutItsCircuitCredential(t *testing.T) {
	pidSchema := &mdoc.MDDLSchema{Format: "mso_mdoc", DocType: "eu.europa.ec.eudi.pid.1"}
	nymSchema := &mdoc.MDDLSchema{Format: "mso_mdoc", DocType: "eu.europa.ec.eudi.nym_auth.1"}

	build := func(scopeCfg *model.VerificationPresetScope, formats *openid4vp.VPFormatsSupported) *model.Cfg {
		return &model.Cfg{
			Common: &model.Common{
				CredentialMetadata: map[string]*model.CredentialMetadata{
					"pid": {Format: "mso_mdoc", MDDL: pidSchema, Attributes: pidSchema.Attributes()},
					"nym": {Format: "mso_mdoc", MDDL: nymSchema, Attributes: nymSchema.Attributes()},
				},
			},
			Verifier: &model.Verifier{
				PreferredVPFormats: formats,
				Presets: map[string]model.PresetDefinition{
					"PID + Pseudonym": {Credentials: model.VerificationPreset{
						"pid": nil,
						"nym": scopeCfg,
					}},
				},
			},
		}
	}

	advertised := &openid4vp.VPFormatsSupported{
		MsoMdoc: &openid4vp.MsoMdocFormat{},
		ZkpReq:  &openid4vp.ZkpReqFormat{},
	}

	for _, tc := range []struct {
		name     string
		scopeCfg *model.VerificationPresetScope
		formats  *openid4vp.VPFormatsSupported
	}{
		{
			name:     "with no req",
			scopeCfg: &model.VerificationPresetScope{Format: openid4vp.FormatZkpReq},
			formats:  advertised,
		},
		{
			name:     "with circuit_zk unadvertised",
			scopeCfg: &model.VerificationPresetScope{Format: openid4vp.FormatZkpReq, Req: nymReq},
			formats:  &openid4vp.VPFormatsSupported{MsoMdoc: &openid4vp.MsoMdocFormat{}},
		},
		{
			name: "with a param the browser would change",
			scopeCfg: &model.VerificationPresetScope{
				Format: openid4vp.FormatZkpReq,
				Req: []openid4vp.ReqItem{{
					FnID: openid4vp.FunctionPseudonym, Return: "nym-1",
					Params: map[string]any{"counter": int64(9007199254740993)},
				}},
			},
			formats: advertised,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := build(tc.scopeCfg, tc.formats)
			client, _ := CreateTestClientWithMock(t, cfg)
			client.cfg = cfg

			reply, err := client.UIMetadata(t.Context())
			require.NoError(t, err)

			if preset := reply.Presets["PID + Pseudonym"]; preset != nil {
				assert.Failf(t, "the preset was published",
					"it asks for %d credential(s) instead of the 2 configured, under a label promising both",
					len(preset.Credentials))
			}
		})
	}

	t.Run("and it IS published when the circuit credential is usable", func(t *testing.T) {
		cfg := build(&model.VerificationPresetScope{Format: openid4vp.FormatZkpReq, Req: nymReq}, advertised)
		client, _ := CreateTestClientWithMock(t, cfg)
		client.cfg = cfg

		reply, err := client.UIMetadata(t.Context())
		require.NoError(t, err)
		preset := reply.Presets["PID + Pseudonym"]
		require.NotNil(t, preset)
		assert.Len(t, preset.Credentials, 2, "both credentials, as configured")
	})
}
