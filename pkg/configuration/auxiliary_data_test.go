package configuration

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/credential/primitives"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// One fixture per refusal rule of checkAuxiliaryData, and the base case it
// mutates, which loads.
func TestCheckAuxiliaryData(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "seed.key")
	require.NoError(t, os.WriteFile(secretPath, []byte(base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))), 0o600))
	ssc := []string{"eu.europa.ec.eudi.nym_auth.1", "ssc"}

	base := func() *model.Cfg {
		return &model.Cfg{
			Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{"nym_auth": {
				Format: "mso_mdoc",
				MDDL: &mdoc.MDDLSchema{Claims: map[string]mdoc.NamespaceClaims{"eu.europa.ec.eudi.nym_auth.1": {
					"birth_date": {ValueType: "full-date"},
					"ssc":        {ValueType: "bstr"},
					"psc":        {Mandatory: true, ValueType: "bstr"},
					"opt":        {ValueType: "bstr"},
				}}},
				AuxiliaryData: &openid4vci.AuxiliaryDataSupported{
					ToWallet: []openid4vci.AuxiliaryDataEntry{{Type: "hash_commitment", Alg: "sha-256", Path: ssc}},
				},
			}}},
			APIGW: &model.APIGW{DataSources: model.DataSources{Presentation: model.PresentationConfig{
				Scopes: map[string]model.PresentationScope{"nym_auth": {From: map[string]model.PresentedCredential{
					"pid": {Derivations: []primitives.Derivation{{HashCommitment: &primitives.HashCommitmentArgs{
						Path: ssc,
						Opening: primitives.OpeningArgs{HKDF: &primitives.HKDFOpeningArgs{
							SecretPath: secretPath, Inputs: []string{"personal_administrative_number"},
						}},
					}}}},
				}}},
			}}},
		}
	}
	entry := func(c *model.Cfg) *openid4vci.AuxiliaryDataEntry {
		return &c.Common.CredentialMetadata["nym_auth"].AuxiliaryData.ToWallet[0]
	}
	derivation := func(c *model.Cfg) *primitives.HashCommitmentArgs {
		return c.APIGW.DataSources.Presentation.Scopes["nym_auth"].From["pid"].Derivations[0].HashCommitment
	}

	require.NoError(t, checkAuxiliaryData(base(), "apigw"))

	t.Run("required comes from mandatory", func(t *testing.T) {
		cfg := base()
		cfg.Common.CredentialMetadata["nym_auth"].AuxiliaryData.ToIssuer = []openid4vci.AuxiliaryDataEntry{
			{Type: "hash_commitment", Alg: "sha-256", Path: []string{ssc[0], "psc"}},
			{Type: "hash_commitment", Alg: "sha-256", Path: []string{ssc[0], "opt"}},
		}
		require.NoError(t, checkAuxiliaryData(cfg, "apigw"))
		deriveAuxiliaryDataRequired(cfg)
		toIssuer := cfg.Common.CredentialMetadata["nym_auth"].AuxiliaryData.ToIssuer
		assert.True(t, toIssuer[0].Required, "psc is mandatory")
		assert.False(t, toIssuer[1].Required, "opt is optional")
	})

	for name, tc := range map[string]struct {
		mutate func(*model.Cfg)
		want   string
	}{
		"an unknown type":      {func(c *model.Cfg) { entry(c).Type = "x" }, `type "x"`},
		"an unknown alg":       {func(c *model.Cfg) { entry(c).Alg = "sha-512" }, `alg "sha-512"`},
		"an opening in config": {func(c *model.Cfg) { entry(c).Opening = "AA" }, "carries no opening"},
		"a non-bstr element":   {func(c *model.Cfg) { entry(c).Path = []string{ssc[0], "birth_date"} }, "full-date element"},
		"an undeclared path":   {func(c *model.Cfg) { entry(c).Path = []string{ssc[0], "nope"} }, "declares no element"},
		"required set in config": {func(c *model.Cfg) {
			c.Common.CredentialMetadata["nym_auth"].AuxiliaryData.ToIssuer = []openid4vci.AuxiliaryDataEntry{{Type: "hash_commitment", Alg: "sha-256", Path: []string{ssc[0], "psc"}, Required: true}}
		}, "comes from the MDDL"},
		"an unfulfilled to_wallet entry": {func(c *model.Cfg) {
			c.APIGW.DataSources.Presentation.Scopes["nym_auth"].From["pid"] = model.PresentedCredential{}
		}, "no hash_commitment derivation fulfils"},
		"a derivation for a path outside to_wallet": {func(c *model.Cfg) {
			derivation(c).Path = []string{ssc[0], "birth_date"}
		}, "is no to_wallet entry"},
		"an unreadable secret": {func(c *model.Cfg) {
			derivation(c).Opening.HKDF.SecretPath = filepath.Join(t.TempDir(), "absent")
		}, "opening: hkdf: reading the opening secret"},
		"an opening with two generators": {func(c *model.Cfg) {
			derivation(c).Opening.Random = &primitives.RandomOpeningArgs{}
		}, "exactly one of hkdf and random"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := base()
			tc.mutate(cfg)
			err := checkAuxiliaryData(cfg, "apigw")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}
