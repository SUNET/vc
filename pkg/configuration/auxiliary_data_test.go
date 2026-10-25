package configuration

import (
	"encoding/base64"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/credential/primitives"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/sdjwtvc"

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
						Opening: &primitives.OpeningArgs{HKDF: &primitives.HKDFOpeningArgs{
							SecretPath: secretPath, Inputs: []string{"personal_administrative_number"}, Bytes: 16,
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
	psc := []string{ssc[0], "psc"}
	// withPSC makes psc a to_issuer entry and configures it in the pid
	// source scope.
	withPSC := func(c *model.Cfg, hc primitives.HashCommitmentArgs) *primitives.HashCommitmentArgs {
		c.Common.CredentialMetadata["nym_auth"].AuxiliaryData.ToIssuer = []openid4vci.AuxiliaryDataEntry{{Type: "hash_commitment", Alg: "sha-256", Path: psc}}
		pid := c.APIGW.DataSources.Presentation.Scopes["nym_auth"].From["pid"]
		pid.Derivations = append(pid.Derivations, primitives.Derivation{HashCommitment: &hc})
		c.APIGW.DataSources.Presentation.Scopes["nym_auth"].From["pid"] = pid
		return &hc
	}

	require.NoError(t, checkAuxiliaryData(base(), "apigw"))

	t.Run("a tstr element holds an encoded commitment", func(t *testing.T) {
		cfg := base()
		cfg.Common.CredentialMetadata["nym_auth"].MDDL.Claims[ssc[0]]["text"] = mdoc.ClaimMetadata{ValueType: "tstr"}
		entry(cfg).Path, entry(cfg).Encoding = []string{ssc[0], "text"}, "hex"
		derivation(cfg).Path = []string{ssc[0], "text"}
		require.NoError(t, checkAuxiliaryData(cfg, "apigw"))
	})

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

	t.Run("unique is optional, with a key of any length, on either direction", func(t *testing.T) {
		for name, mutate := range map[string]func(*model.Cfg){
			"a to_issuer entry without a derivation": func(c *model.Cfg) {
				c.Common.CredentialMetadata["nym_auth"].AuxiliaryData.ToIssuer = []openid4vci.AuxiliaryDataEntry{{Type: "hash_commitment", Alg: "sha-256", Path: psc}}
			},
			"a to_issuer derivation without unique": func(c *model.Cfg) { withPSC(c, primitives.HashCommitmentArgs{Path: psc}) },
			"one commitment for the entry": func(c *model.Cfg) {
				withPSC(c, primitives.HashCommitmentArgs{Path: psc, Unique: &primitives.UniqueArgs{Key: [][]string{}}})
			},
			"unique per another entry": func(c *model.Cfg) {
				withPSC(c, primitives.HashCommitmentArgs{Path: psc, Unique: &primitives.UniqueArgs{Key: [][]string{ssc}}})
			},
			"unique per a composite key": func(c *model.Cfg) {
				withPSC(c, primitives.HashCommitmentArgs{Path: psc, Unique: &primitives.UniqueArgs{Key: [][]string{ssc, {ssc[0], "birth_date"}}}})
			},
			"a unique to_wallet entry": func(c *model.Cfg) {
				derivation(c).Unique = &primitives.UniqueArgs{Key: [][]string{{ssc[0], "birth_date"}}}
			},
		} {
			cfg := base()
			mutate(cfg)
			require.NoError(t, checkAuxiliaryData(cfg, "apigw"), name)
		}
	})

	for name, tc := range map[string]struct {
		mutate func(*model.Cfg)
		want   string
	}{
		"an unknown type":               {func(c *model.Cfg) { entry(c).Type = "x" }, `type "x"`},
		"an unknown alg":                {func(c *model.Cfg) { entry(c).Alg = "sha-512" }, `alg "sha-512"`},
		"an opening in config":          {func(c *model.Cfg) { entry(c).Opening = "AA" }, "carries no opening"},
		"a non-bstr element":            {func(c *model.Cfg) { entry(c).Path = []string{ssc[0], "birth_date"} }, "full-date element"},
		"an undeclared path":            {func(c *model.Cfg) { entry(c).Path = []string{ssc[0], "nope"} }, "declares no element"},
		"an encoding on a bstr element": {func(c *model.Cfg) { entry(c).Encoding = "hex" }, "a commitment in hex text needs a tstr element"},
		"required set in config": {func(c *model.Cfg) {
			c.Common.CredentialMetadata["nym_auth"].AuxiliaryData.ToIssuer = []openid4vci.AuxiliaryDataEntry{{Type: "hash_commitment", Alg: "sha-256", Path: []string{ssc[0], "psc"}, Required: true}}
		}, "comes from the type metadata"},
		"an unfulfilled to_wallet entry": {func(c *model.Cfg) {
			c.APIGW.DataSources.Presentation.Scopes["nym_auth"].From["pid"] = model.PresentedCredential{}
		}, "no hash_commitment derivation fulfils"},
		"a derivation for a path outside auxiliary_data": {func(c *model.Cfg) {
			derivation(c).Path = []string{ssc[0], "birth_date"}
		}, "is no auxiliary_data entry"},
		"an unreadable secret": {func(c *model.Cfg) {
			derivation(c).Opening.HKDF.SecretPath = filepath.Join(t.TempDir(), "absent")
		}, "opening: hkdf: the opening secret"},
		"an opening without a length": {func(c *model.Cfg) {
			derivation(c).Opening.HKDF.Bytes = 0
		}, "an opening has 16 to 64 bytes, got 0"},
		"an opening with two generators": {func(c *model.Cfg) {
			derivation(c).Opening.Random = &primitives.RandomOpeningArgs{Bytes: 16}
		}, "exactly one of hkdf and random"},
		"a to_wallet entry without an opening": {func(c *model.Cfg) {
			derivation(c).Opening = nil
		}, "is a to_wallet entry, which takes an opening"},
		"a to_issuer entry with an opening": {func(c *model.Cfg) {
			withPSC(c, primitives.HashCommitmentArgs{Path: psc, Opening: &primitives.OpeningArgs{Random: &primitives.RandomOpeningArgs{Bytes: 16}}})
		}, "is a to_issuer entry, whose opening the wallet holds"},
		"an entry configured twice": {func(c *model.Cfg) {
			withPSC(c, primitives.HashCommitmentArgs{Path: psc})
			withPSC(c, primitives.HashCommitmentArgs{Path: psc})
		}, "is configured twice"},
		"a key part outside the MDDL": {func(c *model.Cfg) {
			withPSC(c, primitives.HashCommitmentArgs{Path: psc, Unique: &primitives.UniqueArgs{Key: [][]string{{ssc[0], "nope"}}}})
		}, "the type metadata declares no claim at key part"},
		"a key part that is the entry itself": {func(c *model.Cfg) {
			withPSC(c, primitives.HashCommitmentArgs{Path: psc, Unique: &primitives.UniqueArgs{Key: [][]string{psc}}})
		}, "is the entry itself, which every commitment matches"},
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

// The SD-JWT VC rules of checkAuxiliaryData: one fixture per refusal, and
// the base case they mutate, which loads with required taken from the
// VCTM's mandatory flag.
func TestCheckAuxiliaryDataSDJWT(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "seed.key")
	require.NoError(t, os.WriteFile(secretPath, []byte(base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))), 0o600))
	ssc, psc := []string{"commitments", "ssc"}, []string{"commitments", "psc"}
	claim := func(sd string, mandatory bool, path ...string) sdjwtvc.Claim {
		segments := make([]*string, len(path))
		for i := range path {
			segments[i] = &path[i]
		}
		return sdjwtvc.Claim{Path: segments, SD: sd, Mandatory: mandatory}
	}

	base := func() *model.Cfg {
		return &model.Cfg{
			Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{"example": {
				Format: "dc+sd-jwt",
				VCTM: &sdjwtvc.VCTM{VCT: "https://example.org/example", Claims: []sdjwtvc.Claim{
					claim("always", false, ssc...), claim("always", true, psc...), claim("", false, "given_name"),
				}},
				AuxiliaryData: &openid4vci.AuxiliaryDataSupported{
					ToWallet: []openid4vci.AuxiliaryDataEntry{{Type: "hash_commitment", Alg: "sha-256", Path: ssc, Encoding: "base64url"}},
					ToIssuer: []openid4vci.AuxiliaryDataEntry{{Type: "hash_commitment", Alg: "sha-256", Path: psc, Encoding: "hex"}},
				},
			}}},
			APIGW: &model.APIGW{DataSources: model.DataSources{Presentation: model.PresentationConfig{
				Scopes: map[string]model.PresentationScope{"example": {From: map[string]model.PresentedCredential{
					"pid": {Derivations: []primitives.Derivation{{HashCommitment: &primitives.HashCommitmentArgs{
						Path: ssc,
						Opening: &primitives.OpeningArgs{HKDF: &primitives.HKDFOpeningArgs{
							SecretPath: secretPath, Inputs: []string{"personal_administrative_number"}, Bytes: 16,
						}},
					}}}},
				}}},
			}}},
		}
	}
	meta := func(c *model.Cfg) *model.CredentialMetadata { return c.Common.CredentialMetadata["example"] }

	cfg := base()
	require.NoError(t, checkAuxiliaryData(cfg, "apigw"))
	deriveAuxiliaryDataRequired(cfg)
	assert.True(t, meta(cfg).AuxiliaryData.ToIssuer[0].Required, "psc is mandatory in the VCTM")

	for name, tc := range map[string]struct {
		mutate func(*model.Cfg)
		want   string
	}{
		"a path the VCTM does not declare": {func(c *model.Cfg) {
			meta(c).AuxiliaryData.ToIssuer[0].Path = []string{"commitments", "other"}
		}, "the VCTM declares no claim"},
		"a claim the holder cannot withhold": {func(c *model.Cfg) {
			meta(c).VCTM.Claims[1].SD = "allowed"
		}, `needs sd "always"`},
		"a claim declared beneath the commitment": {func(c *model.Cfg) {
			meta(c).VCTM.Claims = append(meta(c).VCTM.Claims, claim("always", false, "commitments", "psc", "x"))
		}, "declares a claim beneath"},
		"a claim the builder writes": {func(c *model.Cfg) {
			meta(c).AuxiliaryData.ToIssuer[0].Path = []string{"cnf"}
		}, `the SD-JWT builder writes "cnf"`},
		"a disclosure member": {func(c *model.Cfg) {
			meta(c).AuxiliaryData.ToIssuer[0].Path = []string{"commitments", "_sd"}
		}, `"_sd" names no claim`},
		"a format without a commitment carrier": {func(c *model.Cfg) {
			meta(c).Format = "ldp_vc"
		}, "auxiliary data is implemented for"},
		"an entry without an encoding": {func(c *model.Cfg) {
			meta(c).AuxiliaryData.ToIssuer[0].Encoding = ""
		}, "the entry needs an encoding"},
		"an unknown encoding": {func(c *model.Cfg) {
			meta(c).AuxiliaryData.ToIssuer[0].Encoding = "base32"
		}, `encoding "base32" is none of`},
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

// sdjwtBuilderClaims covers every claim the SD-JWT builder assigns at the
// payload root. Derived from the builder's source: a commitment at a claim
// it assigns is replaced, and nothing reports it.
func TestSDJWTBuilderClaimsCoverTheBuilder(t *testing.T) {
	const builder = "../sdjwtvc/methods.go"
	file, err := parser.ParseFile(token.NewFileSet(), builder, nil, 0)
	require.NoError(t, err, "the SD-JWT builder must be parseable at %s; if it moved, point this test at it", builder)

	roots := map[string]bool{"body": true, "data": true, "current": true}
	assigned := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, lhs := range assign.Lhs {
			index, ok := lhs.(*ast.IndexExpr)
			if !ok {
				continue
			}
			ident, ok := index.X.(*ast.Ident)
			lit, isLit := index.Index.(*ast.BasicLit)
			if ok && roots[ident.Name] && isLit && lit.Kind == token.STRING {
				assigned[lit.Value[1:len(lit.Value)-1]] = true
			}
		}
		return true
	})
	require.NotEmpty(t, assigned, "no root assignments found; this check would pass vacuously")
	for name := range assigned {
		assert.Contains(t, sdjwtBuilderClaims, name, "the SD-JWT builder assigns %q at the payload root", name)
	}
}
