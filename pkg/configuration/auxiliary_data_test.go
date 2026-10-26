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
	encryption := model.CredentialEncryption{Keys: []model.CredentialEncryptionKey{{PrivateKeyPath: p256KeyPath(t)}}}

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
			APIGW: &model.APIGW{
				IssuerMetadata: model.IssuerMetadata{CredentialEncryption: encryption},
				DataSources: model.DataSources{Presentation: model.PresentationConfig{
					Scopes: map[string]model.PresentationScope{"nym_auth": {From: map[string]model.PresentedCredential{
						"pid": {Derivations: []primitives.Derivation{{HashCommitment: &primitives.HashCommitmentArgs{
							Path: ssc,
							Opening: primitives.OpeningArgs{HKDF: &primitives.HKDFOpeningArgs{
								SecretPath: secretPath, Inputs: []string{"personal_administrative_number"}, Bytes: 16,
							}},
						}}}},
					}}},
				}},
			},
		}
	}
	entry := func(c *model.Cfg) *openid4vci.AuxiliaryDataEntry {
		return &c.Common.CredentialMetadata["nym_auth"].AuxiliaryData.ToWallet[0]
	}
	derivation := func(c *model.Cfg) *primitives.HashCommitmentArgs {
		return c.APIGW.DataSources.Presentation.Scopes["nym_auth"].From["pid"].Derivations[0].HashCommitment
	}

	require.NoError(t, checkAuxiliaryData(base(), "apigw"))

	t.Run("a tstr element holds an encoded commitment", func(t *testing.T) {
		cfg := base()
		cfg.Common.CredentialMetadata["nym_auth"].MDDL.Claims[ssc[0]]["text"] = mdoc.ClaimMetadata{ValueType: "tstr"}
		entry(cfg).Path, entry(cfg).Encoding = []string{ssc[0], "text"}, "hex"
		derivation(cfg).Path = []string{ssc[0], "text"}
		require.NoError(t, checkAuxiliaryData(cfg, "apigw"))
	})

	claimOpening := func(c *model.Cfg, claim string) {
		derivation(c).Opening = primitives.OpeningArgs{Claim: &primitives.ClaimOpeningArgs{Input: claim}}
	}
	t.Run("a claim opening whose claim the credential withholds", func(t *testing.T) {
		cfg := base()
		claimOpening(cfg, "nym_auth_opening")
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
		"to_wallet without a credential encryption key": {func(c *model.Cfg) {
			c.APIGW.IssuerMetadata.CredentialEncryption = model.CredentialEncryption{}
		}, "needs a key under apigw.issuer_metadata.credential_encryption.keys"},
		"a derivation for a path outside to_wallet": {func(c *model.Cfg) {
			derivation(c).Path = []string{ssc[0], "birth_date"}
		}, "is no to_wallet entry"},
		"an unreadable secret": {func(c *model.Cfg) {
			derivation(c).Opening.HKDF.SecretPath = filepath.Join(t.TempDir(), "absent")
		}, "opening: hkdf: the opening secret"},
		"an opening without a length": {func(c *model.Cfg) {
			derivation(c).Opening.HKDF.Bytes = 0
		}, "an opening has 16 to 64 bytes, got 0"},
		"an opening with two generators": {func(c *model.Cfg) {
			derivation(c).Opening.Random = &primitives.RandomOpeningArgs{Bytes: 16}
		}, "exactly one of hkdf, hmac, random and claim"},
		"an hmac opening longer than the HMAC": {func(c *model.Cfg) {
			derivation(c).Opening = primitives.OpeningArgs{HMAC: &primitives.HMACOpeningArgs{
				SecretPath: secretPath, Inputs: []string{"personal_administrative_number"}, Bytes: 33,
			}}
		}, "hmac: an opening has 16 to 32 bytes, got 33"},
		"a claim opening whose claim the MDDL declares": {func(c *model.Cfg) {
			claimOpening(c, "birth_date")
		}, `the credential carries claim "birth_date": the MDDL declares element "birth_date"`},
		"a claim opening whose claim another derivation reads": {func(c *model.Cfg) {
			claimOpening(c, "nym_auth_opening")
			pid := c.APIGW.DataSources.Presentation.Scopes["nym_auth"].From["pid"]
			pid.Derivations = append(pid.Derivations, primitives.Derivation{Copy: &primitives.CopyArgs{Input: "nym_auth_opening", Output: "copied"}})
			c.APIGW.DataSources.Presentation.Scopes["nym_auth"].From["pid"] = pid
		}, `derivations[1] reads claim "nym_auth_opening"`},
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
	encryption := model.CredentialEncryption{Keys: []model.CredentialEncryptionKey{{PrivateKeyPath: p256KeyPath(t)}}}
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
			APIGW: &model.APIGW{
				IssuerMetadata: model.IssuerMetadata{CredentialEncryption: encryption},
				DataSources: model.DataSources{Presentation: model.PresentationConfig{
					Scopes: map[string]model.PresentationScope{"example": {From: map[string]model.PresentedCredential{
						"pid": {Derivations: []primitives.Derivation{{HashCommitment: &primitives.HashCommitmentArgs{
							Path: ssc,
							Opening: primitives.OpeningArgs{HKDF: &primitives.HKDFOpeningArgs{
								SecretPath: secretPath, Inputs: []string{"personal_administrative_number"}, Bytes: 16,
							}},
						}}}},
					}}},
				}},
			},
		}
	}
	meta := func(c *model.Cfg) *model.CredentialMetadata { return c.Common.CredentialMetadata["example"] }
	claimOpening := func(claim string) []primitives.Derivation {
		return []primitives.Derivation{{HashCommitment: &primitives.HashCommitmentArgs{
			Path:    ssc,
			Opening: primitives.OpeningArgs{Claim: &primitives.ClaimOpeningArgs{Input: claim}},
		}}}
	}

	cfg := base()
	require.NoError(t, checkAuxiliaryData(cfg, "apigw"))
	deriveAuxiliaryDataRequired(cfg)
	assert.True(t, meta(cfg).AuxiliaryData.ToIssuer[0].Required, "psc is mandatory in the VCTM")

	cfg = base()
	cfg.APIGW.DataSources.Presentation.Scopes["example"].From["pid"] = model.PresentedCredential{Derivations: claimOpening("nym_auth_opening")}
	require.NoError(t, checkAuxiliaryData(cfg, "apigw"), "a presentation's claim the VCTM leaves out stays out of the credential")

	for name, tc := range map[string]struct {
		mutate func(*model.Cfg)
		want   string
	}{
		"a path the VCTM does not declare": {func(c *model.Cfg) {
			meta(c).AuxiliaryData.ToIssuer[0].Path = []string{"commitments", "other"}
		}, "the VCTM declares no claim"},
		"an empty path": {func(c *model.Cfg) {
			meta(c).AuxiliaryData.ToIssuer[0].Path = nil
		}, "the path is empty"},
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
		"a claim opening whose claim the VCTM declares": {func(c *model.Cfg) {
			c.APIGW.DataSources.Presentation.Scopes["example"].From["pid"] = model.PresentedCredential{Derivations: claimOpening("given_name")}
		}, `the credential carries claim "given_name": the VCTM declares it`},
		"a claim opening on an SD-JWT VC from the datastore": {func(c *model.Cfg) {
			c.APIGW.DataSources.Presentation = model.PresentationConfig{}
			c.APIGW.DataSources.Datastore.Scopes = map[string]model.DatastoreScope{"example": {Derivations: claimOpening("nym_auth_opening")}}
		}, "an SD-JWT VC from the datastore source carries its whole document"},
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
