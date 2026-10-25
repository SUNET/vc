package apiv1

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/credential/primitives"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// With nym_auth as the example: the issuer derives ssc's opening from the
// presented identifiers and writes its SHA-256, and writes psc as the
// wallet sends it.
func TestAuxiliaryData(t *testing.T) {
	schema := &mdoc.MDDLSchema{Claims: map[string]mdoc.NamespaceClaims{"eu.europa.ec.eudi.nym_auth.1": {
		"birth_date": {Mandatory: true, ValueType: "full-date"},
		"ssc":        {Mandatory: true, ValueType: "bstr"},
		"psc":        {ValueType: "bstr"},
	}}}

	secret := []byte(strings.Repeat("s", 32))
	secretPath := filepath.Join(t.TempDir(), "nym_auth_seed.key")
	require.NoError(t, os.WriteFile(secretPath, []byte(base64.RawURLEncoding.EncodeToString(secret)+"\n"), 0o600))

	ssc := []string{"eu.europa.ec.eudi.nym_auth.1", "ssc"}
	psc := []string{"eu.europa.ec.eudi.nym_auth.1", "psc"}
	inputs := []string{"issuing_country", "personal_administrative_number"}
	c := &Client{
		log: logger.NewSimple("test"),
		cfg: &model.Cfg{Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{
			"nym_auth": {
				Format: "mso_mdoc",
				MDDL:   schema,
				AuxiliaryData: &openid4vci.AuxiliaryDataSupported{
					ToWallet: []openid4vci.AuxiliaryDataEntry{{Type: "hash_commitment", Alg: "sha-256", Path: ssc}},
					ToIssuer: []openid4vci.AuxiliaryDataEntry{{Type: "hash_commitment", Alg: "sha-256", Path: psc}},
				},
			},
			"psc_required": {
				Format: "mso_mdoc",
				MDDL:   schema,
				AuxiliaryData: &openid4vci.AuxiliaryDataSupported{
					ToIssuer: []openid4vci.AuxiliaryDataEntry{{Type: "hash_commitment", Alg: "sha-256", Path: psc, Required: true}},
				},
			},
			"pid": {Format: "dc+sd-jwt"},
		}}},
	}
	derivations := []primitives.Derivation{{HashCommitment: &primitives.HashCommitmentArgs{
		Path:    ssc,
		Opening: primitives.OpeningArgs{HKDF: &primitives.HKDFOpeningArgs{SecretPath: secretPath, Inputs: inputs, Bytes: 16}},
	}}}

	walletPSC := sha256.Sum256([]byte("the wallet's private seed"))
	fromWallet := []openid4vci.AuxiliaryDataEntry{{
		Type: "hash_commitment", Alg: "sha-256", Path: psc, Commitment: base64.RawURLEncoding.EncodeToString(walletPSC[:]),
	}}
	document := []byte(`{"birth_date":"2011-06-15"}`)
	issue := func(pan string, entries []openid4vci.AuxiliaryDataEntry) (map[string]any, []openid4vci.AuxiliaryDataEntry) {
		source := map[string]any{"issuing_country": "SE", "personal_administrative_number": pan}
		out, toWallet, err := c.applyAuxiliaryData(t.Context(), "nym_auth", derivations, source, document, entries)
		require.NoError(t, err)
		var doc map[string]any
		require.NoError(t, json.Unmarshal(out, &doc))
		return doc, toWallet
	}

	doc, toWallet := issue("pan-200", fromWallet)
	require.Len(t, toWallet, 1)
	assert.Equal(t, ssc, toWallet[0].Path)
	opening, err := base64.RawURLEncoding.DecodeString(toWallet[0].Opening)
	require.NoError(t, err)
	commitment := sha256.Sum256(opening)
	assert.Equal(t, base64.StdEncoding.EncodeToString(commitment[:]), doc["ssc"], "the opening opens ssc")
	assert.Equal(t, base64.StdEncoding.EncodeToString(walletPSC[:]), doc["psc"])

	again, _ := issue("pan-200", nil)
	assert.Equal(t, doc["ssc"], again["ssc"], "one person, one opening")
	assert.NotContains(t, again, "psc")
	other, _ := issue("pan-201", nil)
	assert.NotEqual(t, doc["ssc"], other["ssc"], "two people, two openings")

	var vciErr *openid4vci.Error
	with := func(change func(*openid4vci.AuxiliaryDataEntry)) []openid4vci.AuxiliaryDataEntry {
		entry := fromWallet[0]
		change(&entry)
		return []openid4vci.AuxiliaryDataEntry{entry}
	}
	for rule, request := range map[string]struct {
		scope   string
		entries []openid4vci.AuxiliaryDataEntry
	}{
		"the commitment is a sha-256 hash": {"nym_auth", with(func(e *openid4vci.AuxiliaryDataEntry) {
			e.Commitment = base64.RawURLEncoding.EncodeToString(walletPSC[:31])
		})},
		"the path is a to_issuer entry": {"nym_auth", with(func(e *openid4vci.AuxiliaryDataEntry) {
			e.Path = []string{"eu.europa.ec.eudi.nym_auth.1", "birth_date"}
		})},
		"the alg is the to_issuer entry's":  {"nym_auth", with(func(e *openid4vci.AuxiliaryDataEntry) { e.Alg = "sha-384" })},
		"the credential takes the entries":  {"pid", fromWallet},
		"the wallet sends a required entry": {"psc_required", nil},
	} {
		source := map[string]any{"issuing_country": "SE", "personal_administrative_number": "pan-200"}
		_, _, err = c.applyAuxiliaryData(t.Context(), request.scope, derivations, source, document, request.entries)
		require.ErrorAs(t, err, &vciErr, rule)
		assert.Equal(t, openid4vci.ErrInvalidProof, vciErr.Err, rule)
	}

	proof := func(payload string) openid4vci.ProofJWTToken {
		return openid4vci.ProofJWTToken("e30." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".c2ln")
	}
	_, err = walletAuxiliaryData(&openid4vci.CredentialRequest{Proofs: &openid4vci.Proofs{JWT: []openid4vci.ProofJWTToken{
		proof(`{"auxiliary_data":[{"type":"hash_commitment","alg":"sha-256","path":["eu.europa.ec.eudi.nym_auth.1","psc"],"commitment":"JhQM6yeuK84BoGVVSxbLL9HjjeiBERnWHEZSIIMqwd0"}]}`),
		proof(`{}`),
	}}})
	require.ErrorAs(t, err, &vciErr, "key proofs that disagree are refused")
	assert.Equal(t, openid4vci.ErrInvalidProof, vciErr.Err)

	_, err = walletAuxiliaryData(&openid4vci.CredentialRequest{Proofs: &openid4vci.Proofs{JWT: []openid4vci.ProofJWTToken{
		proof(`{"auxiliary_data":[{"type":"hash_commitment","alg":"sha-256","path":["eu.europa.ec.eudi.nym_auth.1","psc"],"commitment":"JhQM6yeuK84BoGVVSxbLL9HjjeiBERnWHEZSIIMqwd0","required":false}]}`),
	}}})
	require.ErrorAs(t, err, &vciErr, "an entry from the wallet carries only type, alg, path and commitment")
	assert.Equal(t, openid4vci.ErrInvalidProof, vciErr.Err)
}

// An SD-JWT VC carries each commitment at its claims path, in the
// encoding its entry configures, and the SD-JWT builder turns it into a
// disclosure the holder can withhold.
func TestAuxiliaryDataSDJWT(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "secret.key")
	require.NoError(t, os.WriteFile(secretPath, []byte(base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))), 0o600))
	ssc, psc := []string{"commitments", "ssc"}, []string{"commitments", "psc"}
	always := func(path []string) sdjwtvc.Claim {
		segments := make([]*string, len(path))
		for i := range path {
			segments[i] = &path[i]
		}
		return sdjwtvc.Claim{Path: segments, SD: "always"}
	}
	vctm := &sdjwtvc.VCTM{VCT: "https://example.org/example", Claims: []sdjwtvc.Claim{always(ssc), always(psc)}}
	c := &Client{log: logger.NewSimple("test"), cfg: &model.Cfg{Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{
		"example": {Format: "dc+sd-jwt", VCTM: vctm, AuxiliaryData: &openid4vci.AuxiliaryDataSupported{
			ToWallet: []openid4vci.AuxiliaryDataEntry{{Type: "hash_commitment", Alg: "sha-256", Path: ssc, Encoding: "base64url"}},
			ToIssuer: []openid4vci.AuxiliaryDataEntry{{Type: "hash_commitment", Alg: "sha-256", Path: psc, Encoding: "hex"}},
		}},
	}}}}
	derivations := []primitives.Derivation{{HashCommitment: &primitives.HashCommitmentArgs{
		Path:    ssc,
		Opening: primitives.OpeningArgs{HKDF: &primitives.HKDFOpeningArgs{SecretPath: secretPath, Inputs: []string{"personal_administrative_number"}, Bytes: 16}},
	}}}
	walletPSC := sha256.Sum256([]byte("the wallet's private seed"))
	fromWallet := []openid4vci.AuxiliaryDataEntry{{
		Type: "hash_commitment", Alg: "sha-256", Path: psc, Commitment: base64.RawURLEncoding.EncodeToString(walletPSC[:]),
	}}

	out, toWallet, err := c.applyAuxiliaryData(t.Context(), "example", derivations,
		map[string]any{"personal_administrative_number": "pan-200"}, []byte(`{"given_name":"Alex"}`), fromWallet)
	require.NoError(t, err)
	require.Len(t, toWallet, 1)
	assert.Equal(t, openid4vci.AuxiliaryDataEntry{Type: "hash_commitment", Alg: "sha-256", Path: ssc, Opening: toWallet[0].Opening},
		toWallet[0], "a response entry carries type, alg, path and opening")
	opening, err := base64.RawURLEncoding.DecodeString(toWallet[0].Opening)
	require.NoError(t, err)
	issued := sha256.Sum256(opening)
	want := map[string]any{
		"ssc": base64.RawURLEncoding.EncodeToString(issued[:]),
		"psc": hex.EncodeToString(walletPSC[:]),
	}
	var doc map[string]any
	require.NoError(t, json.Unmarshal(out, &doc))
	assert.Equal(t, want, doc["commitments"], "each commitment is at its claims path, in its entry's encoding")

	payload, disclosures, err := sdjwtvc.New().MakeCredential(sha256.New(), doc, vctm, 0)
	require.NoError(t, err)
	disclosed := map[string]any{}
	for _, d := range disclosures {
		raw, err := base64.RawURLEncoding.DecodeString(d)
		require.NoError(t, err)
		var parts []any
		require.NoError(t, json.Unmarshal(raw, &parts))
		if len(parts) == 3 {
			disclosed[parts[1].(string)] = parts[2]
		}
	}
	assert.Equal(t, want, disclosed, "the holder can withhold each commitment")
	assert.NotContains(t, payload["commitments"], "ssc")
	assert.NotContains(t, payload["commitments"], "psc")
}
