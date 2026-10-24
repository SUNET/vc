package apiv1

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/credential/primitives"
	"github.com/SUNET/vc/pkg/credential/seed"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"

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
	deriver, err := seed.NewDeriver(secret, 16)
	require.NoError(t, err)
	want, err := deriver.Seed(t.Context(), []string{"SE", "pan-200"}, "")
	require.NoError(t, err)
	assert.Equal(t, want, opening, "the opening is the hkdf seed of the identifiers")
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
}
