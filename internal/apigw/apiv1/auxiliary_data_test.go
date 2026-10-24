package apiv1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SUNET/vc/internal/apigw/db"
	"github.com/SUNET/vc/pkg/credential/primitives"
	"github.com/SUNET/vc/pkg/credential/seed"
	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nym_auth as the demo configures it: the opening is the seed
// pkg/credential/seed derives from the presented identifiers, the issued
// ssc is its SHA-256, and psc is the wallet's commitment when the wallet
// sends one.
func TestNymAuthAuxiliaryData(t *testing.T) {
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
	derivations := []primitives.Derivation{
		{HashCommitment: &primitives.HashCommitmentArgs{
			Path:    ssc,
			Opening: &primitives.OpeningArgs{HKDF: &primitives.HKDFOpeningArgs{SecretPath: secretPath, Inputs: inputs}},
		}},
		{HashCommitment: &primitives.HashCommitmentArgs{Path: psc, Unique: &primitives.UniqueArgs{Key: [][]string{ssc}}}},
	}
	c.cfg.APIGW = &model.APIGW{DataSources: model.DataSources{Presentation: model.PresentationConfig{
		Scopes: map[string]model.PresentationScope{"nym_auth": {From: map[string]model.PresentedCredential{"pid": {Derivations: derivations}}}},
	}}}
	c.uniqueCommitmentStore = memoryCommitments{}

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
	deriver, err := seed.NewDeriver(secret, seed.DefaultSeedBytes)
	require.NoError(t, err)
	want, err := deriver.Seed(t.Context(), []string{"SE", "pan-200"}, "")
	require.NoError(t, err)
	assert.Equal(t, want, opening, "the opening is the seed seed_recover reproduces")
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

	// One commitment per subject: the same person's new wallet is refused,
	// another person is accepted, and an operator's reset lets the new
	// commitment in.
	newPSC := sha256.Sum256([]byte("a new wallet's private seed"))
	newWallet := with(func(e *openid4vci.AuxiliaryDataEntry) { e.Commitment = base64.RawURLEncoding.EncodeToString(newPSC[:]) })
	person := func(pan string) map[string]any {
		return map[string]any{"issuing_country": "SE", "personal_administrative_number": pan}
	}
	_, _, err = c.applyAuxiliaryData(t.Context(), "nym_auth", derivations, person("pan-200"), document, newWallet)
	require.ErrorAs(t, err, &vciErr)
	assert.Equal(t, openid4vci.ErrAuxiliaryDataConflict, vciErr.Err)
	_, _, err = c.applyAuxiliaryData(t.Context(), "nym_auth", derivations, person("pan-201"), document, newWallet)
	require.NoError(t, err, "another person's commitment is their own")
	_, _, err = c.applyAuxiliaryData(t.Context(), "nym_auth", derivations[:1], person("pan-200"), document, newWallet)
	require.NoError(t, err, "a commitment without unique is accepted")

	reset := func(path []string, key ...KeyValue) error {
		return c.ResetUniqueCommitment(t.Context(), &ResetUniqueCommitmentRequest{Scope: "nym_auth", Path: path, Key: key, EvidenceRef: "case-1"}, "operator")
	}
	identifiers := func(values ...string) KeyValue { return KeyValue{Path: ssc, Inputs: values} }
	require.NoError(t, reset(psc, identifiers("SE", "pan-200")))
	doc, _ = issue("pan-200", newWallet)
	assert.Equal(t, base64.StdEncoding.EncodeToString(newPSC[:]), doc["psc"], "after the reset the new commitment is issued")
	ssc200 := doc["ssc"].(string)
	require.NoError(t, reset(psc, KeyValue{Path: ssc, Value: &ssc200}), "the value the credential carries names the same key")

	for rule, refusal := range map[string]struct {
		err    error
		status int
	}{
		"the entry is unique per the key": {reset(ssc, identifiers("SE", "pan-200")), http.StatusBadRequest},
		"the inputs fit an hkdf opening":  {reset(psc, identifiers("SE")), http.StatusBadRequest},
		"a commitment is on record":       {reset(psc, identifiers("SE", "pan-999")), http.StatusNotFound},
	} {
		var detailed *helpers.Error
		require.ErrorAs(t, refusal.err, &detailed, rule)
		assert.Equal(t, refusal.status, detailed.HTTPStatus, rule)
	}
}

// The key decides which issuances share a record: an empty key makes one
// commitment for the entry, a composite key one per combination.
func TestUniqueCommitmentKey(t *testing.T) {
	ns := "eu.europa.ec.eudi.nym_auth.1"
	psc, ssc, birth := []string{ns, "psc"}, []string{ns, "ssc"}, []string{ns, "birth_date"}
	c := &Client{log: logger.NewSimple("test"), cfg: &model.Cfg{Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{
		"nym_auth": {AuxiliaryData: &openid4vci.AuxiliaryDataSupported{
			ToIssuer: []openid4vci.AuxiliaryDataEntry{{Type: "hash_commitment", Alg: "sha-256", Path: psc}},
		}},
	}}}}
	type issuance struct {
		ssc, birth string
		psc        byte
		accepted   bool
	}
	for name, tc := range map[string]struct {
		key       [][]string
		issuances []issuance
	}{
		"global":  {[][]string{}, []issuance{{"A", "2011-06-15", 1, true}, {"B", "2011-06-15", 1, true}, {"B", "2011-06-15", 2, false}}},
		"per ssc": {[][]string{ssc}, []issuance{{"A", "2011-06-15", 1, true}, {"B", "2011-06-15", 2, true}, {"A", "2011-06-15", 2, false}}},
		"per ssc and birth_date": {[][]string{ssc, birth}, []issuance{
			{"A", "2011-06-15", 1, true}, {"A", "2012-01-01", 2, true}, {"A", "2011-06-15", 2, false},
		}},
	} {
		c.uniqueCommitmentStore = memoryCommitments{}
		derivations := []primitives.Derivation{{HashCommitment: &primitives.HashCommitmentArgs{Path: psc, Unique: &primitives.UniqueArgs{Key: tc.key}}}}
		for i, is := range tc.issuances {
			document := fmt.Appendf(nil, `{"ssc":%q,"birth_date":%q}`, is.ssc, is.birth)
			entries := []openid4vci.AuxiliaryDataEntry{{Type: "hash_commitment", Alg: "sha-256", Path: psc,
				Commitment: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{is.psc}, sha256.Size))}}
			_, _, err := c.applyAuxiliaryData(t.Context(), "nym_auth", derivations, nil, document, entries)
			if is.accepted {
				assert.NoError(t, err, "%s: issuance %d", name, i)
				continue
			}
			var vciErr *openid4vci.Error
			require.ErrorAs(t, err, &vciErr, "%s: issuance %d", name, i)
			assert.Equal(t, openid4vci.ErrAuxiliaryDataConflict, vciErr.Err, "%s: issuance %d", name, i)
		}
	}
}

// memoryCommitments is a UniqueCommitmentStore over a map.
type memoryCommitments map[string][]byte

func (m memoryCommitments) Accept(_ context.Context, key db.UniqueCommitmentKey, commitment []byte, _ time.Time) ([]byte, error) {
	k := fmt.Sprint(key)
	if _, ok := m[k]; !ok {
		m[k] = commitment
	}
	return m[k], nil
}

func (m memoryCommitments) Reset(_ context.Context, key db.UniqueCommitmentKey, _ db.UniqueCommitmentReset) error {
	k := fmt.Sprint(key)
	if _, ok := m[k]; !ok {
		return db.ErrNoDocuments
	}
	delete(m, k)
	return nil
}
