package apiv1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	"github.com/SUNET/vc/pkg/helpers"
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
	derivations := []primitives.Derivation{
		{HashCommitment: &primitives.HashCommitmentArgs{
			Path:    ssc,
			Opening: &primitives.OpeningArgs{HKDF: &primitives.HKDFOpeningArgs{SecretPath: secretPath, Inputs: inputs, Bytes: 16}},
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
		"the entry carries only type, alg, path and commitment": {"nym_auth", with(func(e *openid4vci.AuxiliaryDataEntry) {
			e.Encoding = "hex"
		})},
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

	query := func(path []string, key ...KeyValue) UniqueCommitmentQuery {
		return UniqueCommitmentQuery{Scope: "nym_auth", Path: path, Key: key}
	}
	reset := func(path []string, key ...KeyValue) error {
		return c.ResetUniqueCommitment(t.Context(), &ResetUniqueCommitmentRequest{UniqueCommitmentQuery: query(path, key...), EvidenceRef: "case-1"}, "operator")
	}
	identifiers := func(values ...string) KeyValue { return KeyValue{Path: ssc, Inputs: values} }
	q := query(psc, identifiers("SE", "pan-200"))
	found, err := c.LookupUniqueCommitment(t.Context(), &q)
	require.NoError(t, err, "the lookup finds the person's commitment")
	assert.False(t, found.RecordedAt.IsZero())
	require.NoError(t, reset(psc, identifiers("SE", "pan-200")))
	_, err = c.LookupUniqueCommitment(t.Context(), &q)
	var gone *helpers.Error
	require.ErrorAs(t, err, &gone, "after the reset nothing is on record")
	assert.Equal(t, http.StatusNotFound, gone.HTTPStatus)
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
	type issuance struct {
		ssc, birth string
		psc        byte
		accepted   bool
	}
	type credential struct {
		format, encoding string
		psc, ssc, birth  []string
		document         string
	}
	mdoc := credential{"mso_mdoc", "", []string{ns, "psc"}, []string{ns, "ssc"}, []string{ns, "birth_date"}, `{"ssc":%q,"birth_date":%q}`}
	sdjwt := credential{"dc+sd-jwt", "base64url", []string{"commitments", "psc"}, []string{"commitments", "ssc"}, []string{"birth_date"}, `{"commitments":{"ssc":%q},"birth_date":%q}`}
	for name, tc := range map[string]struct {
		credential credential
		key        func(credential) [][]string
		issuances  []issuance
	}{
		"global": {mdoc, func(credential) [][]string { return [][]string{} },
			[]issuance{{"A", "2011-06-15", 1, true}, {"B", "2011-06-15", 1, true}, {"B", "2011-06-15", 2, false}}},
		"per ssc": {mdoc, func(c credential) [][]string { return [][]string{c.ssc} },
			[]issuance{{"A", "2011-06-15", 1, true}, {"B", "2011-06-15", 2, true}, {"A", "2011-06-15", 2, false}}},
		"per ssc and birth_date": {mdoc, func(c credential) [][]string { return [][]string{c.ssc, c.birth} },
			[]issuance{{"A", "2011-06-15", 1, true}, {"A", "2012-01-01", 2, true}, {"A", "2011-06-15", 2, false}}},
		"per a nested SD-JWT claim": {sdjwt, func(c credential) [][]string { return [][]string{c.ssc} },
			[]issuance{{"A", "2011-06-15", 1, true}, {"B", "2011-06-15", 2, true}, {"A", "2011-06-15", 2, false}}},
	} {
		cred := tc.credential
		c := &Client{log: logger.NewSimple("test"), uniqueCommitmentStore: memoryCommitments{}, cfg: &model.Cfg{Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{
			"nym_auth": {Format: cred.format, AuxiliaryData: &openid4vci.AuxiliaryDataSupported{
				ToIssuer: []openid4vci.AuxiliaryDataEntry{{Type: "hash_commitment", Alg: "sha-256", Path: cred.psc, Encoding: cred.encoding}},
			}},
		}}}}
		derivations := []primitives.Derivation{{HashCommitment: &primitives.HashCommitmentArgs{Path: cred.psc, Unique: &primitives.UniqueArgs{Key: tc.key(cred)}}}}
		for i, is := range tc.issuances {
			document := fmt.Appendf(nil, cred.document, is.ssc, is.birth)
			entries := []openid4vci.AuxiliaryDataEntry{{Type: "hash_commitment", Alg: "sha-256", Path: cred.psc,
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
type memoryCommitments map[string]memoryRecord

type memoryRecord struct {
	commitment []byte
	at         time.Time
}

func (m memoryCommitments) Accept(_ context.Context, key db.UniqueCommitmentKey, commitment []byte, at time.Time) ([]byte, error) {
	k := fmt.Sprint(key)
	if _, ok := m[k]; !ok {
		m[k] = memoryRecord{commitment: commitment, at: at}
	}
	return m[k].commitment, nil
}

func (m memoryCommitments) Find(_ context.Context, key db.UniqueCommitmentKey) (db.UniqueCommitmentRecord, error) {
	record, ok := m[fmt.Sprint(key)]
	if !ok {
		return db.UniqueCommitmentRecord{}, db.ErrNoDocuments
	}
	return db.UniqueCommitmentRecord{AcceptedAt: record.at}, nil
}

func (m memoryCommitments) Reset(_ context.Context, key db.UniqueCommitmentKey, _ db.UniqueCommitmentReset) error {
	k := fmt.Sprint(key)
	if _, ok := m[k]; !ok {
		return db.ErrNoDocuments
	}
	delete(m, k)
	return nil
}

// An SD-JWT VC carries each commitment at its claims path, in the
// encoding its entry configures, and the SD-JWT builder turns it into a
// disclosure the holder can withhold. An operator's identifiers name the
// key the credential carries.
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
	derivations := []primitives.Derivation{
		{HashCommitment: &primitives.HashCommitmentArgs{
			Path:    ssc,
			Opening: &primitives.OpeningArgs{HKDF: &primitives.HKDFOpeningArgs{SecretPath: secretPath, Inputs: []string{"personal_administrative_number"}, Bytes: 16}},
		}},
		{HashCommitment: &primitives.HashCommitmentArgs{Path: psc, Unique: &primitives.UniqueArgs{Key: [][]string{ssc}}}},
	}
	c.cfg.APIGW = &model.APIGW{DataSources: model.DataSources{Presentation: model.PresentationConfig{
		Scopes: map[string]model.PresentationScope{"example": {From: map[string]model.PresentedCredential{"pid": {Derivations: derivations}}}},
	}}}
	c.uniqueCommitmentStore = memoryCommitments{}
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
	q := UniqueCommitmentQuery{Scope: "example", Path: psc, Key: []KeyValue{{Path: ssc, Inputs: []string{"pan-200"}}}}
	_, err = c.LookupUniqueCommitment(t.Context(), &q)
	require.NoError(t, err, "the identifiers derive ssc in its entry's encoding")

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
