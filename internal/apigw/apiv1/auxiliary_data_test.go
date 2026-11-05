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
	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/credential/primitives"
	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// nymAuthClient serves the nym_auth example as an mso_mdoc credential, and
// returns the derivations of its pid source. The issuer derives ssc's
// opening with hkdf from the presented identifiers, and accepts one psc per
// ssc. psc_required requires psc, and pid takes no auxiliary_data.
func nymAuthClient(t *testing.T) (*Client, []primitives.Derivation) {
	ns := "eu.europa.ec.eudi.nym_auth.1"
	ssc, psc := []string{ns, "ssc"}, []string{ns, "psc"}
	schema := &mdoc.MDDLSchema{Claims: map[string]mdoc.NamespaceClaims{ns: {
		"birth_date": {Mandatory: true, ValueType: "full-date"},
		"ssc":        {Mandatory: true, ValueType: "bstr"},
		"psc":        {ValueType: "bstr"},
	}}}
	secretPath := filepath.Join(t.TempDir(), "nym_auth_seed.key")
	require.NoError(t, os.WriteFile(secretPath, []byte(base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))+"\n"), 0o600))
	derivations := []primitives.Derivation{
		{HashCommitment: &primitives.HashCommitmentArgs{
			Path:    ssc,
			Opening: &primitives.OpeningArgs{HKDF: &primitives.HKDFOpeningArgs{SecretPath: secretPath, Inputs: []string{"issuing_country", "personal_administrative_number"}, Bytes: 16}},
		}},
		{HashCommitment: &primitives.HashCommitmentArgs{Path: psc, Unique: &primitives.UniqueArgs{Key: [][]string{ssc}}}},
	}
	c := &Client{
		log:                   logger.NewSimple("test"),
		uniqueCommitmentStore: memoryCommitments{},
		cfg: &model.Cfg{
			Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{
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
			}},
			APIGW: &model.APIGW{DataSources: model.DataSources{Presentation: model.PresentationConfig{
				Scopes: map[string]model.PresentationScope{"nym_auth": {From: map[string]model.PresentedCredential{"pid": {Derivations: derivations}}}},
			}}},
		},
	}
	return c, derivations
}

// nymAuthSubject is the identifiers a presentation gives for the person
// with pan.
func nymAuthSubject(pan string) map[string]any {
	return map[string]any{"issuing_country": "SE", "personal_administrative_number": pan}
}

// issueAuxiliaryData admits scope's auxiliary_data for a request that asks
// for an encrypted response.
func issueAuxiliaryData(t *testing.T, c *Client, scope string, derivations []primitives.Derivation, sourceClaims map[string]any, documentData []byte, fromWallet []openid4vci.AuxiliaryDataEntry) (appliedAuxiliaryData, error) {
	return c.admitAuxiliaryData(t.Context(), scope, derivations, sourceClaims, documentData, fromWallet, true)
}

// With nym_auth as the example: the issuer derives ssc's opening from the
// presented identifiers and writes its SHA-256, and writes psc as the
// wallet sends it.
func TestAuxiliaryData(t *testing.T) {
	c, derivations := nymAuthClient(t)
	ssc := []string{"eu.europa.ec.eudi.nym_auth.1", "ssc"}
	psc := []string{"eu.europa.ec.eudi.nym_auth.1", "psc"}

	walletPSC := sha256.Sum256([]byte("the wallet's private seed"))
	fromWallet := []openid4vci.AuxiliaryDataEntry{{
		Type: "hash_commitment", Alg: "sha-256", Path: psc, Commitment: base64.RawURLEncoding.EncodeToString(walletPSC[:]),
	}}
	document := []byte(`{"birth_date":"2011-06-15"}`)
	issue := func(pan string, document []byte, entries []openid4vci.AuxiliaryDataEntry) (map[string]any, []openid4vci.AuxiliaryDataEntry) {
		applied, err := c.applyAuxiliaryData(t.Context(), "nym_auth", derivations, nymAuthSubject(pan), document, entries)
		require.NoError(t, err)
		var doc map[string]any
		require.NoError(t, json.Unmarshal(applied.documentData, &doc))
		return doc, applied.toWallet
	}

	doc, toWallet := issue("pan-200", document, fromWallet)
	require.Len(t, toWallet, 1)
	assert.Equal(t, ssc, toWallet[0].Path)
	opening, err := base64.RawURLEncoding.DecodeString(toWallet[0].Opening)
	require.NoError(t, err)
	commitment := sha256.Sum256(opening)
	assert.Equal(t, base64.StdEncoding.EncodeToString(commitment[:]), doc["ssc"], "the opening opens ssc")
	assert.Equal(t, base64.StdEncoding.EncodeToString(walletPSC[:]), doc["psc"])

	again, _ := issue("pan-200", document, nil)
	assert.Equal(t, doc["ssc"], again["ssc"], "one person, one opening")
	assert.NotContains(t, again, "psc")
	other, _ := issue("pan-201", document, nil)
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
		_, err = c.applyAuxiliaryData(t.Context(), request.scope, derivations, nymAuthSubject("pan-200"), document, request.entries)
		require.ErrorAs(t, err, &vciErr, rule)
		assert.Equal(t, openid4vci.ErrInvalidProof, vciErr.Err, rule)
	}

	// The issuer already holds a commitment at a to_issuer path: the same one
	// stands, a different one is auxiliary_data_conflict, and without the
	// wallet's entry the credential carries none.
	held := func(commitment string) []byte {
		return []byte(`{"birth_date":"2011-06-15","psc":"` + commitment + `"}`)
	}
	stored := base64.StdEncoding.EncodeToString(walletPSC[:])
	_, err = c.applyAuxiliaryData(t.Context(), "nym_auth", derivations, nymAuthSubject("pan-200"), held(stored), fromWallet)
	require.NoError(t, err, "the wallet sends the commitment the issuer holds")
	_, err = c.applyAuxiliaryData(t.Context(), "nym_auth", derivations, nymAuthSubject("pan-200"), held("AAAA"), fromWallet)
	require.ErrorAs(t, err, &vciErr, "the wallet sends another commitment")
	assert.Equal(t, openid4vci.ErrAuxiliaryDataConflict, vciErr.Err)
	unsent, _ := issue("pan-200", held(stored), nil)
	assert.NotContains(t, unsent, "psc", "the wallet sends no entry")

	// A to_wallet commitment is the issuer's own, so a conflict on one
	// denies the request.
	sscPerBirthDate := []primitives.Derivation{{HashCommitment: &primitives.HashCommitmentArgs{
		Path:    ssc,
		Opening: derivations[0].HashCommitment.Opening,
		Unique:  &primitives.UniqueArgs{Key: [][]string{{"eu.europa.ec.eudi.nym_auth.1", "birth_date"}}},
	}}}
	_, err = issueAuxiliaryData(t, c, "nym_auth", sscPerBirthDate, nymAuthSubject("pan-200"), document, nil)
	require.NoError(t, err)
	_, err = issueAuxiliaryData(t, c, "nym_auth", sscPerBirthDate, nymAuthSubject("pan-201"), document, nil)
	require.ErrorAs(t, err, &vciErr, "another person born the same day")
	assert.Equal(t, openid4vci.ErrCredentialRequestDenied, vciErr.Err)

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

// An operator names a subject by the identifiers ssc's opening derives
// from. They derive the key the subject's issuance recorded, so the
// operator's reset lets the subject's next wallet register its psc.
func TestUniqueCommitmentReset(t *testing.T) {
	c, derivations := nymAuthClient(t)
	ssc := []string{"eu.europa.ec.eudi.nym_auth.1", "ssc"}
	psc := []string{"eu.europa.ec.eudi.nym_auth.1", "psc"}
	document := []byte(`{"birth_date":"2011-06-15"}`)
	// wallet returns the psc claim of a wallet with seed, and its entry.
	wallet := func(seed string) (string, []openid4vci.AuxiliaryDataEntry) {
		commitment := sha256.Sum256([]byte(seed))
		return base64.StdEncoding.EncodeToString(commitment[:]), []openid4vci.AuxiliaryDataEntry{{
			Type: "hash_commitment", Alg: "sha-256", Path: psc, Commitment: base64.RawURLEncoding.EncodeToString(commitment[:]),
		}}
	}
	_, first := wallet("the first wallet's private seed")
	secondPSC, second := wallet("the second wallet's private seed")

	_, err := c.admitAuxiliaryData(t.Context(), "nym_auth", derivations, nymAuthSubject("pan-200"), document, second, false)
	var vciErr *openid4vci.Error
	require.ErrorAs(t, err, &vciErr, "an opening needs an encrypted response")
	assert.Equal(t, openid4vci.ErrInvalidEncryptionParameters, vciErr.Err)
	_, err = issueAuxiliaryData(t, c, "nym_auth", derivations, nymAuthSubject("pan-200"), document, first)
	require.NoError(t, err, "the refused request recorded nothing")
	_, err = issueAuxiliaryData(t, c, "nym_auth", derivations, nymAuthSubject("pan-200"), document, second)
	require.ErrorAs(t, err, &vciErr, "the record holds the first wallet's psc")
	assert.Equal(t, openid4vci.ErrAuxiliaryDataConflict, vciErr.Err)
	_, err = issueAuxiliaryData(t, c, "nym_auth", derivations[:1], nymAuthSubject("pan-200"), document, second)
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
	require.NoError(t, err, "the subject's identifiers find the record")
	assert.False(t, found.RecordedAt.IsZero())
	require.NoError(t, reset(psc, identifiers("SE", "pan-200")))
	_, err = c.LookupUniqueCommitment(t.Context(), &q)
	var gone *helpers.Error
	require.ErrorAs(t, err, &gone, "the reset removed the record")
	assert.Equal(t, http.StatusNotFound, gone.HTTPStatus)
	applied, err := issueAuxiliaryData(t, c, "nym_auth", derivations, nymAuthSubject("pan-200"), document, second)
	require.NoError(t, err, "after the reset the second wallet's psc is accepted")
	var doc map[string]any
	require.NoError(t, json.Unmarshal(applied.documentData, &doc))
	assert.Equal(t, secondPSC, doc["psc"])
	carried := doc["ssc"].(string)
	require.NoError(t, reset(psc, KeyValue{Path: ssc, Value: &carried}), "the value the credential carries names the same key")

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
			_, err := issueAuxiliaryData(t, c, "nym_auth", derivations, nil, document, entries)
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

func (m memoryCommitments) Accept(_ context.Context, commitments []db.UniqueCommitment, at time.Time) error {
	var stored []string
	for i, c := range commitments {
		k := fmt.Sprint(c.Key)
		record, ok := m[k]
		switch {
		case !ok:
			m[k] = memoryRecord{commitment: c.Commitment, at: at}
			stored = append(stored, k)
		case !bytes.Equal(record.commitment, c.Commitment):
			for _, k := range stored {
				delete(m, k)
			}
			return &db.UniqueCommitmentConflict{Index: i}
		}
	}
	return nil
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

	applied, err := issueAuxiliaryData(t, c, "example", derivations,
		map[string]any{"personal_administrative_number": "pan-200"}, []byte(`{"given_name":"Alex"}`), fromWallet)
	require.NoError(t, err)
	toWallet := applied.toWallet
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
	require.NoError(t, json.Unmarshal(applied.documentData, &doc))
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

// Nested verified claims reload from a Mongo-backed store as bson.D and
// bson.A, and a dotted opening input must still resolve in them.
func TestSourceDerivationsReadsClaimsFromTheMongoStore(t *testing.T) {
	stored, err := bson.Marshal(&cache.AuthorizationContext{
		DataSource:     string(model.DataSourcePresentation),
		PresentedScope: "pid",
		VerifiedClaims: map[string]any{"subject": map[string]any{"pan": "pan-1", "list": []any{map[string]any{"a": "b"}}}},
	})
	require.NoError(t, err)
	var authContext cache.AuthorizationContext
	require.NoError(t, bson.Unmarshal(stored, &authContext))
	require.IsType(t, bson.D{}, authContext.VerifiedClaims["subject"], "the premise: the store returns bson.D")

	c := &Client{cfg: &model.Cfg{APIGW: &model.APIGW{DataSources: model.DataSources{Presentation: model.PresentationConfig{
		Scopes: map[string]model.PresentationScope{"nym_auth": {From: map[string]model.PresentedCredential{"pid": {}}}},
	}}}}}

	_, claims := c.sourceDerivations("nym_auth", &authContext, nil)
	secret := []byte(strings.Repeat("s", 32))
	secretPath := filepath.Join(t.TempDir(), "seed.key")
	require.NoError(t, os.WriteFile(secretPath, []byte(base64.RawURLEncoding.EncodeToString(secret)+"\n"), 0o600))
	opening := primitives.HKDFOpeningArgs{SecretPath: secretPath, Inputs: []string{"subject.pan"}, Bytes: 16}
	hc := primitives.HashCommitmentArgs{Path: []string{"commitments", "ssc"}, Opening: &primitives.OpeningArgs{HKDF: &opening}}
	_, err = hc.NewOpening(claims)
	require.NoError(t, err, "subject.pan resolves in the normalised claims")
	assert.IsType(t, []any{}, claims["subject"].(map[string]any)["list"])
}

// An opening reads the claims its source supplied. For an assertion that is
// what the callback captured, which the document filter may have dropped; for
// the other sources it is the document before its derivations run.
func TestOpeningSourceClaims(t *testing.T) {
	document := &model.CompleteDocument{
		DocumentData:  map[string]any{"given_name": "Alex"},
		OpeningClaims: map[string]any{"personal_administrative_number": "pan-1"},
	}
	assertion := &cache.AuthorizationContext{DataSource: string(model.DataSourceAssertion)}
	datastore := &cache.AuthorizationContext{DataSource: string(model.DataSourceDatastore)}

	assert.Equal(t, document.OpeningClaims, openingSourceClaims(assertion, document), "the captured claims, not the filtered document")
	assert.Equal(t, document.DocumentData, openingSourceClaims(datastore, document), "a datastore document is the source")
	assert.Equal(t, document.DocumentData, openingSourceClaims(assertion, &model.CompleteDocument{DocumentData: document.DocumentData}),
		"a document cached without captured claims gives its data")
}

// An opening that reads a claim the OIDC document filter drops still works,
// because the callback captured the claim before the filter.
func TestOIDCDocumentCarriesTheOpeningClaims(t *testing.T) {
	c, _, _, _ := claimsTestClient(t)
	cc, err := c.newCallbackClaims("ehic", oidcIdentityClaims(), nil)
	require.NoError(t, err)
	cc.openingClaims = map[string]any{"sub": "opening-input"}

	doc, err := c.buildOIDCDocument(cc, "https://issuer.example", true)
	require.NoError(t, err)
	assert.NotContains(t, doc.DocumentData, "sub", "the document filter drops the claim")
	assert.Equal(t, map[string]any{"sub": "opening-input"}, doc.OpeningClaims)

	encoded, err := json.Marshal(map[string]*model.CompleteDocument{"d": doc})
	require.NoError(t, err)
	var back map[string]*model.CompleteDocument
	require.NoError(t, json.Unmarshal(encoded, &back))
	assert.Equal(t, doc.OpeningClaims, back["d"].OpeningClaims, "the claims survive the JSON cache")
}

// A memory store hands every request the same claims, so normalising them
// must not write into them.
func TestStoredClaimsLeavesTheCachedClaimsUnchanged(t *testing.T) {
	nested := map[string]any{"pan": "pan-1"}
	items := []any{map[string]any{"a": "b"}}
	cached := map[string]any{"subject": nested, "list": items}

	normalised := storedClaims(cached)

	assert.Equal(t, map[string]any{"subject": map[string]any{"pan": "pan-1"}, "list": []any{map[string]any{"a": "b"}}}, normalised)
	normalised["subject"].(map[string]any)["pan"] = "changed"
	normalised["list"].([]any)[0] = "changed"
	assert.Equal(t, "pan-1", nested["pan"], "the cached object is not shared")
	assert.IsType(t, map[string]any{}, items[0], "the cached array is not shared")
}

// A claim opening is the bytes the claim holds, and the credential carries
// their SHA-256. The claim is base64url of the bytes 00 to 0f, whose
// SHA-256 is from `openssl dgst -sha256`.
func TestAuxiliaryDataClaimOpening(t *testing.T) {
	ssc := []string{"commitments", "ssc"}
	vctm := &sdjwtvc.VCTM{VCT: "https://example.org/example", Claims: []sdjwtvc.Claim{{Path: []*string{&ssc[0], &ssc[1]}, SD: "always"}}}
	c := &Client{log: logger.NewSimple("test"), cfg: &model.Cfg{Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{
		"example": {Format: "dc+sd-jwt", VCTM: vctm, AuxiliaryData: &openid4vci.AuxiliaryDataSupported{
			ToWallet: []openid4vci.AuxiliaryDataEntry{{Type: "hash_commitment", Alg: "sha-256", Path: ssc, Encoding: "hex"}},
		}},
	}}}}
	derivations := []primitives.Derivation{{HashCommitment: &primitives.HashCommitmentArgs{
		Path:    ssc,
		Opening: &primitives.OpeningArgs{Claim: &primitives.ClaimOpeningArgs{Input: "nym_auth_opening"}},
	}}}
	const claim = "AAECAwQFBgcICQoLDA0ODw"

	applied, err := c.applyAuxiliaryData(t.Context(), "example", derivations, map[string]any{"nym_auth_opening": claim}, []byte(`{}`), nil)
	require.NoError(t, err)
	require.Len(t, applied.toWallet, 1)
	assert.Equal(t, claim, applied.toWallet[0].Opening, "the opening is the claim's bytes")
	var doc map[string]any
	require.NoError(t, json.Unmarshal(applied.documentData, &doc))
	assert.Equal(t, map[string]any{"ssc": "be45cb2605bf36bebde684841a28f0fd43c69850a3dce5fedba69928ee3a8991"}, doc["commitments"])
}
