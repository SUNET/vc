package apiv1

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/SUNET/vc/internal/apigw/db"
	"github.com/SUNET/vc/pkg/credential/seed"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakePSCStore is the record, in memory. Only Accept is exercised by
// the issuance path; the rest is the operator's surface and is covered
// against the real backends in internal/apigw/db.
type fakePSCStore struct {
	accepted map[string]string
	fail     error
}

func (f *fakePSCStore) Accept(_ context.Context, subjectKey, psc string, _ time.Time) error {
	if f.fail != nil {
		return f.fail
	}
	if f.accepted == nil {
		f.accepted = map[string]string{}
	}
	if existing, seen := f.accepted[subjectKey]; seen {
		if existing != psc {
			return db.ErrPSCConflict
		}
		return nil
	}
	f.accepted[subjectKey] = psc
	return nil
}

func (f *fakePSCStore) Get(context.Context, string) (*db.NymAuthPSCRecord, error) { return nil, nil }
func (f *fakePSCStore) Reset(context.Context, string, string, string, time.Time) error {
	return nil
}
func (f *fakePSCStore) Resets(context.Context, string) ([]db.NymAuthPSCReset, error) {
	return nil, nil
}
func (f *fakePSCStore) Erase(context.Context, string) error { return nil }

// holderClient is an mdoc scope whose commitment the HOLDER supplies.
func holderClient(t *testing.T, store db.NymAuthPSCStore) *Client {
	t.Helper()
	return &Client{
		log: logger.NewSimple("test"),
		cfg: &model.Cfg{Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{
			"nym_auth": {
				Format: openid4vp.FormatMsoMdoc,
				Commitments: map[string]*model.CommitmentClaim{"psc": {
					Source:   model.CommitmentSourceHolder,
					Subjects: []string{"personal_administrative_number"},
				}},
				MDDL: &mdoc.MDDLSchema{
					DocType: "eu.europa.ec.eudi.nym_auth.1",
					Claims: map[string]mdoc.NamespaceClaims{
						"eu.europa.ec.eudi.nym_auth.1": {
							"personal_administrative_number": {Mandatory: true, ValueType: "tstr"},
							"psc":                            {Mandatory: true, ValueType: "bstr"},
						},
					},
				},
			},
		}}},
		pscStore: store,
	}
}

const holderDocument = `{"personal_administrative_number":"198001011234"}`

// The holder's commitment is written into the credential as sent, and
// recorded against the subject.
func TestHolderCommitmentIsWrittenAndRecorded(t *testing.T) {
	store := &fakePSCStore{}
	client := holderClient(t, store)
	hexValue, _ := testPSC()

	out, delivered, err := client.injectCommitments(t.Context(), "nym_auth", openid4vp.FormatMsoMdoc, []byte(holderDocument), hexValue)
	require.NoError(t, err)
	assert.Empty(t, delivered, "there is no seed to deliver - the holder has it")

	var doc map[string]any
	require.NoError(t, json.Unmarshal(out, &doc))
	// mdoc document data is flat, and the configured encoding for it
	// is base64 - the carrier is a bstr.
	assert.NotEmpty(t, doc["psc"])
	assert.NotEqual(t, hexValue, doc["psc"], "an mdoc bstr carries base64, not hex")

	subjectKey, err := seed.SubjectKeyHex([]string{"198001011234"})
	require.NoError(t, err)
	assert.Equal(t, hexValue, store.accepted[subjectKey],
		"the record is keyed by the subject identifiers, not by anything in the proof")
}

// The same commitment again is not a conflict: re-issuance, batch
// issuance and a retried request all reach this legitimately.
func TestHolderCommitmentAcceptsTheSameValueTwice(t *testing.T) {
	store := &fakePSCStore{}
	client := holderClient(t, store)
	hexValue, _ := testPSC()

	for range 2 {
		_, _, err := client.injectCommitments(t.Context(), "nym_auth", openid4vp.FormatMsoMdoc, []byte(holderDocument), hexValue)
		require.NoError(t, err)
	}
}

// A second, DIFFERENT commitment is refused with the marked 400 - and
// refused HERE, inside the injection, which runs before the format
// dispatch. So nothing is signed and no status-list index is burned.
func TestHolderCommitmentConflictIsTheMarked400(t *testing.T) {
	store := &fakePSCStore{}
	client := holderClient(t, store)
	hexValue, _ := testPSC()
	require.NoError(t, store.Accept(t.Context(), mustSubjectKey(t), hexValue, time.Now()))

	other := hexValue[:62] + "ff"
	require.NotEqual(t, hexValue, other)

	_, _, err := client.injectCommitments(t.Context(), "nym_auth", openid4vp.FormatMsoMdoc, []byte(holderDocument), other)
	require.Error(t, err)

	var vciErr *openid4vci.Error
	require.ErrorAs(t, err, &vciErr)
	assert.Equal(t, openid4vci.ErrInvalidCredentialRequest, vciErr.Err)
	assert.Equal(t, 400, openid4vci.StatusCode(vciErr))
	description, ok := vciErr.ErrorDescription.(string)
	require.True(t, ok)
	assert.Contains(t, description, model.PSCConflictPrefix)
}

// A wallet that sent no commitment, for a credential that requires
// one, is refused as an invalid proof - and the message names the
// claim and where it is advertised, because a wallet that missed the
// advertisement has no other way to find out.
func TestHolderCommitmentRefusesAMissingClaim(t *testing.T) {
	client := holderClient(t, &fakePSCStore{})

	_, _, err := client.injectCommitments(t.Context(), "nym_auth", openid4vp.FormatMsoMdoc, []byte(holderDocument), "")
	require.Error(t, err)

	var vciErr *openid4vci.Error
	require.ErrorAs(t, err, &vciErr)
	assert.Equal(t, openid4vci.ErrInvalidProof, vciErr.Err)
	description, ok := vciErr.ErrorDescription.(string)
	require.True(t, ok)
	assert.Contains(t, description, model.PSCProofClaim)
	assert.Contains(t, description, model.HolderCommitmentsMember)
}

// Without a store there is no way to enforce one commitment per
// subject, so the issuance is refused rather than accepting whatever
// arrived. Startup refuses this configuration; this is the second
// gate, for a caller that reached here anyway.
func TestHolderCommitmentRefusesWithoutAStore(t *testing.T) {
	client := holderClient(t, nil)
	hexValue, _ := testPSC()

	_, _, err := client.injectCommitments(t.Context(), "nym_auth", openid4vp.FormatMsoMdoc, []byte(holderDocument), hexValue)
	assert.ErrorContains(t, err, "commitment store is not available")
}

// A store failure that is not a conflict must not be reported as one:
// an operator told "this subject already has a commitment" would go
// looking for a record that does not exist.
func TestHolderCommitmentDistinguishesAStoreFailureFromAConflict(t *testing.T) {
	client := holderClient(t, &fakePSCStore{fail: assert.AnError})
	hexValue, _ := testPSC()

	_, _, err := client.injectCommitments(t.Context(), "nym_auth", openid4vp.FormatMsoMdoc, []byte(holderDocument), hexValue)
	require.Error(t, err)

	var vciErr *openid4vci.Error
	assert.False(t, errors.As(err, &vciErr) && vciErr.Err == openid4vci.ErrInvalidCredentialRequest,
		"a store failure is not the subject's fault and must not read as a conflict")
	assert.ErrorIs(t, err, assert.AnError, "and the underlying failure must still be reachable")
}

func mustSubjectKey(t *testing.T) string {
	t.Helper()
	key, err := seed.SubjectKeyHex([]string{"198001011234"})
	require.NoError(t, err)
	return key
}
