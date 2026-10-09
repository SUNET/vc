package apiv1

import (
	"context"
	"testing"

	"github.com/SUNET/vc/internal/registry/db"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/require"
)

type recordingAdminDB struct {
	updates []struct {
		Section, Index int64
		Status         uint8
	}
	found *db.TokenStatusListDoc
}

func (r *recordingAdminDB) FindOne(_ context.Context, _, _ int64) (*db.TokenStatusListDoc, error) {
	return r.found, nil
}

func (r *recordingAdminDB) UpdateStatus(_ context.Context, section, index int64, status uint8) error {
	r.updates = append(r.updates, struct {
		Section, Index int64
		Status         uint8
	}{section, index, status})
	return nil
}

func newOwnershipClient(t *testing.T) (*Client, *recordingAdminDB) {
	t.Helper()
	adminDB := &recordingAdminDB{}
	return &Client{
		cfg:     &model.Cfg{Registry: &model.Registry{PublicURL: "https://registry.example.com"}},
		log:     logger.NewSimple("test"),
		adminDB: adminDB,
	}, adminDB
}

// TestUpdateStatus_RefusesAListThisRegistryDoesNotOwn is the safety case for
// storing external status entries at all.
//
// An external draft-ietf-oauth-status-list service has no sections, so every
// entry it allocates is recorded with Section 0. Acting on (section, index)
// alone would write status 0/17 of THIS registry's own list - revoking
// whichever local credential sits there while leaving the intended
// credential valid. Two wrong outcomes, no error.
func TestUpdateStatus_RefusesAListThisRegistryDoesNotOwn(t *testing.T) {
	c, adminDB := newOwnershipClient(t)

	err := c.UpdateStatus(t.Context(), &UpdateStatusRequest{
		Section:       0,
		Index:         17,
		Status:        1,
		StatusListURI: "https://status.example.com/statuslists/abc",
	})

	require.Error(t, err)
	require.Contains(t, err.Error(), "not issued by this registry")
	require.Empty(t, adminDB.updates, "nothing may be written to the local list")
}

// TestUpdateStatus_AcceptsThisRegistrysOwnList: the URI must be compared
// against the exact URL the allocation reply and the token's sub claim are
// built from, so a genuine local entry still works.
func TestUpdateStatus_AcceptsThisRegistrysOwnList(t *testing.T) {
	c, adminDB := newOwnershipClient(t)

	uri, err := c.cfg.Registry.StatusListURL(4)
	require.NoError(t, err)
	require.Equal(t, "https://registry.example.com/statuslists/4", uri)

	require.NoError(t, c.UpdateStatus(t.Context(), &UpdateStatusRequest{
		Section: 4, Index: 9, Status: 1, StatusListURI: uri,
	}))
	require.Len(t, adminDB.updates, 1)
	require.Equal(t, int64(4), adminDB.updates[0].Section)
	require.Equal(t, int64(9), adminDB.updates[0].Index)
	require.Equal(t, uint8(1), adminDB.updates[0].Status)
}

// TestUpdateStatus_RefusesTheRightURIForTheWrongSection: the URI names a
// list this registry does own, but not the one that section lives in, so
// acting on it would write to a different list than the operator saw.
func TestUpdateStatus_RefusesTheRightURIForTheWrongSection(t *testing.T) {
	c, adminDB := newOwnershipClient(t)

	err := c.UpdateStatus(t.Context(), &UpdateStatusRequest{
		Section: 4, Index: 9, Status: 1,
		StatusListURI: "https://registry.example.com/statuslists/5",
	})
	require.Error(t, err)
	require.Empty(t, adminDB.updates)
}

// TestUpdateStatus_RefusesAnEmptyURI: section and index alone no longer
// identify an entry.
func TestUpdateStatus_RefusesAnEmptyURI(t *testing.T) {
	c, adminDB := newOwnershipClient(t)

	err := c.UpdateStatus(t.Context(), &UpdateStatusRequest{Section: 0, Index: 1, Status: 1})
	require.Error(t, err)
	require.Empty(t, adminDB.updates)
}

// TestSearchPerson_DoesNotReadExternalEntriesFromTheLocalDatabase: reading
// an external entry's coordinates out of adminDB reports the status of a
// different credential, and a miss leaves Status at 0, which reads as VALID.
func TestSearchPerson_DoesNotReadExternalEntriesFromTheLocalDatabase(t *testing.T) {
	c, adminDB := newOwnershipClient(t)
	adminDB.found = &db.TokenStatusListDoc{Status: 1} // local entry at the same coordinates

	c.credentialSubjects = &stubCredentialSubjects{docs: []*db.CredentialSubjectDoc{
		{Identifier: "p", Section: 0, Index: 17, StatusListURI: "https://status.example.com/statuslists/abc"},
		{Identifier: "p", Section: 4, Index: 9, StatusListURI: "https://registry.example.com/statuslists/4"},
	}}

	reply, err := c.SearchPerson(t.Context(), &SearchPersonRequest{Identifier: "p"})
	require.NoError(t, err)
	require.Len(t, reply.Results, 2)

	external := reply.Results[0]
	require.False(t, external.Local)
	require.False(t, external.StatusKnown, "this registry cannot read an external list")
	require.Equal(t, uint8(0), external.Status, "and must not report another credential's status")

	local := reply.Results[1]
	require.True(t, local.Local)
	require.True(t, local.StatusKnown)
	require.Equal(t, uint8(1), local.Status)
}

type stubCredentialSubjects struct {
	docs []*db.CredentialSubjectDoc
}

func (s *stubCredentialSubjects) Search(context.Context, string) ([]*db.CredentialSubjectDoc, error) {
	return s.docs, nil
}

func (s *stubCredentialSubjects) Add(context.Context, *db.CredentialSubjectDoc) error { return nil }

// TestSearchPerson_LegacyRecordsKeepTheirUpdateControl: status_list_uri was
// added after these records were written. Every one of them is this
// registry's own - nothing else writes to that collection - so treating a
// blank as "belongs to somebody else" would make every pre-existing entry
// display as unknown and lose its update control. That is a regression in
// the admin GUI, not a safety measure.
func TestSearchPerson_LegacyRecordsKeepTheirUpdateControl(t *testing.T) {
	c, adminDB := newOwnershipClient(t)
	adminDB.found = &db.TokenStatusListDoc{Status: 2}

	c.credentialSubjects = &stubCredentialSubjects{docs: []*db.CredentialSubjectDoc{
		{Identifier: "p", Section: 4, Index: 9}, // no StatusListURI
	}}

	reply, err := c.SearchPerson(t.Context(), &SearchPersonRequest{Identifier: "p"})
	require.NoError(t, err)
	require.Len(t, reply.Results, 1)

	got := reply.Results[0]
	require.True(t, got.Local, "a record written before the field existed is still this registry's own")
	require.True(t, got.StatusKnown)
	require.Equal(t, uint8(2), got.Status)
	require.Equal(t, "https://registry.example.com/statuslists/4", got.StatusListURI,
		"the URL is derived so the admin form can name what it acts on")
}

// TestUpdateStatus_StillRefusesAnEmptyURI: filling legacy records in on
// display must not make the update path lenient. The form always sends the
// displayed URI, so a caller naming no list at all is still refused.
func TestUpdateStatus_LegacyDerivationDoesNotWeakenUpdate(t *testing.T) {
	c, adminDB := newOwnershipClient(t)

	err := c.UpdateStatus(t.Context(), &UpdateStatusRequest{Section: 4, Index: 9, Status: 1})
	require.Error(t, err)
	require.Empty(t, adminDB.updates)
}

// TestSaveCredentialSubject_DerivesALegacyURI: an APIGW older than the
// status_list_uri field sends none. Rejecting it would drop the mapping for
// every credential issued during a rolling upgrade; the registry can derive
// it, because every entry it stores is its own.
func TestSaveCredentialSubject_DerivesALegacyURI(t *testing.T) {
	c, _ := newOwnershipClient(t)
	store := &recordingCredentialSubjects{}
	c.credentialSubjects = store

	require.NoError(t, c.SaveCredentialSubject(t.Context(), &SaveCredentialSubjectRequest{
		Identifier: "p", Section: 4, Index: 9,
	}))
	require.Len(t, store.added, 1)
	require.Equal(t, "https://registry.example.com/statuslists/4", store.added[0].StatusListURI)
}

// TestSaveCredentialSubject_RefusesAForeignList: the registry cannot act on
// an entry it does not own, so recording one would only produce a row its
// admin view can display and nothing can change.
func TestSaveCredentialSubject_RefusesAForeignList(t *testing.T) {
	c, _ := newOwnershipClient(t)
	store := &recordingCredentialSubjects{}
	c.credentialSubjects = store

	err := c.SaveCredentialSubject(t.Context(), &SaveCredentialSubjectRequest{
		Identifier: "p", Section: 0, Index: 17,
		StatusListURI: "https://status.example.com/statuslists/abc",
	})
	require.Error(t, err)
	require.Empty(t, store.added)
}

type recordingCredentialSubjects struct {
	stubCredentialSubjects
	added []*db.CredentialSubjectDoc
}

func (r *recordingCredentialSubjects) Add(_ context.Context, doc *db.CredentialSubjectDoc) error {
	r.added = append(r.added, doc)
	return nil
}
