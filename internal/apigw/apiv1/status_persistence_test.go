package apiv1

import (
	"context"
	"testing"

	"github.com/SUNET/vc/internal/gen/registry/apiv1_registry"
	"github.com/SUNET/vc/pkg/logger"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// recordingRegistryClient captures SaveCredentialSubject calls. Every other
// method panics: this test is about one call, and a silent zero value from
// an unimplemented method would make a broken test look like a passing one.
type recordingRegistryClient struct {
	apiv1_registry.RegistryServiceClient
	saved []*apiv1_registry.SaveCredentialSubjectRequest
}

func (r *recordingRegistryClient) SaveCredentialSubject(_ context.Context, in *apiv1_registry.SaveCredentialSubjectRequest, _ ...grpc.CallOption) (*apiv1_registry.SaveCredentialSubjectReply, error) {
	r.saved = append(r.saved, in)
	return &apiv1_registry.SaveCredentialSubjectReply{}, nil
}

func newStatusPersistenceClient(t *testing.T) (*Client, *recordingRegistryClient) {
	t.Helper()
	rec := &recordingRegistryClient{}
	return &Client{log: logger.NewSimple("test"), registryClient: rec}, rec
}

// TestSaveCredentialSubjects_ExternalAllocationIsPersisted is the regression
// test for the defect: the filter was `if e.Section <= 0 { continue }`, and
// an external draft-ietf-oauth-status-list service has no sections, so every
// single entry it allocated reported Section 0 and was silently discarded.
//
// The mapping is what revocation looks a credential up by, so a discarded
// entry means a credential that can never be revoked - and nothing anywhere
// reports an error.
func TestSaveCredentialSubjects_ExternalAllocationIsPersisted(t *testing.T) {
	c, rec := newStatusPersistenceClient(t)

	err := c.saveCredentialSubjects(t.Context(), "person-1", []statusEntry{
		{Section: 0, Index: 17, URI: "https://status.example.com/statuslists/abc"},
	})
	require.NoError(t, err)

	require.Len(t, rec.saved, 1, "an external status entry (Section 0) must still be recorded")
	require.Equal(t, "person-1", rec.saved[0].Identifier)
	require.Equal(t, int64(17), rec.saved[0].Index)
	require.Equal(t, "https://status.example.com/statuslists/abc", rec.saved[0].StatusListURI)
}

// TestSaveCredentialSubjects_RegistryAllocationIsPersisted covers the
// registry backend, including section 0, which the old filter also dropped.
func TestSaveCredentialSubjects_RegistryAllocationIsPersisted(t *testing.T) {
	c, rec := newStatusPersistenceClient(t)

	err := c.saveCredentialSubjects(t.Context(), "person-2", []statusEntry{
		{Section: 0, Index: 3, URI: "https://registry.example.com/statuslists/0"},
		{Section: 4, Index: 5, URI: "https://registry.example.com/statuslists/4"},
	})
	require.NoError(t, err)

	require.Len(t, rec.saved, 2)
	require.Equal(t, int64(0), rec.saved[0].Section)
	require.Equal(t, "https://registry.example.com/statuslists/0", rec.saved[0].StatusListURI)
	require.Equal(t, int64(4), rec.saved[1].Section)
}

// TestSaveCredentialSubjects_NoAllocationIsNotRecorded: an entry with no URI
// is one the issuance path never allocated, which is exactly how it reports
// "this credential was issued without a status claim".
func TestSaveCredentialSubjects_NoAllocationIsNotRecorded(t *testing.T) {
	c, rec := newStatusPersistenceClient(t)

	err := c.saveCredentialSubjects(t.Context(), "person-3", []statusEntry{{Section: 0, Index: 0}})
	require.NoError(t, err)
	require.Empty(t, rec.saved, "nothing was allocated, so there is nothing to record")
}

// TestSaveCredentialSubjects_NoIdentifierIsNotRecorded preserves the
// pre-existing guard.
func TestSaveCredentialSubjects_NoIdentifierIsNotRecorded(t *testing.T) {
	c, rec := newStatusPersistenceClient(t)

	err := c.saveCredentialSubjects(t.Context(), "", []statusEntry{
		{Section: 1, Index: 1, URI: "https://registry.example.com/statuslists/1"},
	})
	require.NoError(t, err)
	require.Empty(t, rec.saved)
}
