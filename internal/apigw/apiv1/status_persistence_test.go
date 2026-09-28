package apiv1

import (
	"context"
	"errors"
	"testing"

	"github.com/SUNET/vc/internal/apigw/db"
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
	err   error
}

func (r *recordingRegistryClient) SaveCredentialSubject(_ context.Context, in *apiv1_registry.SaveCredentialSubjectRequest, _ ...grpc.CallOption) (*apiv1_registry.SaveCredentialSubjectReply, error) {
	r.saved = append(r.saved, in)
	if r.err != nil {
		return nil, r.err
	}
	return &apiv1_registry.SaveCredentialSubjectReply{}, nil
}

func persistenceClient(t *testing.T, registry apiv1_registry.RegistryServiceClient) (*Client, *stubStatusStore) {
	t.Helper()
	store := &stubStatusStore{}
	return &Client{
		log:            logger.NewSimple("test"),
		db:             &db.Service{CredentialStatusColl: store},
		registryClient: registry,
	}, store
}

// TestSaveCredentialSubjects_ExternalAllocationIsPersisted is the regression
// test for the original defect: the filter was `if e.Section <= 0 { continue }`,
// and an external draft-ietf-oauth-status-list service has no sections, so
// every entry it allocated reported Section 0 and was silently discarded.
// The mapping is what revocation looks a credential up by, so a discarded
// entry meant a credential that could never be revoked - with no error
// anywhere.
func TestSaveCredentialSubjects_ExternalAllocationIsPersisted(t *testing.T) {
	c, store := persistenceClient(t, nil)

	err := c.saveCredentialSubjects(t.Context(), "person-1", []statusEntry{
		{Section: 0, Index: 17, URI: "https://status.example.com/statuslists/abc", Backend: "status_service"},
	})
	require.NoError(t, err)

	require.Len(t, store.saved, 1, "an external status entry (Section 0) must still be recorded")
	require.Equal(t, "person-1", store.saved[0].Identifier)
	require.Equal(t, int64(17), store.saved[0].Index)
	require.Equal(t, "https://status.example.com/statuslists/abc", store.saved[0].StatusListURI)
	require.Equal(t, "status_service", store.saved[0].Backend,
		"the backend must be recorded, or revocation cannot route the entry")
}

// TestSaveCredentialSubjects_NoRegistryIsFine: the local registry is
// optional, so issuance must not depend on one being reachable.
func TestSaveCredentialSubjects_NoRegistryIsFine(t *testing.T) {
	c, store := persistenceClient(t, nil)
	require.Nil(t, c.registryClient)

	require.NoError(t, c.saveCredentialSubjects(t.Context(), "person-1", []statusEntry{
		{Index: 3, URI: "https://status.example.com/statuslists/abc", Backend: "status_service"},
	}))
	require.Len(t, store.saved, 1)
}

// TestSaveCredentialSubjects_RegistryIsMirroredBestEffort: when a registry
// IS configured its admin GUI reads from there, so the entry is mirrored -
// but a registry that is down costs its admin view a row, not the
// credential its revocability.
func TestSaveCredentialSubjects_RegistryIsMirroredBestEffort(t *testing.T) {
	rec := &recordingRegistryClient{}
	c, store := persistenceClient(t, rec)

	require.NoError(t, c.saveCredentialSubjects(t.Context(), "person-2", []statusEntry{
		{Section: 4, Index: 5, URI: "https://registry.example.com/statuslists/4", Backend: "registry"},
	}))
	require.Len(t, store.saved, 1)
	require.Len(t, rec.saved, 1)
	require.Equal(t, int64(4), rec.saved[0].Section)
	require.Equal(t, "https://registry.example.com/statuslists/4", rec.saved[0].StatusListURI)

	// A failing registry does not fail issuance.
	failing := &recordingRegistryClient{err: errors.New("registry down")}
	c2, store2 := persistenceClient(t, failing)
	require.NoError(t, c2.saveCredentialSubjects(t.Context(), "person-3", []statusEntry{
		{Section: 4, Index: 6, URI: "https://registry.example.com/statuslists/4", Backend: "registry"},
	}))
	require.Len(t, store2.saved, 1, "the authoritative record is still written")
}

// TestSaveCredentialSubjects_StoreFailureFailsIssuance: the apigw's own
// record is what revocation uses. A credential whose entry was not recorded
// can never be revoked, and the entry is consumed either way - failing
// leaves the wallet without a credential and the slot unused, which is
// recoverable. Letting it through is not.
func TestSaveCredentialSubjects_StoreFailureFailsIssuance(t *testing.T) {
	c, store := persistenceClient(t, nil)
	store.err = errors.New("database unavailable")

	err := c.saveCredentialSubjects(t.Context(), "person-1", []statusEntry{
		{Index: 17, URI: "https://status.example.com/statuslists/abc", Backend: "status_service"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to record credential status entry")
}

// TestSaveCredentialSubjects_NoAllocationIsNotRecorded: an entry with no URI
// is one the issuance path never allocated, which is exactly how it reports
// "this credential was issued without a status claim".
func TestSaveCredentialSubjects_NoAllocationIsNotRecorded(t *testing.T) {
	c, store := persistenceClient(t, nil)

	require.NoError(t, c.saveCredentialSubjects(t.Context(), "person-3", []statusEntry{{Section: 0, Index: 0}}))
	require.Empty(t, store.saved, "nothing was allocated, so there is nothing to record")
}

// TestSaveCredentialSubjects_NoIdentifierIsNotRecorded preserves the
// pre-existing guard.
func TestSaveCredentialSubjects_NoIdentifierIsNotRecorded(t *testing.T) {
	c, store := persistenceClient(t, nil)

	require.NoError(t, c.saveCredentialSubjects(t.Context(), "", []statusEntry{
		{Section: 1, Index: 1, URI: "https://registry.example.com/statuslists/1", Backend: "registry"},
	}))
	require.Empty(t, store.saved)
}
