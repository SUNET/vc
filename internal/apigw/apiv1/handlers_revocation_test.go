package apiv1

import (
	"context"
	"errors"
	"testing"

	"github.com/SUNET/vc/internal/apigw/db"
	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// recordingIssuer captures SetCredentialStatus calls. Every other method is
// left to the embedded nil interface so an unexpected call panics rather
// than returning a zero value that reads as success.
type recordingIssuer struct {
	apiv1_issuer.IssuerServiceClient
	calls []*apiv1_issuer.SetCredentialStatusRequest
	err   error
}

func (r *recordingIssuer) SetCredentialStatus(_ context.Context, in *apiv1_issuer.SetCredentialStatusRequest, _ ...grpc.CallOption) (*apiv1_issuer.SetCredentialStatusReply, error) {
	r.calls = append(r.calls, in)
	if r.err != nil {
		return nil, r.err
	}
	return &apiv1_issuer.SetCredentialStatusReply{}, nil
}

type stubStatusStore struct {
	entries []*db.CredentialStatusEntry
	saved   []*db.CredentialStatusEntry
	err     error
}

func (s *stubStatusStore) Save(_ context.Context, e *db.CredentialStatusEntry) error {
	s.saved = append(s.saved, e)
	return s.err
}

func (s *stubStatusStore) SearchByIdentifier(_ context.Context, _ string) ([]*db.CredentialStatusEntry, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.entries, nil
}

func revokeClient(t *testing.T, store *stubStatusStore, issuer apiv1_issuer.IssuerServiceClient) *Client {
	t.Helper()
	log := logger.NewSimple("test")
	tracer, err := trace.NewForTesting(t.Context(), "revoke", log)
	require.NoError(t, err)
	return &Client{
		cfg:          &model.Cfg{},
		log:          log,
		tracer:       tracer,
		db:           &db.Service{CredentialStatusColl: store},
		issuerClient: issuer,
	}
}

func externalEntry() *db.CredentialStatusEntry {
	return &db.CredentialStatusEntry{
		StatusListURI: "https://status.example.com/statuslists/abc",
		Index:         17,
		Identifier:    "person-1",
		Section:       0,
		Backend:       "status_service",
	}
}

func registryEntry() *db.CredentialStatusEntry {
	return &db.CredentialStatusEntry{
		StatusListURI: "https://registry.example.com/statuslists/4",
		Index:         9,
		Identifier:    "person-1",
		Section:       4,
		Backend:       "registry",
	}
}

// TestRevokeCredential_WorksWithoutALocalRegistry is the point of the
// feature: a deployment using an external status service has no registry at
// all, and revocation must still work end to end.
func TestRevokeCredential_WorksWithoutALocalRegistry(t *testing.T) {
	issuer := &recordingIssuer{}
	c := revokeClient(t, &stubStatusStore{entries: []*db.CredentialStatusEntry{externalEntry()}}, issuer)
	require.Nil(t, c.registryClient, "this test must not depend on a registry client")

	reply, err := c.RevokeCredential(t.Context(), &RevokeCredentialRequest{Identifier: "person-1"})
	require.NoError(t, err)
	require.Len(t, reply.Revoked, 1)

	require.Len(t, issuer.calls, 1)
	require.Equal(t, "status_service", issuer.calls[0].Backend)
	require.Equal(t, "https://status.example.com/statuslists/abc", issuer.calls[0].StatusListUri)
	require.Equal(t, int64(17), issuer.calls[0].Index)
	require.Equal(t, uint32(1), issuer.calls[0].Status, "revoke defaults to INVALID")
}

// TestRevokeCredential_CarriesTheRecordedBackend: the backend recorded at
// issuance is what decides routing, so an entry with section 0 from an
// external service must not be presented to the issuer as a registry entry.
func TestRevokeCredential_CarriesTheRecordedBackend(t *testing.T) {
	issuer := &recordingIssuer{}
	c := revokeClient(t, &stubStatusStore{entries: []*db.CredentialStatusEntry{
		externalEntry(), registryEntry(),
	}}, issuer)

	reply, err := c.RevokeCredential(t.Context(), &RevokeCredentialRequest{Identifier: "person-1"})
	require.NoError(t, err)
	require.Len(t, reply.Revoked, 2)

	require.Len(t, issuer.calls, 2)
	require.Equal(t, "status_service", issuer.calls[0].Backend)
	require.Equal(t, int64(0), issuer.calls[0].Section)
	require.Equal(t, "registry", issuer.calls[1].Backend)
	require.Equal(t, int64(4), issuer.calls[1].Section)
}

// TestRevokeCredential_NothingRecordedIsNotSuccess: answering OK when no
// status changed would report a revocation that did not happen.
func TestRevokeCredential_NothingRecordedIsNotSuccess(t *testing.T) {
	issuer := &recordingIssuer{}
	c := revokeClient(t, &stubStatusStore{}, issuer)

	_, err := c.RevokeCredential(t.Context(), &RevokeCredentialRequest{Identifier: "nobody"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "no status list entry is recorded")
	require.Empty(t, issuer.calls)
}

// TestRevokeCredential_NarrowsToOneEntry lets a caller that knows which
// credential to revoke avoid revoking the subject's others.
func TestRevokeCredential_NarrowsToOneEntry(t *testing.T) {
	issuer := &recordingIssuer{}
	c := revokeClient(t, &stubStatusStore{entries: []*db.CredentialStatusEntry{
		externalEntry(), registryEntry(),
	}}, issuer)

	idx := int64(9)
	reply, err := c.RevokeCredential(t.Context(), &RevokeCredentialRequest{
		Identifier:    "person-1",
		StatusListURI: "https://registry.example.com/statuslists/4",
		Index:         &idx,
	})
	require.NoError(t, err)
	require.Len(t, reply.Revoked, 1)
	require.Len(t, issuer.calls, 1)
	require.Equal(t, "registry", issuer.calls[0].Backend)
}

func TestRevokeCredential_NarrowingNeedsBothHalves(t *testing.T) {
	issuer := &recordingIssuer{}
	c := revokeClient(t, &stubStatusStore{entries: []*db.CredentialStatusEntry{registryEntry()}}, issuer)

	_, err := c.RevokeCredential(t.Context(), &RevokeCredentialRequest{
		Identifier:    "person-1",
		StatusListURI: "https://registry.example.com/statuslists/4",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "must be given together")
	require.Empty(t, issuer.calls)
}

// TestRevokeCredential_SuspendAndReinstate: revoke defaults to INVALID but
// the endpoint writes whatever status was asked for.
func TestRevokeCredential_SuspendAndReinstate(t *testing.T) {
	for name, status := range map[string]uint8{"suspend": 2, "reinstate": 0} {
		t.Run(name, func(t *testing.T) {
			issuer := &recordingIssuer{}
			c := revokeClient(t, &stubStatusStore{entries: []*db.CredentialStatusEntry{registryEntry()}}, issuer)

			s := status
			_, err := c.RevokeCredential(t.Context(), &RevokeCredentialRequest{Identifier: "person-1", Status: &s})
			require.NoError(t, err)
			require.Len(t, issuer.calls, 1)
			require.Equal(t, uint32(status), issuer.calls[0].Status)
		})
	}
}

// TestRevokeCredential_IssuerFailureIsReported: a partial failure must not
// come back as success, because the caller would believe the credential is
// revoked when it is not.
func TestRevokeCredential_IssuerFailureIsReported(t *testing.T) {
	issuer := &recordingIssuer{err: errors.New("backend unreachable")}
	c := revokeClient(t, &stubStatusStore{entries: []*db.CredentialStatusEntry{registryEntry()}}, issuer)

	reply, err := c.RevokeCredential(t.Context(), &RevokeCredentialRequest{Identifier: "person-1"})
	require.Error(t, err)
	require.Nil(t, reply)
	require.Contains(t, err.Error(), "failed to set status of entry 9")
}
