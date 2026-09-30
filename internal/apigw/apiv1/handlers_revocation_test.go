package apiv1

import (
	"context"
	"errors"
	"fmt"
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
	// ctxErrs is the ctx.Err() seen by each call, so a test can tell a
	// cleanup that was SENT from one the caller's cancellation killed
	// before it left.
	ctxErrs []error
	err     error
}

func (r *recordingIssuer) SetCredentialStatus(ctx context.Context, in *apiv1_issuer.SetCredentialStatusRequest, _ ...grpc.CallOption) (*apiv1_issuer.SetCredentialStatusReply, error) {
	r.calls = append(r.calls, in)
	r.ctxErrs = append(r.ctxErrs, ctx.Err())
	if r.err != nil {
		return nil, r.err
	}
	return &apiv1_issuer.SetCredentialStatusReply{}, nil
}

type stubStatusStore struct {
	entries []*db.CredentialStatusEntry
	saved   []*db.CredentialStatusEntry
	err     error
	// failAfter, when non-zero, lets the first N saves succeed and fails
	// the next - so a partial failure part-way through a batch can be
	// exercised.
	failAfter int
	// deleted records rollback of mappings written earlier in a batch that
	// then failed, keyed the way the store keys them.
	deleted []string
	// deleteCtxErrs mirrors recordingIssuer.ctxErrs for the rollback path.
	deleteCtxErrs []error
}

func (s *stubStatusStore) Delete(ctx context.Context, uri string, index int64, backend string) error {
	s.deleted = append(s.deleted, fmt.Sprintf("%s|%d|%s", uri, index, backend))
	s.deleteCtxErrs = append(s.deleteCtxErrs, ctx.Err())
	return nil
}

func (s *stubStatusStore) Save(_ context.Context, e *db.CredentialStatusEntry) error {
	s.saved = append(s.saved, e)
	if s.failAfter > 0 {
		if len(s.saved) <= s.failAfter {
			return nil
		}
		return errors.New("database unavailable")
	}
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

	reply, err := c.RevokeCredential(t.Context(), &RevokeCredentialRequest{Identifier: "person-1", Authorize: allowAll})
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

	reply, err := c.RevokeCredential(t.Context(), &RevokeCredentialRequest{Identifier: "person-1", Authorize: allowAll})
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

	_, err := c.RevokeCredential(t.Context(), &RevokeCredentialRequest{Identifier: "nobody", Authorize: allowAll})
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
		Authorize:     allowAll,
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
		Authorize:     allowAll,
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
			_, err := c.RevokeCredential(t.Context(), &RevokeCredentialRequest{Identifier: "person-1", Status: &s, Authorize: allowAll})
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

	reply, err := c.RevokeCredential(t.Context(), &RevokeCredentialRequest{Identifier: "person-1", Authorize: allowAll})
	require.Error(t, err)
	require.Nil(t, reply)
	require.Contains(t, err.Error(), "failed to set status of entry 9")
}

// TestRevokeCredential_RefusesEntriesOutsideTheCallersAuthorization is the
// security case: the route authenticates its caller, but authentication is
// not authorization. The identifier in the request is the CALLER'S OWN
// INPUT, so without binding to something recorded at issuance, any principal
// the API auth accepts could revoke any subject's credentials by naming
// them.
func TestRevokeCredential_RefusesEntriesOutsideTheCallersAuthorization(t *testing.T) {
	issuer := &recordingIssuer{}
	mine := registryEntry()
	mine.AuthenticSource, mine.Scope = "SUNET", "pid"
	theirs := externalEntry()
	theirs.AuthenticSource, theirs.Scope = "OTHER_ORG", "ehic"

	c := revokeClient(t, &stubStatusStore{entries: []*db.CredentialStatusEntry{mine, theirs}}, issuer)

	reply, err := c.RevokeCredential(t.Context(), &RevokeCredentialRequest{
		Identifier: "person-1",
		Authorize:  grants(pair{"SUNET", "pid"}),
	})
	require.NoError(t, err)
	require.Len(t, reply.Revoked, 1, "only the entry inside the caller's authorization may be revoked")
	require.Equal(t, "https://registry.example.com/statuslists/4", reply.Revoked[0].StatusListURI)

	require.Len(t, issuer.calls, 1, "the unauthorized entry must never reach the issuer")
	require.Equal(t, "registry", issuer.calls[0].Backend)
}

// TestRevokeCredential_AllEntriesUnauthorizedIsAnError: refusing every entry
// must not read as success-with-nothing-done, and must not disclose that the
// subject holds credentials elsewhere.
func TestRevokeCredential_AllEntriesUnauthorizedIsAnError(t *testing.T) {
	issuer := &recordingIssuer{}
	theirs := registryEntry()
	theirs.AuthenticSource, theirs.Scope = "OTHER_ORG", "ehic"

	c := revokeClient(t, &stubStatusStore{entries: []*db.CredentialStatusEntry{theirs}}, issuer)

	_, err := c.RevokeCredential(t.Context(), &RevokeCredentialRequest{
		Identifier: "person-1",
		Authorize:  grants(pair{"SUNET", "pid"}),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not authorized")
	require.NotContains(t, err.Error(), "OTHER_ORG", "an unauthorized caller must not learn where else the subject holds credentials")
	require.Empty(t, issuer.calls)
}

// TestRevokeCredential_NoAuthorizerRefusesEverything is the fail-closed
// reading of a missing decision: a caller reached a destructive operation
// with no way to tell whether they may perform it.
func TestRevokeCredential_NoAuthorizerRefusesEverything(t *testing.T) {
	issuer := &recordingIssuer{}
	c := revokeClient(t, &stubStatusStore{entries: []*db.CredentialStatusEntry{registryEntry()}}, issuer)

	_, err := c.RevokeCredential(t.Context(), &RevokeCredentialRequest{Identifier: "person-1"})
	require.Error(t, err)
	require.Empty(t, issuer.calls)
}

// TestRevokeCredential_PairsAreAtomic is the Cartesian-product case: grants
// of (SUNET, pid) and (OTHER, ehic) must NOT authorize (SUNET, ehic).
// Flattening the grants into a source list and a scope list would, because
// both values appear in both lists.
func TestRevokeCredential_PairsAreAtomic(t *testing.T) {
	issuer := &recordingIssuer{}
	crossed := registryEntry()
	crossed.AuthenticSource, crossed.Scope = "SUNET", "ehic"

	c := revokeClient(t, &stubStatusStore{entries: []*db.CredentialStatusEntry{crossed}}, issuer)

	_, err := c.RevokeCredential(t.Context(), &RevokeCredentialRequest{
		Identifier: "person-1",
		Authorize:  grants(pair{"SUNET", "pid"}, pair{"OTHER", "ehic"}),
	})
	require.Error(t, err, "(SUNET, ehic) was never granted, even though both values appear among the grants")
	require.Contains(t, err.Error(), "not authorized")
	require.Empty(t, issuer.calls)
}

type pair struct{ source, scope string }

// grants builds an authorizer that permits exactly the listed pairs, the way
// a SPOCP rule set does - never their Cartesian product.
func grants(allowed ...pair) func(string, string) bool {
	return func(source, scope string) bool {
		for _, p := range allowed {
			if p.source == source && p.scope == scope {
				return true
			}
		}
		return false
	}
}

func allowAll(string, string) bool { return true }

// sharedURIEntries are two entries at the SAME list URI and index under
// different backends. That is a reconfiguration rather than a normal state,
// but it is precisely why the store keys on all three columns, so the
// revoke endpoint has to cope with it too.
func sharedURIEntries() []*db.CredentialStatusEntry {
	const uri = "https://status.example.com/statuslists/1"
	return []*db.CredentialStatusEntry{
		{StatusListURI: uri, Index: 7, Identifier: "person-1", Backend: "registry", Section: 3},
		{StatusListURI: uri, Index: 7, Identifier: "person-1", Backend: "status_service"},
	}
}

// TestRevokeCredential_AmbiguousNarrowingIsRefused: the caller asked to act
// on ONE entry, and (status_list_uri, idx) does not identify one. Acting on
// both would revoke a credential nobody asked about.
func TestRevokeCredential_AmbiguousNarrowingIsRefused(t *testing.T) {
	issuer := &recordingIssuer{}
	c := revokeClient(t, &stubStatusStore{entries: sharedURIEntries()}, issuer)

	idx := int64(7)
	_, err := c.RevokeCredential(t.Context(), &RevokeCredentialRequest{
		Identifier:    "person-1",
		StatusListURI: "https://status.example.com/statuslists/1",
		Index:         &idx,
		Authorize:     allowAll,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "more than one backend")
	require.Empty(t, issuer.calls, "nothing may be acted on before the ambiguity is resolved")
}

// TestRevokeCredential_BackendResolvesTheAmbiguity: naming the backend
// selects exactly one of them, and leaves the other alone.
func TestRevokeCredential_BackendResolvesTheAmbiguity(t *testing.T) {
	issuer := &recordingIssuer{}
	c := revokeClient(t, &stubStatusStore{entries: sharedURIEntries()}, issuer)

	idx := int64(7)
	reply, err := c.RevokeCredential(t.Context(), &RevokeCredentialRequest{
		Identifier:    "person-1",
		StatusListURI: "https://status.example.com/statuslists/1",
		Index:         &idx,
		Backend:       "status_service",
		Authorize:     allowAll,
	})
	require.NoError(t, err)
	require.Len(t, reply.Revoked, 1)
	require.Len(t, issuer.calls, 1)
	require.Equal(t, "status_service", issuer.calls[0].Backend)
}

// TestRevokeCredential_BackendAloneDoesNotNarrow: without the pair, a
// backend filter would quietly revoke every entry that subject holds on
// that backend under the banner of a narrowed request. It filters, and the
// unnarrowed case still means "everything".
func TestRevokeCredential_BackendNarrowsTheUnnarrowedCase(t *testing.T) {
	issuer := &recordingIssuer{}
	c := revokeClient(t, &stubStatusStore{entries: []*db.CredentialStatusEntry{
		externalEntry(), registryEntry(),
	}}, issuer)

	reply, err := c.RevokeCredential(t.Context(), &RevokeCredentialRequest{
		Identifier: "person-1",
		Backend:    "registry",
		Authorize:  allowAll,
	})
	require.NoError(t, err)
	require.Len(t, reply.Revoked, 1)
	require.Equal(t, "registry", issuer.calls[0].Backend)
}
