package apiv1

import (
	"context"
	"errors"
	"testing"

	"github.com/SUNET/vc/internal/apigw/db"
	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"
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
	c, store, _ := persistenceClientWithIssuer(t, registry)
	return c, store
}

func persistenceClientWithIssuer(t *testing.T, registry apiv1_registry.RegistryServiceClient) (*Client, *stubStatusStore, *recordingIssuer) {
	t.Helper()
	store := &stubStatusStore{}
	issuer := &recordingIssuer{}
	return &Client{
		log:            logger.NewSimple("test"),
		db:             &db.Service{CredentialStatusColl: store},
		registryClient: registry,
		issuerClient:   issuer,
	}, store, issuer
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

	err := c.saveCredentialSubjects(t.Context(), "person-1", "SUNET", "pid", []statusEntry{
		{Section: 0, Index: 17, URI: "https://status.example.com/statuslists/abc", Backend: "status_service"},
	})
	require.NoError(t, err)

	require.Len(t, store.saved, 1, "an external status entry (Section 0) must still be recorded")
	require.Equal(t, "person-1", store.saved[0].Identifier)
	require.Equal(t, int64(17), store.saved[0].Index)
	require.Equal(t, "https://status.example.com/statuslists/abc", store.saved[0].StatusListURI)
	require.Equal(t, "status_service", store.saved[0].Backend,
		"the backend must be recorded, or revocation cannot route the entry")
	// Authorization is decided against these at revocation time. If they are
	// not recorded here there is nothing to decide against but the subject
	// identifier, which is the caller's own input and authorizes nothing.
	require.Equal(t, "SUNET", store.saved[0].AuthenticSource,
		"the authentic source must be recorded, or revocation cannot be authorized")
	require.Equal(t, "pid", store.saved[0].Scope,
		"the scope must be recorded, or revocation cannot be authorized")
}

// TestSaveCredentialSubjects_NoRegistryIsFine: the local registry is
// optional, so issuance must not depend on one being reachable.
func TestSaveCredentialSubjects_NoRegistryIsFine(t *testing.T) {
	c, store := persistenceClient(t, nil)
	require.Nil(t, c.registryClient)

	require.NoError(t, c.saveCredentialSubjects(t.Context(), "person-1", "SUNET", "pid", []statusEntry{
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

	require.NoError(t, c.saveCredentialSubjects(t.Context(), "person-2", "SUNET", "pid", []statusEntry{
		{Section: 4, Index: 5, URI: "https://registry.example.com/statuslists/4", Backend: "registry"},
	}))
	require.Len(t, store.saved, 1)
	require.Len(t, rec.saved, 1)
	require.Equal(t, int64(4), rec.saved[0].Section)
	require.Equal(t, "https://registry.example.com/statuslists/4", rec.saved[0].StatusListURI)

	// A failing registry does not fail issuance.
	failing := &recordingRegistryClient{err: errors.New("registry down")}
	c2, store2 := persistenceClient(t, failing)
	require.NoError(t, c2.saveCredentialSubjects(t.Context(), "person-3", "SUNET", "pid", []statusEntry{
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

	err := c.saveCredentialSubjects(t.Context(), "person-1", "SUNET", "pid", []statusEntry{
		{Index: 17, URI: "https://status.example.com/statuslists/abc", Backend: "status_service"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to record credential status entry")
}

// TestSaveCredentialSubjects_NoAllocationIsNotRecorded: an entry with no URI
// is one the issuance path never allocated, which is exactly how it reports
// "this credential was issued without a status claim".
//
// The issuer has to SAY so. Section 0, index 0 and no URI is also what a
// registry's first allocation looks like from an issuer too old to send one,
// so the zero values alone cannot carry this meaning.
func TestSaveCredentialSubjects_NoAllocationIsNotRecorded(t *testing.T) {
	c, store := persistenceClient(t, nil)

	require.NoError(t, c.saveCredentialSubjects(t.Context(), "person-3", "SUNET", "pid", []statusEntry{
		{Section: 0, Index: 0, Allocated: apiv1_issuer.StatusAllocation_STATUS_ALLOCATION_NONE},
	}))
	require.Empty(t, store.saved, "nothing was allocated, so there is nothing to record")
}

// TestSaveCredentialSubjects_NoIdentifierIsNotRecorded: an issuance with
// no identifier AND no allocated entry has nothing to record.
//
// This used to assert that an ALLOCATED entry was silently skipped too,
// which was the defect - the credential carries the status reference either
// way, so skipping the mapping mints something the revoke endpoint can
// never find. That case is now
// TestSaveCredentialSubjects_AllocatedWithoutIdentifierIsRefused.
func TestSaveCredentialSubjects_NoIdentifierIsNotRecorded(t *testing.T) {
	c, store := persistenceClient(t, nil)

	require.NoError(t, c.saveCredentialSubjects(t.Context(), "", "SUNET", "pid", []statusEntry{{Section: 1, Index: 1}}))
	require.Empty(t, store.saved)
}

// TestSaveCredentialSubjects_ExternalEntriesAreNotMirrored: the registry's
// credential_subjects collection has a UNIQUE index on (section, index).
// That is correct for its own sharded list and wrong for anything else -
// every entry an external status service issues reports section 0, so the
// second one to land at any given index collides, either with another
// list's entry or with the registry's own entry at (0, index). The registry
// also refuses to act on entries it does not own, so mirroring them would
// add rows it can only display.
func TestSaveCredentialSubjects_ExternalEntriesAreNotMirrored(t *testing.T) {
	rec := &recordingRegistryClient{}
	c, store := persistenceClient(t, rec)

	require.NoError(t, c.saveCredentialSubjects(t.Context(), "person-1", "SUNET", "pid", []statusEntry{
		{Section: 0, Index: 17, URI: "https://status.example.com/statuslists/abc", Backend: "status_service"},
		{Section: 0, Index: 17, URI: "https://status.example.com/statuslists/def", Backend: "status_service"},
		{Section: 4, Index: 5, URI: "https://registry.example.com/statuslists/4", Backend: "registry"},
	}))

	require.Len(t, store.saved, 3, "all three are recorded authoritatively")
	require.Len(t, rec.saved, 1, "only the registry-backed entry may be mirrored")
	require.Equal(t, int64(4), rec.saved[0].Section)
	require.Equal(t, "https://registry.example.com/statuslists/4", rec.saved[0].StatusListURI)
}

// TestSaveCredentialSubjects_StoreFailureReleasesAllocations: the entries
// were allocated, and are VALID on their backend, before this runs. Failing
// without releasing them strands live slots that nothing points at - and
// since the caller may retry, every attempt would strand another set.
func TestSaveCredentialSubjects_StoreFailureReleasesAllocations(t *testing.T) {
	c, store, issuer := persistenceClientWithIssuer(t, nil)
	store.err = errors.New("database unavailable")

	err := c.saveCredentialSubjects(t.Context(), "person-1", "SUNET", "pid", []statusEntry{
		{Index: 17, URI: "https://status.example.com/statuslists/abc", Backend: "status_service"},
	})
	require.Error(t, err)

	require.Len(t, issuer.calls, 1, "an allocated entry that will never be issued must be released")
	require.Equal(t, uint32(1), issuer.calls[0].Status, "released entries are marked INVALID")
	require.Equal(t, "https://status.example.com/statuslists/abc", issuer.calls[0].StatusListUri)
	require.Equal(t, "status_service", issuer.calls[0].Backend, "released through the backend that allocated it")
}

// TestSaveCredentialSubjects_FailureReleasesEarlierEntriesToo: the request
// fails as a whole, so entries recorded before the failing one are stranded
// as well - no credential is delivered for any of them.
func TestSaveCredentialSubjects_FailureReleasesEarlierEntriesToo(t *testing.T) {
	c, store, issuer := persistenceClientWithIssuer(t, nil)
	store.failAfter = 1

	err := c.saveCredentialSubjects(t.Context(), "person-1", "SUNET", "pid", []statusEntry{
		{Section: 4, Index: 5, URI: "https://registry.example.com/statuslists/4", Backend: "registry"},
		{Index: 17, URI: "https://status.example.com/statuslists/abc", Backend: "status_service"},
	})
	require.Error(t, err)

	require.Len(t, issuer.calls, 2, "both the failing entry and the one already recorded must be released")
	released := map[string]bool{}
	for _, call := range issuer.calls {
		released[call.StatusListUri] = true
	}
	require.True(t, released["https://registry.example.com/statuslists/4"])
	require.True(t, released["https://status.example.com/statuslists/abc"])
}

// TestSaveCredentialSubjects_AllocatedWithoutIdentifierIsRefused: an empty
// identifier is legitimate for assertion- and datastore-backed issuance,
// but it is not a reason to drop an allocated entry. The credential already
// carries the status reference, so skipping the mapping mints something
// that looks revocable and that the revoke endpoint can never find.
func TestSaveCredentialSubjects_AllocatedWithoutIdentifierIsRefused(t *testing.T) {
	c, store, issuer := persistenceClientWithIssuer(t, nil)

	err := c.saveCredentialSubjects(t.Context(), "", "SUNET", "pid", []statusEntry{
		{Index: 17, URI: "https://status.example.com/statuslists/abc", Backend: "status_service"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "could never be revoked")
	require.Empty(t, store.saved)
	require.Len(t, issuer.calls, 1, "the allocated entry must be released, not stranded")
}

// TestSaveCredentialSubjects_NoIdentifierAndNoAllocationIsFine keeps the
// ordinary case: a flow that allocated nothing has nothing to record and
// nothing to fail over.
func TestSaveCredentialSubjects_NoIdentifierAndNoAllocationIsFine(t *testing.T) {
	c, store, issuer := persistenceClientWithIssuer(t, nil)

	require.NoError(t, c.saveCredentialSubjects(t.Context(), "", "SUNET", "pid", []statusEntry{{}}))
	require.Empty(t, store.saved)
	require.Empty(t, issuer.calls)
}

// TestSaveCredentialSubjects_FailureReleasesUnattemptedEntriesToo: the
// entries AFTER the failing one were allocated before the loop started;
// they are simply never reached. Releasing only the prefix leaked the tail
// of every failed batch, and since the caller may retry, each attempt leaks
// another.
func TestSaveCredentialSubjects_FailureReleasesUnattemptedEntriesToo(t *testing.T) {
	c, store, issuer := persistenceClientWithIssuer(t, nil)
	store.failAfter = 1

	err := c.saveCredentialSubjects(t.Context(), "person-1", "SUNET", "pid", []statusEntry{
		{Section: 4, Index: 5, URI: "https://registry.example.com/statuslists/4", Backend: "registry"},
		{Index: 17, URI: "https://status.example.com/statuslists/abc", Backend: "status_service"},
		{Index: 18, URI: "https://status.example.com/statuslists/def", Backend: "status_service"},
	})
	require.Error(t, err)

	released := map[string]bool{}
	for _, call := range issuer.calls {
		released[call.StatusListUri] = true
	}
	require.Len(t, issuer.calls, 3, "every allocated entry must be released, reached or not")
	require.True(t, released["https://registry.example.com/statuslists/4"], "recorded before the failure")
	require.True(t, released["https://status.example.com/statuslists/abc"], "the failing entry")
	require.True(t, released["https://status.example.com/statuslists/def"],
		"allocated but never reached - this is the one that used to leak")
}

// TestSaveCredentialSubjects_AllocatedWithoutURIIsRefused: an entry that was
// allocated and carries no URI has already been embedded in what the issuer
// signed, so continuing delivers a credential advertising a revocation status
// nothing can ever set. That used to be a warning and a `continue`.
func TestSaveCredentialSubjects_AllocatedWithoutURIIsRefused(t *testing.T) {
	c, store, issuer := persistenceClientWithIssuer(t, nil)

	err := c.saveCredentialSubjects(t.Context(), "person-1", "SUNET", "pid", []statusEntry{
		{Section: 3, Index: 9, Allocated: apiv1_issuer.StatusAllocation_STATUS_ALLOCATION_ALLOCATED},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "no list URI")
	require.Empty(t, store.saved)
	// Nothing can be released either - releasing names the list URI, which
	// is the thing that is missing - so the call is made and skips it.
	require.Empty(t, issuer.calls)
}

// TestSaveCredentialSubjects_AllocatedWithoutURIReleasesItsSiblings: the
// batch fails as a whole, so entries in it that DO have a URI must not be
// left VALID and unreferenced.
func TestSaveCredentialSubjects_AllocatedWithoutURIReleasesItsSiblings(t *testing.T) {
	c, _, issuer := persistenceClientWithIssuer(t, nil)

	err := c.saveCredentialSubjects(t.Context(), "person-1", "SUNET", "pid", []statusEntry{
		{Section: 3, Index: 9},
		{Index: 17, URI: "https://status.example.com/statuslists/abc", Backend: "status_service"},
	})
	require.Error(t, err)
	require.Len(t, issuer.calls, 1)
	require.Equal(t, "https://status.example.com/statuslists/abc", issuer.calls[0].StatusListUri)
}

// TestSaveCredentialSubjects_UnroutableBackendIsRefused: a URI with no
// routable backend fails the same way a backend with no URI does - the
// mapping can be written and never acted on. SetCredentialStatus refuses an
// unknown backend rather than guessing (guessing writes a status into the
// wrong list), so recording one mints a credential whose revocation call is
// rejected forever.
func TestSaveCredentialSubjects_UnroutableBackendIsRefused(t *testing.T) {
	for name, backend := range map[string]string{
		"empty":   "",
		"unknown": "some_future_service",
	} {
		t.Run(name, func(t *testing.T) {
			c, store, issuer := persistenceClientWithIssuer(t, nil)

			err := c.saveCredentialSubjects(t.Context(), "person-1", "SUNET", "pid", []statusEntry{
				{Index: 17, URI: "https://status.example.com/statuslists/abc", Backend: backend},
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), "not a backend this build can reach")
			require.Empty(t, store.saved, "an entry nothing could revoke must not be recorded")
			require.Len(t, issuer.calls, 1, "the allocation must be released, not stranded")
		})
	}
}

// TestSaveCredentialSubjects_FailureRollsBackRecordedMappings: releasing the
// allocations is only half of undoing a failed batch. The rows already
// written name credentials nobody received, and revoke-by-identifier would
// later act on them - reporting a revocation of something never issued,
// against an entry that has already been released.
func TestSaveCredentialSubjects_FailureRollsBackRecordedMappings(t *testing.T) {
	c, store, issuer := persistenceClientWithIssuer(t, nil)
	store.failAfter = 1

	err := c.saveCredentialSubjects(t.Context(), "person-1", "SUNET", "pid", []statusEntry{
		{Section: 4, Index: 5, URI: "https://registry.example.com/statuslists/4", Backend: "registry"},
		{Index: 17, URI: "https://status.example.com/statuslists/abc", Backend: "status_service"},
	})
	require.Error(t, err)

	require.Equal(t, []string{"https://registry.example.com/statuslists/4|5|registry"}, store.deleted,
		"the mapping written before the failure must be removed, addressed the way it is keyed")
	require.Len(t, issuer.calls, 2, "and both allocations are still released")
}

// TestSaveCredentialSubjects_SuccessRollsBackNothing is the other half, so
// the rollback is not simply deleting what it just wrote.
func TestSaveCredentialSubjects_SuccessRollsBackNothing(t *testing.T) {
	c, store, issuer := persistenceClientWithIssuer(t, nil)

	require.NoError(t, c.saveCredentialSubjects(t.Context(), "person-1", "SUNET", "pid", []statusEntry{
		{Index: 17, URI: "https://status.example.com/statuslists/abc", Backend: "status_service"},
	}))
	require.Empty(t, store.deleted)
	require.Empty(t, issuer.calls)
	require.Len(t, store.saved, 1)
}

// TestSaveCredentialSubjects_CleanupSurvivesARequestCancellation: a
// cancelled or timed-out request is one of the COMMON ways to reach the
// release path, and the cleanup used to inherit that context - so the
// release RPC and the mapping rollback were cancelled before they were
// sent, exactly when they mattered. The entries then stayed VALID and
// unreferenced although the code had tried to release them.
func TestSaveCredentialSubjects_CleanupSurvivesARequestCancellation(t *testing.T) {
	c, store, issuer := persistenceClientWithIssuer(t, nil)
	store.failAfter = 1

	ctx, cancel := context.WithCancel(t.Context())
	cancel() // the client hung up after the entries were allocated

	err := c.saveCredentialSubjects(ctx, "person-1", "SUNET", "pid", []statusEntry{
		{Section: 4, Index: 5, URI: "https://registry.example.com/statuslists/4", Backend: "registry"},
		{Index: 17, URI: "https://status.example.com/statuslists/abc", Backend: "status_service"},
	})
	require.Error(t, err)

	require.Len(t, issuer.calls, 2, "cancellation must not skip the release")
	for i, ctxErr := range issuer.ctxErrs {
		require.NoError(t, ctxErr, "release %d was sent on a context already cancelled by the caller", i)
	}

	require.NotEmpty(t, store.deleted, "the mapping written before the failure must be rolled back")
	for i, ctxErr := range store.deleteCtxErrs {
		require.NoError(t, ctxErr, "rollback %d was sent on a context already cancelled by the caller", i)
	}
}

// TestSaveCredentialSubjects_SilentIssuerIsRefused: an issuer that does not
// say whether it allocated anything cannot be read as having allocated
// nothing. A registry's FIRST allocation is section 0, index 0, and an issuer
// older than status_list_uri sends no URI and no backend either - byte-for-byte
// what "nothing was allocated" looks like. The apigw used to continue on that
// guess and deliver a credential whose status entry was never recorded, so
// revocation could never find it.
//
// A loud failure during a partial upgrade is the better half of that trade,
// and it is the only reading that does not require guessing.
func TestSaveCredentialSubjects_SilentIssuerIsRefused(t *testing.T) {
	c, store, issuer := persistenceClientWithIssuer(t, nil)

	// Exactly the ambiguous tuple: zero section, zero index, no URI, no
	// backend, and no statement either way.
	err := c.saveCredentialSubjects(t.Context(), "person-1", "SUNET", "pid", []statusEntry{{}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "did not report whether")
	require.Empty(t, store.saved, "nothing is recorded on a reply that cannot be trusted")
	require.Empty(t, issuer.calls, "and there is no URI to release it by")
}

// TestSaveCredentialSubjects_NoStoreReleasesAllocations: an apigw with no
// credential-status store still receives allocated entries from the issuer,
// because allocation is configured on the ISSUER and the two are separate
// deployments. The issuance fails here - correctly, the mapping is what
// revocation looks a credential up by - but the slots were already reserved
// and VALID, and this was the one failure path that returned without
// releasing them.
//
// It matters more than the other paths rather than less: the callers set
// saved = true before entering saveCredentialSubjects, deliberately handing
// cleanup over to it, and in a deployment configured this way EVERY batch
// takes this branch. The leak was the steady state, not an edge case.
func TestSaveCredentialSubjects_NoStoreReleasesAllocations(t *testing.T) {
	issuer := &recordingIssuer{}
	c := &Client{
		log:          logger.NewSimple("test"),
		issuerClient: issuer,
	}

	err := c.saveCredentialSubjects(t.Context(), "person-1", "SUNET", "pid", []statusEntry{
		{Section: 4, Index: 5, URI: "https://registry.example.com/statuslists/4", Backend: "registry"},
		{Index: 17, URI: "https://status.example.com/statuslists/abc", Backend: "status_service"},
	})
	require.Error(t, err, "an entry that cannot be recorded must not be issued")

	require.Len(t, issuer.calls, 2, "both allocated entries must be released, not just the one the loop reached")
	released := map[string]uint32{}
	for _, call := range issuer.calls {
		released[call.StatusListUri] = call.Status
	}
	require.Equal(t, uint32(1), released["https://registry.example.com/statuslists/4"], "released entries are marked INVALID")
	require.Equal(t, uint32(1), released["https://status.example.com/statuslists/abc"])
}
