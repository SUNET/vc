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
func TestSaveCredentialSubjects_NoAllocationIsNotRecorded(t *testing.T) {
	c, store := persistenceClient(t, nil)

	require.NoError(t, c.saveCredentialSubjects(t.Context(), "person-3", "SUNET", "pid", []statusEntry{{Section: 0, Index: 0}}))
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

// TestSaveCredentialSubjects_AllocatedWithoutURIIsRefused: an issuer older
// than the status_list_uri field returns a section and an index and no URI.
// It has already embedded that entry in what it signed, so continuing
// delivers a credential advertising a revocation status nothing can ever
// set. That used to be a warning and a `continue`.
func TestSaveCredentialSubjects_AllocatedWithoutURIIsRefused(t *testing.T) {
	c, store, issuer := persistenceClientWithIssuer(t, nil)

	err := c.saveCredentialSubjects(t.Context(), "person-1", "SUNET", "pid", []statusEntry{
		{Section: 3, Index: 9},
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
