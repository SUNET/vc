package tokenstatuslistissuer

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/SUNET/vc/internal/registry/cache"
	"github.com/SUNET/vc/internal/registry/db"
)

// fakeTokenStatusListStore is a minimal db.TokenStatusListStore whose
// GetAllStatusesForSection can be made to block for as long as the test wants,
// standing in for the full-section fetch that (per the benchmark run against a
// real MongoDB instance with a realistic 1,000,000-entry section) takes on the
// order of 15-20 seconds in a production-sized deployment.
type fakeTokenStatusListStore struct {
	// blockGetAll, if non-nil, is read from GetAllStatusesForSection before it
	// returns. The test controls when it's closed to simulate the slow fetch
	// finishing.
	blockGetAll chan struct{}
	// entered is closed the first time GetAllStatusesForSection is called, so the
	// test can deterministically wait for the background refresh to have started
	// before asserting anything about how long it's blocked for.
	entered chan struct{}

	statuses []uint8
}

func (f *fakeTokenStatusListStore) CountAll(ctx context.Context) (int64, error) { return 0, nil }

func (f *fakeTokenStatusListStore) CountDecoysInSectionWithLimit(ctx context.Context, section int64, limit int64) (int64, error) {
	// Report plenty of remaining decoys so CreateNewSectionIfNeeded never tries
	// to create a new section.
	return 2000, nil
}

func (f *fakeTokenStatusListStore) CreateNewSection(ctx context.Context, section int64, sectionSize int64) error {
	return nil
}

func (f *fakeTokenStatusListStore) Add(ctx context.Context, section int64, status uint8) (int64, error) {
	return 42, nil
}

func (f *fakeTokenStatusListStore) UpdateStatus(ctx context.Context, section int64, index int64, status uint8) error {
	return nil
}

func (f *fakeTokenStatusListStore) GetAllStatusesForSection(ctx context.Context, section int64) ([]uint8, error) {
	if f.entered != nil {
		select {
		case <-f.entered:
		default:
			close(f.entered)
		}
	}
	if f.blockGetAll != nil {
		<-f.blockGetAll
	}
	return f.statuses, nil
}

func (f *fakeTokenStatusListStore) InitializeIfEmpty(ctx context.Context) error { return nil }

func (f *fakeTokenStatusListStore) FindOne(ctx context.Context, section, index int64) (*db.TokenStatusListDoc, error) {
	return &db.TokenStatusListDoc{Index: index, Section: section}, nil
}

type fakeTokenStatusListMetadataStore struct{}

func (f *fakeTokenStatusListMetadataStore) GetCurrentSection(ctx context.Context) (int64, error) {
	return 0, nil
}

func (f *fakeTokenStatusListMetadataStore) UpdateCurrentSection(ctx context.Context, newSection int64) error {
	return nil
}

func (f *fakeTokenStatusListMetadataStore) GetAllSections(ctx context.Context) ([]int64, error) {
	return []int64{0}, nil
}

// newAsyncTestSuite builds a Service backed by fake, in-memory stores instead of a
// real MongoDB testcontainer. This lets the test control exactly how long a
// "full section fetch" takes (via fakeTokenStatusListStore.blockGetAll) without
// depending on real Mongo timing, which would otherwise make a test that proves
// AddStatus doesn't block on it either slow (a real 1M-entry section) or flaky
// (a smaller one, with no reliable margin between "fast" and "slow").
func newAsyncTestSuite(t *testing.T, store *fakeTokenStatusListStore) *testSuite {
	// Unlike the other suites in this file, this one needs neither Docker nor a
	// real MongoDB: cache.New only touches Mongo when HA is enabled (default:
	// disabled), and Service.New only needs a signing key file plus the fake
	// stores constructed below.
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	suite := &testSuite{t: t, ctx: ctx, cancel: cancel}
	suite.generateSigningKey()
	suite.initializeConfiguration()
	suite.initializeLogging()
	suite.initializeTracing()

	suite.dbService = &db.Service{
		TokenStatusListColl:     store,
		TokenStatusListMetadata: &fakeTokenStatusListMetadataStore{},
	}

	var err error
	suite.cacheService, err = cache.New(ctx, suite.cfg, suite.dbService, suite.tracer, suite.log)
	require.NoError(t, err)

	return suite
}

func (s *testSuite) cleanupAsync() {
	s.cancel()
}

// TestAddStatus_DoesNotBlockOnSlowCacheRefresh is a regression test for the root
// cause of the "minting a credential takes ~20 seconds" report: AddStatus used to
// call refreshSection synchronously, which re-fetches every entry in the section
// (up to SectionSize, default 1,000,000) and re-signs the JWT/CWT representations
// before returning. Benchmarked against a real MongoDB instance with a realistic
// 1,000,000-entry section (the config default), that full fetch alone took ~15-20
// seconds even though it's fully served by the section+index index (no missing
// index, no collection scan) -- the cost is simply transferring and decoding a
// million documents on every single credential issuance.
//
// This test simulates that slow fetch deterministically (via a store whose
// GetAllStatusesForSection blocks until the test releases it) and asserts that
// AddStatus returns quickly regardless, then that the cache still eventually
// catches up once the slow refresh completes. Before the fix, this test would
// block for the full duration of blockGetAll instead of returning almost
// immediately.
func TestAddStatus_DoesNotBlockOnSlowCacheRefresh(t *testing.T) {
	store := &fakeTokenStatusListStore{
		blockGetAll: make(chan struct{}),
		entered:     make(chan struct{}),
		statuses:    []uint8{0, 1, 2},
	}
	suite := newAsyncTestSuite(t, store)
	defer suite.cleanupAsync()

	service, err := New(suite.ctx, suite.cfg, suite.cacheService, suite.dbService, suite.log)
	require.NoError(t, err)
	defer service.Close(suite.ctx)

	// Wait for the initial startup refresh (refreshLoop's immediate
	// refreshAllSections call) to have entered GetAllStatusesForSection and
	// blocked, so we know AddStatus below is genuinely racing a slow refresh
	// rather than running before one ever started.
	select {
	case <-store.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for initial refresh to start")
	}

	start := time.Now()
	section, index, err := service.AddStatus(suite.ctx, 0)
	elapsed := time.Since(start)
	require.NoError(t, err)
	assert.Equal(t, int64(0), section)
	assert.Equal(t, int64(42), index)

	// The slow refresh (store.blockGetAll) is still blocked at this point. If
	// AddStatus still refreshed the cache synchronously, this would take at
	// least as long as the refresh is blocked for. We assert a generous but
	// meaningful bound: comfortably above normal scheduling noise, comfortably
	// below the multi-second refresh this test deliberately never unblocks
	// until after AddStatus has already returned.
	assert.Less(t, elapsed, 2*time.Second,
		"AddStatus should not block on the (still in-progress) cache refresh")

	// Cache must not be populated yet -- the refresh is still blocked.
	assert.Empty(t, service.GetCachedJWT(suite.ctx, section))

	// Now let the slow refresh finish and confirm the cache does eventually
	// catch up, proving the async refresh isn't just dropped.
	close(store.blockGetAll)

	require.Eventually(t, func() bool {
		return service.GetCachedJWT(suite.ctx, section) != ""
	}, 5*time.Second, 50*time.Millisecond, "cache should be populated once the background refresh completes")
}
