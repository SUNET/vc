package mdoc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// defaultVegaVerifierKeyCacheBytes bounds what the Vega verifier-key store
// may hold ON DISK.
//
// A decompressed Vega verifier key is ~100MB, and the store is keyed by
// zkSystemID, so an unbounded one grows by that much for every distinct
// circuit revision the verifier is ever asked to verify against, and never
// gives any of it back.
//
// 512MiB, which is room for about five keys. Two would cover a clean
// rollover, and the extra headroom is deliberately cheap: this is a cap, not
// a reservation, so usage only reaches it if that many distinct revisions are
// genuinely in use. The scenario it buys off is the one that fails quietly -
// a working set one key larger than the cap makes every request evict the
// key the next one needs, so the store degrades to a full fetch per
// verification with no error and nothing in the logs but latency. Paying
// disk only in the case where the alternative is refetching 100MB per
// request is the right side of that trade.
//
// It is DISK rather than RSS since the keys moved out of the process (see
// vegaKeyStore), which is also why the default can afford to be generous:
// what used to be resident memory shared with everything else the verifier
// does is now a file the kernel pages in for the worker and drops again.
// Override it with verifier.zk_key_cache.max_bytes.
//
// The ceiling is PER PROCESS, not per deployment. Under Common.HA.Enable
// there are several verifier instances, each with its own store, so the
// footprint to size for is this times the instance count - and each
// instance only reaches it if it has actually served that many revisions.
const defaultVegaVerifierKeyCacheBytes = 512 << 20

// vegaKeyCache is the byte-bounded LRU accounting under vegaKeyStore. It
// tracks SIZES, not bytes: the bytes are files, and this decides which of
// them may stay.
//
// Deliberately not locked: it lives inside a struct that already holds a
// mutex covering both this and the in-flight-load bookkeeping beside it, and
// a second lock here would only invite the two to disagree. Callers hold
// that one. It is also in its own untagged file rather than beside its only
// caller, which is behind the zknative build tag - the eviction rule has no
// cgo in it, and a rule that cannot be exercised without the crate staged is
// a rule nobody checks.
//
// Deliberately outside pkg/cache and Common.HA, which is the convention for
// everything else the verifier caches (see internal/verifier/cache: HA backs
// those with MongoDB so instances share them). Two reasons, and the first is
// decisive:
//
//   - a value here cannot go in that backend. The Mongo store persists each
//     entry as a BSON document, and MongoDB caps those at 16MiB; a ~100MB
//     key exceeds it by an order of magnitude, and pkg/cache has no size
//     guard that would catch the attempt before it failed at runtime.
//   - sharing would not help even if it fit. These are immutable public
//     artifacts fetched from the circuit catalog, identical on every
//     instance, so a per-instance copy is not divergent state - it is the
//     same bytes, and pulling 100MB out of Mongo on a miss is strictly worse
//     than fetching from the catalog the miss would have gone to anyway.
//
// What HA does change is the footprint (see defaultVegaVerifierKeyCacheBytes)
// and that the in-flight dedup beside this is per process too: on a cold
// start or a circuit rollover, every instance fetches the artifact once,
// independently, rather than one fetching it for all of them. Pre-warming
// (WarmVegaVerifierKeys) moves that off the request path on each of them.
type vegaKeyCache struct {
	sizes map[string]int
	lru   []string // oldest first
	bytes int
	max   int
}

func newVegaKeyCache(max int) *vegaKeyCache {
	return &vegaKeyCache{sizes: make(map[string]int), max: max}
}

// get reports whether id is held, marking it most recently used.
func (c *vegaKeyCache) get(id string) (int, bool) {
	size, ok := c.sizes[id]
	if ok {
		c.touch(id)
	}
	return size, ok
}

// put records size under id and returns the ids evicted oldest-first to
// bring the total back inside the bound. The caller deletes their files.
//
// The entry just stored is never evicted here, even when it alone exceeds
// the bound: the caller is about to use it, and reporting an entry that was
// dropped on the way out would be a strange way to enforce a ceiling. It
// does not get to stay, though - see vegaKeyStore.put, which retires an
// oversized entry when its last holder lets go, so the bound is a real disk
// bound and not a target the first big artifact permanently overshoots.
func (c *vegaKeyCache) put(id string, size int) []string {
	if previous, ok := c.sizes[id]; ok {
		c.bytes -= previous
	}
	c.sizes[id] = size
	c.bytes += size
	c.touch(id)

	var evicted []string
	for c.bytes > c.max && len(c.lru) > 1 {
		oldest := c.lru[0]
		c.lru = c.lru[1:]
		c.bytes -= c.sizes[oldest]
		delete(c.sizes, oldest)
		evicted = append(evicted, oldest)
	}
	return evicted
}

// drop forgets id without evicting anything else, for the case where the
// file behind it turned out to be gone.
func (c *vegaKeyCache) drop(id string) {
	size, ok := c.sizes[id]
	if !ok {
		return
	}
	c.bytes -= size
	delete(c.sizes, id)
	for i, existing := range c.lru {
		if existing == id {
			c.lru = append(c.lru[:i:i], c.lru[i+1:]...)
			return
		}
	}
}

func (c *vegaKeyCache) touch(id string) {
	for i, existing := range c.lru {
		if existing == id {
			c.lru = append(append(c.lru[:i:i], c.lru[i+1:]...), id)
			return
		}
	}
	c.lru = append(c.lru, id)
}

// vegaKeyStore keeps decompressed Vega verifier keys as FILES and hands the
// worker a path instead of the bytes.
//
// The worker is a separate process, so the key has to cross a boundary
// however it is held. It used to cross as base64 inside the request JSON,
// which meant ~133MB encoded, written down a pipe and decoded again on EVERY
// verification - paid whether the cache hit or missed, so what the cache
// bought was the network fetch and nothing else (SUNET/vc#656). A path costs
// nothing to send, and the kernel's page cache does the sharing that the
// in-process copy was pretending to do.
//
// The directory is PROCESS-PRIVATE and removed when the process exits.
// Nothing is adopted from a previous run: a file sitting in that directory
// is a verifier key, and a verifier key decides which proofs verify, so
// trusting bytes this process did not itself hash-verify out of the catalog
// would be a poor trade for a cold start that pre-warming already removes.
type vegaKeyStore struct {
	mu sync.Mutex
	// parent is where dir gets created; "" means the OS temp directory.
	parent string
	// dir is this store's own directory, created on first write.
	dir     string
	cache   *vegaKeyCache
	entries map[string]*vegaKeyEntry
	// closed is set by removeAll. A store that has been torn down must not
	// quietly recreate its directory because a background pre-warm landed
	// a moment later and left key files behind after the process exited.
	closed bool
	// pins counts every outstanding hold across the WHOLE store, including
	// entries that have been retired out of the map while still in use.
	//
	// Counted here rather than summed over entries, because the entries
	// map is exactly where a retired-but-pinned key is NOT: retireLocked
	// removes it and leaves its file on disk for the last release. A
	// shutdown that scanned the map would see zero and delete the
	// directory out from under that worker - the failure the pinning
	// exists to prevent, reached through the one case where the entry is
	// gone and the file is not.
	pins int
}

// vegaKeyEntry is one key file and who is using it.
type vegaKeyEntry struct {
	path string
	size int
	// pins counts callers holding the path and not finished with it. The
	// worker is a separate process that opens the file ITSELF, some
	// milliseconds after being handed the path, so a concurrent load
	// evicting the file in that window makes a perfectly valid
	// presentation fail (SUNET/vc#656 review). A pinned entry is never
	// unlinked.
	pins int
	// evicted records that the LRU has given up on this entry while it was
	// still pinned. The file goes when the last holder releases it.
	evicted bool
}

// newVegaKeyStore returns a store that will create its directory under
// parent on first write. An empty parent means the OS temp directory.
func newVegaKeyStore(parent string, max int) *vegaKeyStore {
	return &vegaKeyStore{
		cache:   newVegaKeyCache(max),
		entries: make(map[string]*vegaKeyEntry),
		parent:  parent,
	}
}

// vegaKeyStoreDirPerm is 0700: the directory holds material that decides
// which proofs verify, so nothing but this process's user has any business
// reading or - far more to the point - writing it.
const vegaKeyStoreDirPerm = 0o700

// setMax changes the bound, evicting down to it.
func (s *vegaKeyStore) setMax(max int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cache.max = max
	s.evictDownLocked()
}

// evictDownLocked brings the accounting back inside the bound. Callers hold
// s.mu.
func (s *vegaKeyStore) evictDownLocked() {
	for s.cache.bytes > s.cache.max && len(s.cache.lru) > 1 {
		oldest := s.cache.lru[0]
		s.cache.lru = s.cache.lru[1:]
		s.cache.bytes -= s.cache.sizes[oldest]
		delete(s.cache.sizes, oldest)
		s.retireLocked(oldest)
	}
}

// retireLocked drops an entry from the store, deleting its file unless
// somebody is still using it. Callers hold s.mu.
func (s *vegaKeyStore) retireLocked(id string) {
	entry, ok := s.entries[id]
	if !ok {
		return
	}
	delete(s.entries, id)
	if entry.pins > 0 {
		// Still in use. Mark it and let the last release unlink the file;
		// until then it is off the books but still on disk, which is the
		// right way round - a verification in progress must not have its
		// key pulled out from under it.
		entry.evicted = true
		return
	}
	os.Remove(entry.path)
}

// acquire returns the path to id's key file and a function to call when the
// caller is done with it. The file will not be unlinked before then.
//
// A path whose file has gone - someone cleaned /tmp, a container restarted
// around a mounted directory - is reported as a miss and forgotten, not
// handed to the worker to fail on. The caller then refetches, which is the
// behaviour a cache is supposed to have.
func (s *vegaKeyStore) acquire(id string) (string, func(), bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// A closed store hands out nothing. Without this, removeAll's pin check
	// can see zero and a new acquire can pin an entry in the gap before
	// resetLocked - handing a worker a path that is about to disappear,
	// which is the failure the pinning exists to prevent arriving through
	// the door marked shutdown.
	if s.closed {
		return "", nil, false
	}

	entry, ok := s.entries[id]
	if !ok {
		return "", nil, false
	}
	if _, err := os.Stat(entry.path); err != nil {
		s.cache.drop(id)
		delete(s.entries, id)
		return "", nil, false
	}
	s.cache.get(id)
	entry.pins++
	s.pins++
	return entry.path, s.releaseFunc(id, entry), true
}

// releaseFunc returns the one-shot release for a pinned entry.
func (s *vegaKeyStore) releaseFunc(id string, entry *vegaKeyEntry) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			entry.pins--
			s.pins--
			if entry.pins > 0 || !entry.evicted {
				return
			}
			// Evicted while in use and now unused: this is the delete the
			// eviction pass deferred. Guarded on the PATH rather than the
			// entry, so that even if two generations somehow shared a file
			// name this could only ever unlink a file no current entry
			// claims. put gives every generation its own path, which makes
			// this guard redundant and worth keeping anyway - it is the
			// line that decides whether a live key gets deleted.
			if current, ok := s.entries[id]; !ok || current.path != entry.path {
				os.Remove(entry.path)
			}
		})
	}
}

// partition splits ids into those the store still holds and those it does
// not, under ONE lock.
//
// One lock because the answer is a snapshot and the server is serving
// while it is taken: id-by-id get calls can see a key evicted between two
// of them and report a set that was never true at any instant.
func (s *vegaKeyStore) partition(ids []string) (resident, missing []string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, id := range ids {
		if entry, ok := s.entries[id]; ok {
			if _, err := os.Stat(entry.path); err == nil {
				resident = append(resident, id)
				continue
			}
		}
		missing = append(missing, id)
	}
	return resident, missing
}

// get reports whether id is held and returns its path WITHOUT pinning it.
// For tests and for "is this warm?" questions; anything about to hand the
// path to a worker must use acquire.
func (s *vegaKeyStore) get(id string) (string, bool) {
	path, release, ok := s.acquire(id)
	if ok {
		release()
	}
	return path, ok
}

// put writes b to the store and returns its path, ALREADY PINNED - the
// caller is about to use it, and the release closes that window rather
// than leaving it open between writing the file and asking for it back.
//
// Written to a temporary name and renamed into place, so a concurrent
// reader - or a worker that has already been handed the path - never sees a
// half-written key. Rename within one directory is atomic on every
// filesystem this runs on.
func (s *vegaKeyStore) put(id string, b []byte) (string, func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return "", nil, errors.New("the Vega verifier key store has been closed")
	}
	if err := s.ensureDir(); err != nil {
		return "", nil, err
	}

	// A UNIQUE path per generation, not a deterministic one per id. Two
	// generations of the same circuit sharing a file name means the
	// rename below replaces a file an earlier, still-pinned holder was
	// about to open, and - worse - that holder's release then unlinks the
	// NEW generation's file, because the path it remembers is the path
	// that now belongs to somebody else. Uniqueness makes "this entry's
	// file" mean exactly one thing for the entry's whole life.
	//
	// CreateTemp supplies the uniqueness; the hashed id is kept as a
	// prefix so a directory listing is still readable.
	tmp, err := os.CreateTemp(s.dir, vegaKeyFileName(id)+".*")
	if err != nil {
		return "", nil, fmt.Errorf("creating a temporary file for Vega verifier key %q: %w", id, err)
	}
	tmpName := tmp.Name()
	path := tmpName + vegaKeyFileSuffix

	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return "", nil, fmt.Errorf("writing Vega verifier key %q: %w", id, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return "", nil, fmt.Errorf("closing Vega verifier key %q: %w", id, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return "", nil, fmt.Errorf("installing Vega verifier key %q: %w", id, err)
	}

	// Replacing an entry for the same id retires the old one, which may be
	// pinned by a verification already under way - its file then survives
	// until that release. Paths are unique per generation, so the two
	// never collide.
	if _, ok := s.entries[id]; ok {
		s.retireLocked(id)
	}

	entry := &vegaKeyEntry{path: path, size: len(b), pins: 1}
	s.pins++
	s.entries[id] = entry

	// Evict only AFTER the new entry is installed and pinned. The other
	// order can delete the file the caller is about to use, when the new
	// key alone exceeds the bound.
	for _, evicted := range s.cache.put(id, len(b)) {
		s.retireLocked(evicted)
	}

	// A key that alone exceeds the bound survived that pass - it had to,
	// the caller is about to read it - and used to survive forever after,
	// making max_bytes a target rather than the disk bound it is
	// documented as. Retire it NOW, which leaves the file in place while
	// pinned and deletes it on the last release.
	if len(b) > s.cache.max {
		s.cache.drop(id)
		s.retireLocked(id)
	}

	return path, s.releaseFunc(id, entry), nil
}

// ensureDir creates the store's own directory, once. Callers hold s.mu.
//
// A fresh subdirectory rather than writing straight into parent: the store
// owns what it creates and removes exactly that on the way out, so a
// configured key_cache_dir that happens to hold something else does not get
// swept up with it.
func (s *vegaKeyStore) ensureDir() error {
	if s.dir != "" {
		return nil
	}
	if s.parent != "" {
		if err := os.MkdirAll(s.parent, vegaKeyStoreDirPerm); err != nil {
			return fmt.Errorf("creating the Vega verifier key parent directory %s: %w", s.parent, err)
		}
	}
	dir, err := os.MkdirTemp(s.parent, "vc-vega-keys-")
	if err != nil {
		return fmt.Errorf("creating the Vega verifier key directory: %w", err)
	}
	// MkdirTemp is already 0700, but say so rather than depend on it.
	if err := os.Chmod(dir, vegaKeyStoreDirPerm); err != nil {
		return fmt.Errorf("securing the Vega verifier key directory: %w", err)
	}
	s.dir = dir
	return nil
}

// removeAll deletes the store's directory and everything in it, and closes
// the store so nothing recreates it afterwards.
//
// Waits, bounded by ctx, for any key still pinned by a verification in
// progress. Deleting the directory out from under one is the same failure
// eviction was taught to avoid, arriving at shutdown instead - and the
// window is real: the verifier's HTTP server only recently learned to stop
// accepting requests before this runs, and a handler that has the path but
// has not yet exec'd the worker is exactly the case.
//
// On timeout it deletes anyway and says so. The process is exiting; a
// verification that was going to fail because the process is going away
// will fail either way, and leaving half a gigabyte behind to avoid a
// doomed request is the worse trade.
func (s *vegaKeyStore) removeAll(ctx context.Context) error {
	s.mu.Lock()
	s.closed = true
	dir := s.dir
	s.mu.Unlock()

	if dir == "" {
		return nil
	}

	// closed is set above, BEFORE the wait: a store that is shutting down
	// stops handing out paths immediately, so the count below can only
	// fall.
	if pinned := s.waitForPins(ctx); pinned > 0 {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.resetLocked()
		if err := os.RemoveAll(dir); err != nil {
			return err
		}
		return fmt.Errorf("removed the Vega verifier key store with %d key(s) still in use", pinned)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.resetLocked()
	return os.RemoveAll(dir)
}

// vegaKeyStorePinPollInterval is how often removeAll re-checks for
// outstanding pins. Short: this runs once, at shutdown, and the thing it
// is waiting for is a subprocess that takes well under a second.
const vegaKeyStorePinPollInterval = 10 * time.Millisecond

// waitForPins blocks until no entry is pinned or ctx is done, returning
// how many were still pinned when it gave up (0 on a clean drain).
func (s *vegaKeyStore) waitForPins(ctx context.Context) int {
	for {
		pinned := s.pinnedCount()
		if pinned == 0 {
			return 0
		}
		select {
		case <-ctx.Done():
			return pinned
		case <-time.After(vegaKeyStorePinPollInterval):
		}
	}
}

func (s *vegaKeyStore) pinnedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pins
}

// resetLocked empties the store's bookkeeping. Callers hold s.mu.
func (s *vegaKeyStore) resetLocked() {
	s.entries = make(map[string]*vegaKeyEntry)
	s.cache = newVegaKeyCache(s.cache.max)
	s.dir = ""
	// pins is deliberately NOT cleared. Outstanding holds still exist and
	// their releases will decrement it; zeroing it here would make the
	// counter go negative and a second teardown read as "nothing pinned"
	// when something is.
}

// vegaKeyFileSuffix is appended to a store file's unique name. Cosmetic;
// the uniqueness comes from CreateTemp.
const vegaKeyFileSuffix = ".vk"

// vegaKeyFileName maps a catalog id to a file-name PREFIX. The suffix that
// makes the name unique comes from os.CreateTemp - see put for why two
// generations of one circuit must never share a path.
//
// Hashed rather than used directly: the id reaches here from a presented
// proof's zkSystemId. FetchCircuit refuses one that is not a flat token
// before any of this runs, but a file name derived from attacker-influenced
// input is the kind of thing that stays correct only as long as both ends
// agree, and a hash cannot contain a separator at all.
func vegaKeyFileName(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

// vegaVerifierKeys is the process-wide Vega verifier-key store.
//
// Process-wide rather than a field on ZkVerifierConfig because NewZkHandler
// is called INSIDE the request loop (see handlers_verification.go): a
// per-handler store would be created and thrown away per presentation,
// which is not a cache at all. That is also why the two knobs below are
// setters rather than config fields.
var vegaVerifierKeys = newVegaKeyStore("", defaultVegaVerifierKeyCacheBytes)

// SetVegaVerifierKeyCacheBytes changes the on-disk bound for the Vega
// verifier-key store, evicting down to it immediately.
//
// 512MiB (defaultVegaVerifierKeyCacheBytes) is sized for a five-revision
// working set. An operator facing more, or running many small pods on a
// shared disk, had no way to say so (SUNET/vc#656). A value of zero or less
// is ignored rather than treated as "cache nothing": a store that evicts
// every entry the moment it is written turns every verification into a
// 100MB fetch, and that is not something to arrive at by leaving a config
// field unset.
func SetVegaVerifierKeyCacheBytes(n int) {
	if n <= 0 {
		return
	}
	vegaVerifierKeys.setMax(n)
}

// SetVegaVerifierKeyCacheDir chooses where the store creates its directory.
//
// Call before anything triggers a load - at startup, from config. It has no
// effect once the directory exists, because moving a store that the worker
// may already hold paths into would be a race for no benefit; the default
// is the OS temp directory, which is right for almost everyone.
//
// Worth setting when the OS temp directory is small (a few hundred MB of
// keys is a lot for a tmpfs) or when it is on memory-backed storage, where
// the whole point of moving the keys out of the process is lost.
func SetVegaVerifierKeyCacheDir(dir string) {
	if dir == "" {
		return
	}
	vegaVerifierKeys.mu.Lock()
	defer vegaVerifierKeys.mu.Unlock()
	if vegaVerifierKeys.dir != "" {
		return
	}
	vegaVerifierKeys.parent = dir
}

// VegaVerifierKeyCacheBytes reports the store's current on-disk bound, so
// a caller that has just configured it can confirm what took effect
// (nothing else in the process can see the store at all).
func VegaVerifierKeyCacheBytes() int {
	vegaVerifierKeys.mu.Lock()
	defer vegaVerifierKeys.mu.Unlock()
	return vegaVerifierKeys.cache.max
}

// CloseVegaVerifierKeyStore deletes the store's directory and everything in
// it, waiting (bounded by ctx) for any key a verification still has pinned.
//
// For a clean shutdown; the OS would get the temp directory eventually, but
// "eventually" is not a promise worth making about half a gigabyte, and a
// configured key_cache_dir it would not get at all.
func CloseVegaVerifierKeyStore(ctx context.Context) error {
	return vegaVerifierKeys.removeAll(ctx)
}

// isVegaCatalogSystem reports whether a catalog descriptor's System names
// a zk-cred-vega circuit - the only kind this store holds keys for.
//
// Separate from isVegaSystem in zk_verifier.go, which answers the same
// question about a DCQL zk_system_type entry on the VERIFY path. Same
// vegaSystemPrefix, different input: that one takes a request spec and
// falls back to the presented id, which has nothing to say here.
func isVegaCatalogSystem(system string) bool {
	return strings.HasPrefix(system, vegaSystemPrefix)
}

// VegaWarmResult reports what WarmVegaVerifierKeys managed to do.
type VegaWarmResult struct {
	// Warmed are the prover-key catalog ids whose verifier keys are on
	// disk WHEN THE WARM-UP FINISHED, ready for the first presentation
	// that names them.
	//
	// Residency at the end, not a count of successful loads: the store is
	// bounded, so a working set larger than max_bytes means later circuits
	// evict earlier ones, and reporting the loads would claim keys are
	// ready that the first presentation has to refetch.
	Warmed []string
	// Evicted are ids that loaded and did not survive - the working set
	// does not fit in max_bytes. Nothing is broken; the keys load lazily
	// as before, and every request pays for one. The only visible symptom
	// otherwise is latency, which is why this is reported separately
	// rather than folded into Warmed or Failed.
	Evicted []string
	// Failed maps a prover-key id to why warming it did not work. A
	// failure here is not fatal: the key loads lazily on first use exactly
	// as it did before, the caller simply pays for it then.
	Failed map[string]error
}

// vegaProverRoleParam is the catalog params key and value identifying a
// prover-key entry. zk-cred-vega publishes separate prover and verifier
// entries for one circuit revision; the wallet names the PROVER id in its
// proof, which is what the store is keyed by.
const (
	vegaRoleParam  = "role"
	vegaRoleProver = "prover"

	// vegaStatusActive is the only catalog status worth warming. A
	// deprecated revision still presents - wallets update on their own
	// schedule - and still loads lazily on first use; warming every
	// revision ever published would grow without bound for the sake of a
	// request that may never come.
	vegaStatusActive = "active"
)
