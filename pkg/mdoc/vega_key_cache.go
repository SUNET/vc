package mdoc

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
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
// Override it with verifier.zk_circuits.key_cache_bytes.
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
// The entry just stored is never evicted, even when it alone exceeds the
// bound: the caller is about to use it, and reporting an entry that was
// dropped on the way out would be a strange way to enforce a ceiling. A
// single key larger than max therefore exceeds it, by design, for as long as
// it is the only one held.
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
	dir   string
	cache *vegaKeyCache
	paths map[string]string
}

// newVegaKeyStore returns a store that will create its directory under
// parent on first write. An empty parent means the OS temp directory.
func newVegaKeyStore(parent string, max int) *vegaKeyStore {
	return &vegaKeyStore{
		cache:  newVegaKeyCache(max),
		paths:  make(map[string]string),
		parent: parent,
	}
}

// vegaKeyStoreDirPerm is 0700: the directory holds material that decides
// which proofs verify, so nothing but this process's user has any business
// reading or - far more to the point - writing it.
const vegaKeyStoreDirPerm = 0o700

// setMax changes the bound, evicting down to it. Safe to call before any
// write; see SetVegaVerifierKeyCacheBytes.
func (s *vegaKeyStore) setMax(max int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cache.max = max
	for s.cache.bytes > s.cache.max && len(s.cache.lru) > 1 {
		oldest := s.cache.lru[0]
		s.cache.lru = s.cache.lru[1:]
		s.cache.bytes -= s.cache.sizes[oldest]
		delete(s.cache.sizes, oldest)
		s.removeFile(oldest)
	}
}

// get returns the path to id's key file, or ok=false.
//
// A path whose file has gone - someone cleaned /tmp, a container restarted
// around a mounted directory - is reported as a miss and forgotten, not
// handed to the worker to fail on. The caller then refetches, which is the
// behaviour a cache is supposed to have.
func (s *vegaKeyStore) get(id string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	path, ok := s.paths[id]
	if !ok {
		return "", false
	}
	if _, err := os.Stat(path); err != nil {
		s.cache.drop(id)
		delete(s.paths, id)
		return "", false
	}
	s.cache.get(id)
	return path, true
}

// put writes b to the store and returns its path.
//
// Written to a temporary name and renamed into place, so a concurrent
// reader - or a worker that has already been handed the path - never sees a
// half-written key. Rename within one directory is atomic on every
// filesystem this runs on.
func (s *vegaKeyStore) put(id string, b []byte) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureDir(); err != nil {
		return "", err
	}

	path := filepath.Join(s.dir, vegaKeyFileName(id))
	tmp, err := os.CreateTemp(s.dir, ".vk-*")
	if err != nil {
		return "", fmt.Errorf("creating a temporary file for Vega verifier key %q: %w", id, err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return "", fmt.Errorf("writing Vega verifier key %q: %w", id, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return "", fmt.Errorf("closing Vega verifier key %q: %w", id, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return "", fmt.Errorf("installing Vega verifier key %q: %w", id, err)
	}

	// Evict only AFTER the new entry is installed. The other order can
	// delete the file the caller is about to use, when the new key alone
	// exceeds the bound.
	for _, evicted := range s.cache.put(id, len(b)) {
		s.removeFile(evicted)
	}
	s.paths[id] = path
	return path, nil
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

func (s *vegaKeyStore) removeFile(id string) {
	if path, ok := s.paths[id]; ok {
		os.Remove(path)
		delete(s.paths, id)
	}
}

// removeAll deletes the store's directory and everything in it.
func (s *vegaKeyStore) removeAll() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.dir == "" {
		return nil
	}
	dir := s.dir
	s.paths = make(map[string]string)
	s.cache = newVegaKeyCache(s.cache.max)
	s.dir = ""
	return os.RemoveAll(dir)
}

// vegaKeyFileName maps a catalog id to a file name.
//
// Hashed rather than used directly: the id reaches here from a presented
// proof's zkSystemId. FetchCircuit refuses one that is not a flat token
// before any of this runs, but a file name derived from attacker-influenced
// input is the kind of thing that stays correct only as long as both ends
// agree, and a hash cannot contain a separator at all.
func vegaKeyFileName(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:]) + ".vk"
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
// it. For a clean shutdown; the OS would get the temp directory eventually,
// but "eventually" is not a promise worth making about half a gigabyte.
func CloseVegaVerifierKeyStore() error {
	return vegaVerifierKeys.removeAll()
}

// VegaWarmResult reports what WarmVegaVerifierKeys managed to do.
type VegaWarmResult struct {
	// Warmed are the prover-key catalog ids whose verifier keys are now on
	// disk, ready for the first presentation that names them.
	Warmed []string
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
