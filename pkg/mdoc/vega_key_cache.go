package mdoc

// maxVegaVerifierKeyCacheBytes bounds what vegaKeyCache may hold.
//
// A decompressed Vega verifier key is ~100MB, and the cache is keyed by
// zkSystemID, so an unbounded one grows the verifier's RSS permanently by
// that much for every distinct circuit revision it is ever asked to verify
// against, and never gives any of it back.
//
// 512MiB, which is room for about five keys. Two would cover a clean
// rollover, and the extra headroom is deliberately cheap: this is a cap, not
// a reservation, so RSS only reaches it if that many distinct revisions are
// genuinely in use. The scenario it buys off is the one that fails quietly -
// a working set one key larger than the cap makes every request evict the
// key the next one needs, so the cache degrades to a full fetch per
// verification with no error and nothing in the logs but latency. Paying
// memory only in the case where the alternative is refetching 100MB per
// request is the right side of that trade.
//
// The ceiling is PER PROCESS, not per deployment. Under Common.HA.Enable
// there are several verifier instances, each with its own copy of this
// cache, so the footprint to size for is this times the instance count -
// and each instance only reaches it if it has actually served that many
// revisions.
const maxVegaVerifierKeyCacheBytes = 512 << 20

// vegaKeyCache is a byte-bounded LRU of decompressed verifier-key blobs.
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
// What HA does change is the footprint (see maxVegaVerifierKeyCacheBytes)
// and that the in-flight dedup beside this is per process too: on a cold
// start or a circuit rollover, every instance fetches the artifact once,
// independently, rather than one fetching it for all of them.
type vegaKeyCache struct {
	byID  map[string][]byte
	lru   []string // oldest first
	bytes int
	max   int
}

func newVegaKeyCache(max int) *vegaKeyCache {
	return &vegaKeyCache{byID: make(map[string][]byte), max: max}
}

// get returns the cached bytes for id, marking it most recently used.
func (c *vegaKeyCache) get(id string) ([]byte, bool) {
	b, ok := c.byID[id]
	if ok {
		c.touch(id)
	}
	return b, ok
}

// put caches b under id and evicts oldest-first until the total fits.
//
// The entry just stored is never evicted, even when it alone exceeds the
// bound: the caller is about to use it, and handing back bytes that were
// dropped on the way out would be a strange way to enforce a ceiling. A
// single key larger than max therefore exceeds it, by design, for as long as
// it is the only one held.
func (c *vegaKeyCache) put(id string, b []byte) {
	if previous, ok := c.byID[id]; ok {
		c.bytes -= len(previous)
	}
	c.byID[id] = b
	c.bytes += len(b)
	c.touch(id)

	for c.bytes > c.max && len(c.lru) > 1 {
		oldest := c.lru[0]
		c.lru = c.lru[1:]
		c.bytes -= len(c.byID[oldest])
		delete(c.byID, oldest)
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
