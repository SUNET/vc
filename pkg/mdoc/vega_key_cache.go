package mdoc

// maxVegaVerifierKeyCacheBytes bounds what vegaKeyCache may hold.
//
// A decompressed Vega verifier key is ~100MB, and the cache is keyed by
// zkSystemID, so an unbounded one grows the verifier's RSS permanently by
// that much for every distinct circuit revision it is ever asked to verify
// against, and never gives any of it back. 256MiB leaves room for two
// revisions in flight - what a circuit rollover needs - while keeping the
// ceiling a number someone can reason about when sizing the process.
const maxVegaVerifierKeyCacheBytes = 256 << 20

// vegaKeyCache is a byte-bounded LRU of decompressed verifier-key blobs.
//
// Deliberately not locked: it lives inside a struct that already holds a
// mutex covering both this and the in-flight-load bookkeeping beside it, and
// a second lock here would only invite the two to disagree. Callers hold
// that one. It is also in its own untagged file rather than beside its only
// caller, which is behind the zknative build tag - the eviction rule has no
// cgo in it, and a rule that cannot be exercised without the crate staged is
// a rule nobody checks.
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
