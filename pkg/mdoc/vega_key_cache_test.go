package mdoc

import "testing"

func blob(n int) []byte { return make([]byte, n) }

func TestVegaKeyCacheEviction(t *testing.T) {
	t.Run("evicts oldest first once the bound is passed", func(t *testing.T) {
		c := newVegaKeyCache(300)
		c.put("a", blob(100))
		c.put("b", blob(100))
		c.put("c", blob(100))
		if c.bytes != 300 {
			t.Fatalf("expected 300 bytes held, got %d", c.bytes)
		}

		c.put("d", blob(100)) // 400 > 300, so "a" goes
		if _, ok := c.byID["a"]; ok {
			t.Fatal("the oldest entry should have been evicted")
		}
		if c.bytes != 300 {
			t.Fatalf("expected the bound to be restored, got %d bytes", c.bytes)
		}
	})

	t.Run("a read makes an entry the newest", func(t *testing.T) {
		c := newVegaKeyCache(300)
		c.put("a", blob(100))
		c.put("b", blob(100))
		c.put("c", blob(100))

		if _, ok := c.get("a"); !ok {
			t.Fatal("a should still be cached")
		}
		c.put("d", blob(100)) // "b" is now the oldest, not "a"

		if _, ok := c.byID["a"]; !ok {
			t.Fatal("a was just read and must survive")
		}
		if _, ok := c.byID["b"]; ok {
			t.Fatal("b was the least recently used and should have gone")
		}
	})

	t.Run("re-putting the same id does not double-count", func(t *testing.T) {
		c := newVegaKeyCache(1000)
		c.put("a", blob(100))
		c.put("a", blob(250))
		if c.bytes != 250 {
			t.Fatalf("expected the replacement to be counted once, got %d", c.bytes)
		}
		if len(c.lru) != 1 {
			t.Fatalf("expected one entry in the lru, got %d", len(c.lru))
		}
	})

	t.Run("a single oversized entry is kept", func(t *testing.T) {
		// The caller is about to use it - handing back bytes evicted on the
		// way out would be a strange way to enforce a ceiling.
		c := newVegaKeyCache(100)
		c.put("huge", blob(500))
		if _, ok := c.get("huge"); !ok {
			t.Fatal("the only entry must be kept even when it exceeds the bound")
		}
	})

	t.Run("an oversized entry still evicts what came before it", func(t *testing.T) {
		c := newVegaKeyCache(100)
		c.put("small", blob(50))
		c.put("huge", blob(500))
		if _, ok := c.byID["small"]; ok {
			t.Fatal("the older entry should have been evicted to make room")
		}
		if c.bytes != 500 {
			t.Fatalf("expected only the new entry counted, got %d", c.bytes)
		}
	})

	t.Run("the real bound holds a plausible working set", func(t *testing.T) {
		// ~100MB each. Two cover a clean rollover; the headroom is for a
		// wallet population straddling more than two revisions, which is
		// where a tight bound would thrash instead of cache.
		c := newVegaKeyCache(maxVegaVerifierKeyCacheBytes)
		for _, id := range []string{"r10", "r11", "r12", "r13", "r14"} {
			c.put(id, blob(100<<20))
		}
		for _, id := range []string{"r10", "r11", "r12", "r13", "r14"} {
			if _, ok := c.byID[id]; !ok {
				t.Fatalf("%s should still be cached inside the bound", id)
			}
		}
		// Still bounded, though: a sixth evicts the oldest.
		c.put("r15", blob(100<<20))
		if _, ok := c.byID["r10"]; ok {
			t.Fatal("the bound must still evict - this is a cap, not unbounded growth")
		}
	})
}
