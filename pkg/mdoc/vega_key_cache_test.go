package mdoc

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVegaKeyCacheEviction(t *testing.T) {
	t.Run("evicts oldest first once the bound is passed", func(t *testing.T) {
		c := newVegaKeyCache(300)
		c.put("a", 100)
		c.put("b", 100)
		c.put("c", 100)
		if c.bytes != 300 {
			t.Fatalf("expected 300 bytes held, got %d", c.bytes)
		}

		c.put("d", 100) // 400 > 300, so "a" goes
		if _, ok := c.sizes["a"]; ok {
			t.Fatal("the oldest entry should have been evicted")
		}
		if c.bytes != 300 {
			t.Fatalf("expected the bound to be restored, got %d bytes", c.bytes)
		}
	})

	t.Run("a read makes an entry the newest", func(t *testing.T) {
		c := newVegaKeyCache(300)
		c.put("a", 100)
		c.put("b", 100)
		c.put("c", 100)

		if _, ok := c.get("a"); !ok {
			t.Fatal("a should still be cached")
		}
		c.put("d", 100) // "b" is now the oldest, not "a"

		if _, ok := c.sizes["a"]; !ok {
			t.Fatal("a was just read and must survive")
		}
		if _, ok := c.sizes["b"]; ok {
			t.Fatal("b was the least recently used and should have gone")
		}
	})

	t.Run("re-putting the same id does not double-count", func(t *testing.T) {
		c := newVegaKeyCache(1000)
		c.put("a", 100)
		c.put("a", 250)
		if c.bytes != 250 {
			t.Fatalf("expected the replacement to be counted once, got %d", c.bytes)
		}
		if len(c.lru) != 1 {
			t.Fatalf("expected one entry in the lru, got %d", len(c.lru))
		}
	})

	t.Run("a single oversized entry is kept", func(t *testing.T) {
		// The caller is about to use it - reporting an entry dropped on the
		// way out would be a strange way to enforce a ceiling.
		c := newVegaKeyCache(100)
		c.put("huge", 500)
		if _, ok := c.get("huge"); !ok {
			t.Fatal("the only entry must be kept even when it exceeds the bound")
		}
	})

	t.Run("an oversized entry still evicts what came before it", func(t *testing.T) {
		c := newVegaKeyCache(100)
		c.put("small", 50)
		c.put("huge", 500)
		if _, ok := c.sizes["small"]; ok {
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
		c := newVegaKeyCache(defaultVegaVerifierKeyCacheBytes)
		for _, id := range []string{"r10", "r11", "r12", "r13", "r14"} {
			c.put(id, 100<<20)
		}
		for _, id := range []string{"r10", "r11", "r12", "r13", "r14"} {
			if _, ok := c.sizes[id]; !ok {
				t.Fatalf("%s should still be cached inside the bound", id)
			}
		}
		// Still bounded, though: a sixth evicts the oldest.
		c.put("r15", 100<<20)
		if _, ok := c.sizes["r10"]; ok {
			t.Fatal("the bound must still evict - this is a cap, not unbounded growth")
		}
	})
}

// put reports what it evicted, because the store has to delete those files
// and a count it cannot act on is no use.
func TestVegaKeyCacheReportsWhatItEvicted(t *testing.T) {
	c := newVegaKeyCache(300)
	c.put("a", 100)
	c.put("b", 100)

	evicted := c.put("c", 250)
	if len(evicted) != 2 || evicted[0] != "a" || evicted[1] != "b" {
		t.Fatalf("evicted = %v, want [a b] in oldest-first order", evicted)
	}
	if c.bytes != 250 {
		t.Errorf("bytes = %d, want 250", c.bytes)
	}
}

func TestVegaKeyCacheDropForgetsOneEntry(t *testing.T) {
	c := newVegaKeyCache(300)
	c.put("a", 100)
	c.put("b", 100)

	c.drop("a")
	if _, ok := c.sizes["a"]; ok {
		t.Error("a should be gone")
	}
	if c.bytes != 100 {
		t.Errorf("bytes = %d, want 100", c.bytes)
	}
	if len(c.lru) != 1 || c.lru[0] != "b" {
		t.Errorf("lru = %v, want [b]", c.lru)
	}
	// Dropping something absent is a no-op, not a corruption of the total.
	c.drop("nonesuch")
	if c.bytes != 100 {
		t.Errorf("bytes = %d after dropping an absent id, want 100", c.bytes)
	}
}

func TestVegaKeyStoreRoundTrip(t *testing.T) {
	s := newVegaKeyStore(t.TempDir(), 1000)
	t.Cleanup(func() { _ = s.removeAll() })

	if _, ok := s.get("a"); ok {
		t.Fatal("an empty store should hold nothing")
	}

	path, releasePath, err := s.put("a", []byte("key material"))
	if err != nil {
		t.Fatal(err)
	}
	releasePath()

	got, ok := s.get("a")
	if !ok || got != path {
		t.Fatalf("get() = %q, %v; want %q, true", got, ok, path)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "key material" {
		t.Fatalf("file contents = %q, %v", data, err)
	}
	// 0700 on the directory: the file decides which proofs verify, so
	// nothing but this process's user has any business writing it.
	info, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != vegaKeyStoreDirPerm {
		t.Errorf("directory mode = %o, want %o", perm, vegaKeyStoreDirPerm)
	}
}

// Eviction has to delete the file, or the bound is accounting fiction and
// the disk fills up anyway.
func TestVegaKeyStoreEvictionDeletesTheFile(t *testing.T) {
	s := newVegaKeyStore(t.TempDir(), 10)
	t.Cleanup(func() { _ = s.removeAll() })

	oldPath, releaseOldpath, err := s.put("a", make([]byte, 8))
	if err != nil {
		t.Fatal(err)
	}
	releaseOldpath()
	if _, release, err := s.put("b", make([]byte, 8)); err != nil {
		t.Fatal(err)
	} else {
		release()
	}

	if _, ok := s.get("a"); ok {
		t.Error("a should have been evicted")
	}
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Errorf("the evicted key's file is still on disk at %s (%v)", oldPath, err)
	}
}

// The entry just stored is the one the caller is about to hand to the
// worker, so it must survive its own eviction pass even when it alone
// exceeds the bound.
func TestVegaKeyStoreKeepsTheEntryItJustWrote(t *testing.T) {
	s := newVegaKeyStore(t.TempDir(), 10)
	t.Cleanup(func() { _ = s.removeAll() })

	path, releasePath, err := s.put("huge", make([]byte, 500))
	if err != nil {
		t.Fatal(err)
	}
	releasePath()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the key just written must still be on disk: %v", err)
	}
	if got, ok := s.get("huge"); !ok || got != path {
		t.Fatalf("get() = %q, %v; want %q, true", got, ok, path)
	}
}

// A key file that has gone - someone cleaned the directory, a container
// restarted around a mount - must read as a miss so the caller refetches,
// not as a path the worker then fails to open.
func TestVegaKeyStoreTreatsAMissingFileAsAMiss(t *testing.T) {
	s := newVegaKeyStore(t.TempDir(), 1000)
	t.Cleanup(func() { _ = s.removeAll() })

	path, releasePath, err := s.put("a", []byte("key material"))
	if err != nil {
		t.Fatal(err)
	}
	releasePath()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	if _, ok := s.get("a"); ok {
		t.Fatal("a key whose file is gone must not be reported as cached")
	}
	if s.cache.bytes != 0 {
		t.Errorf("bytes = %d, want 0 - the accounting has to forget it too", s.cache.bytes)
	}
}

func TestVegaKeyStoreSetMaxEvictsDownToTheNewBound(t *testing.T) {
	s := newVegaKeyStore(t.TempDir(), 1000)
	t.Cleanup(func() { _ = s.removeAll() })

	aPath, releaseApath, err := s.put("a", make([]byte, 100))
	if err != nil {
		t.Fatal(err)
	}
	releaseApath()
	if _, release, err := s.put("b", make([]byte, 100)); err != nil {
		t.Fatal(err)
	} else {
		release()
	}

	s.setMax(150)

	if _, ok := s.get("a"); ok {
		t.Error("lowering the bound should have evicted the oldest entry")
	}
	if _, err := os.Stat(aPath); !os.IsNotExist(err) {
		t.Errorf("the evicted key's file is still on disk at %s", aPath)
	}
	if _, ok := s.get("b"); !ok {
		t.Error("the newest entry should have survived")
	}
}

func TestVegaKeyStoreRemoveAllTakesTheDirectory(t *testing.T) {
	parent := t.TempDir()
	s := newVegaKeyStore(parent, 1000)

	path, releasePath, err := s.put("a", []byte("key material"))
	if err != nil {
		t.Fatal(err)
	}
	releasePath()
	dir := filepath.Dir(path)

	if err := s.removeAll(); err != nil {
		t.Fatalf("removeAll() error = %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("%s should be gone", dir)
	}
	// Its own subdirectory, not the configured parent: a key_cache_dir that
	// happens to hold something else must not be swept up with it.
	if _, err := os.Stat(parent); err != nil {
		t.Errorf("the configured parent directory should survive: %v", err)
	}
}

// Hashed, so an id that reached here from a presented proof cannot shape a
// path at all.
func TestVegaKeyFileNameIsAHash(t *testing.T) {
	name := vegaKeyFileName("../../etc/passwd")
	if filepath.Base(name) != name {
		t.Fatalf("file name %q contains a path separator", name)
	}
	if name == vegaKeyFileName("vega-mc-p256-v1-prover-key-r12") {
		t.Fatal("different ids must not collide")
	}
}

func TestSetVegaVerifierKeyCacheBytes(t *testing.T) {
	original := VegaVerifierKeyCacheBytes()
	t.Cleanup(func() { SetVegaVerifierKeyCacheBytes(original) })

	SetVegaVerifierKeyCacheBytes(64 << 20)
	if got := VegaVerifierKeyCacheBytes(); got != 64<<20 {
		t.Fatalf("bound = %d, want %d", got, 64<<20)
	}

	// Zero or negative is ignored rather than taken as "cache nothing": a
	// store that evicts every entry the moment it is written turns every
	// verification into a 100MB fetch, and that is not somewhere to end up
	// by leaving a config field unset.
	for _, n := range []int{0, -1} {
		SetVegaVerifierKeyCacheBytes(n)
		if got := VegaVerifierKeyCacheBytes(); got != 64<<20 {
			t.Errorf("SetVegaVerifierKeyCacheBytes(%d) changed the bound to %d", n, got)
		}
	}
}

func TestSetVegaVerifierKeyCacheDirOnlyAppliesBeforeTheDirectoryExists(t *testing.T) {
	s := newVegaKeyStore("", 1000)
	t.Cleanup(func() { _ = s.removeAll() })

	first := t.TempDir()
	s.parent = first

	path, releasePath, err := s.put("a", []byte("key material"))
	if err != nil {
		t.Fatal(err)
	}
	releasePath()
	created := filepath.Dir(path)

	// Once the directory exists, moving it would be a race against a worker
	// that may already hold a path into it, for no benefit.
	s.parent = t.TempDir()
	if _, release, err := s.put("b", []byte("more key material")); err != nil {
		t.Fatal(err)
	} else {
		release()
	}
	second, ok := s.get("b")
	if !ok {
		t.Fatal("b should be stored")
	}
	if filepath.Dir(second) != created {
		t.Errorf("the store moved to %s after its directory existed", filepath.Dir(second))
	}
}

// The race the reference counting exists for: the worker is a separate
// process that opens the path ITSELF, some milliseconds after being handed
// it, so a concurrent load evicting the file in that window fails a
// perfectly valid presentation.
func TestVegaKeyStoreDoesNotUnlinkAKeyInUse(t *testing.T) {
	s := newVegaKeyStore(t.TempDir(), 10)
	t.Cleanup(func() { _ = s.removeAll() })

	inUse, release, err := s.put("in-use", make([]byte, 8))
	if err != nil {
		t.Fatal(err)
	}

	// Another circuit arrives and the bound forces an eviction.
	_, releaseOther, err := s.put("other", make([]byte, 8))
	if err != nil {
		t.Fatal(err)
	}
	releaseOther()

	if _, ok := s.get("in-use"); ok {
		t.Error("the pinned entry should be off the books once evicted")
	}
	if _, err := os.Stat(inUse); err != nil {
		t.Fatalf("a key still in use must not be unlinked: %v", err)
	}

	// Once the holder is done, the deferred delete happens.
	release()
	if _, err := os.Stat(inUse); !os.IsNotExist(err) {
		t.Errorf("the file should be gone after the last release (%v)", err)
	}
}

// Releasing twice must not double-count, or one holder calling release
// twice unlinks a key another holder is still using - the very failure the
// pinning exists to prevent, arrived at from the other direction.
//
// Two holders, the entry then evicted, and the first holder releasing
// twice. With a non-idempotent release that takes pins from 2 to 0 and
// deletes the file out from under the second.
func TestVegaKeyStoreReleaseIsIdempotent(t *testing.T) {
	s := newVegaKeyStore(t.TempDir(), 10)
	t.Cleanup(func() { _ = s.removeAll() })

	path, releaseFirst, err := s.put("a", make([]byte, 8))
	if err != nil {
		t.Fatal(err)
	}

	again, releaseSecond, ok := s.acquire("a")
	if !ok || again != path {
		t.Fatalf("acquire() = %q, %v; want %q, true", again, ok, path)
	}

	// Another circuit arrives and the bound evicts "a" while it is pinned.
	_, releaseOther, err := s.put("other", make([]byte, 8))
	if err != nil {
		t.Fatal(err)
	}
	releaseOther()

	releaseFirst()
	releaseFirst()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the key is still held by another caller and must not be unlinked: %v", err)
	}

	releaseSecond()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("the file should be gone once the last holder releases (%v)", err)
	}
}

// A store that has been torn down must not quietly recreate its directory
// because a background pre-warm landed a moment later, leaving key files
// behind after the process exited.
func TestVegaKeyStoreRefusesWritesAfterClose(t *testing.T) {
	parent := t.TempDir()
	s := newVegaKeyStore(parent, 1000)

	if _, release, err := s.put("a", []byte("key material")); err != nil {
		t.Fatal(err)
	} else {
		release()
	}
	if err := s.removeAll(); err != nil {
		t.Fatal(err)
	}

	if _, _, err := s.put("b", []byte("late arrival")); err == nil {
		t.Fatal("a closed store must refuse writes")
	}

	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("the store recreated its directory after close: %v", entries)
	}
}
