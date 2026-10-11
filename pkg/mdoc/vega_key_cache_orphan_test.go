//go:build unix

package mdoc

import (
	"os"
	"path/filepath"
	"testing"
)

// Only a clean shutdown removes the store's directory. A crash cannot, and
// before the lock-and-sweep each abnormal restart stranded up to max_bytes
// under a persistent verifier.zk_key_cache.dir - permanently, and once per
// restart, which is a disk that fills outside the bound the config
// promises.
func TestVegaKeyStoreSweepsDirectoriesLeftByACrash(t *testing.T) {
	parent := t.TempDir()

	// What a killed process leaves: its directory, its keys and a lock
	// file nobody holds any more, because the kernel released it when that
	// process died.
	orphan := filepath.Join(parent, vegaKeyStoreDirPrefix+"crashed")
	mkStoreDir(t, orphan, true)

	// A store directory with no lock file yet. NOT an orphan as far as
	// this process can tell: that is exactly how another process's
	// directory looks in the moment between its MkdirTemp and its lock
	// file appearing, and sweeping it would delete a live store.
	young := filepath.Join(parent, vegaKeyStoreDirPrefix+"just-created")
	mkStoreDir(t, young, false)

	// Not a store directory, so not the sweep's business however much it
	// looks like clutter.
	bystander := filepath.Join(parent, "someone-elses-cache")
	mkStoreDir(t, bystander, false)

	store := newVegaKeyStore(parent, 1<<20)
	t.Cleanup(func() { _ = store.removeAll(t.Context()) })
	// Released straight away: put hands back a pin, and removeAll waits for
	// outstanding pins before it deletes anything.
	_, release, err := store.put("vega-r1", []byte("a key"))
	if err != nil {
		t.Fatalf("put() error = %v", err)
	}
	release()

	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Errorf("%s still present (stat err = %v), want it swept", filepath.Base(orphan), err)
	}
	for _, kept := range []string{young, bystander} {
		if _, err := os.Stat(kept); err != nil {
			t.Errorf("os.Stat(%s) = %v, want a directory this process cannot prove is abandoned left alone", filepath.Base(kept), err)
		}
	}
	if _, err := os.Stat(store.dir); err != nil {
		t.Errorf("os.Stat(%s) = %v, want the store's own directory kept", store.dir, err)
	}
}

// The sweep has to fail closed: a directory it cannot prove is abandoned
// stays. Deleting one that a second verifier on the same host is reading
// keys out of would fail live presentations, which is far worse than the
// disk use it is there to avoid.
func TestVegaKeyStoreLeavesALockedDirectoryAlone(t *testing.T) {
	parent := t.TempDir()

	// Another process's store: its lock is held for as long as the file
	// stays open, exactly as a running verifier holds its own.
	live := filepath.Join(parent, vegaKeyStoreDirPrefix+"running")
	mkStoreDir(t, live, true)
	held, err := tryLockVegaKeyStoreFile(filepath.Join(live, vegaKeyStoreLockName))
	if err != nil || held == nil {
		t.Fatalf("tryLockVegaKeyStoreFile() = %v, %v, want the lock taken", held, err)
	}
	t.Cleanup(func() { _ = held.Close() })

	store := newVegaKeyStore(parent, 1<<20)
	t.Cleanup(func() { _ = store.removeAll(t.Context()) })
	// Released straight away: put hands back a pin, and removeAll waits for
	// outstanding pins before it deletes anything.
	_, release, err := store.put("vega-r1", []byte("a key"))
	if err != nil {
		t.Fatalf("put() error = %v", err)
	}
	release()

	if _, err := os.Stat(filepath.Join(live, "key.vk")); err != nil {
		t.Errorf("os.Stat() = %v, want a directory whose lock is held to survive the sweep", err)
	}
}

// A lock this process cannot even open is not evidence of anything, so
// the directory stays. Treating an I/O or permission error the same as
// "no owner" would delete a running verifier's keys on exactly the kind
// of filesystem trouble that makes everything else look broken too.
func TestVegaKeyStoreLeavesADirectoryItCannotReadAlone(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root opens an unreadable file anyway, so the permission cannot be simulated")
	}
	parent := t.TempDir()

	unreadable := filepath.Join(parent, vegaKeyStoreDirPrefix+"unreadable")
	mkStoreDir(t, unreadable, true)
	lockPath := filepath.Join(unreadable, vegaKeyStoreLockName)
	if err := os.Chmod(lockPath, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(lockPath, vegaKeyStoreLockPerm) })

	store := newVegaKeyStore(parent, 1<<20)
	t.Cleanup(func() { _ = store.removeAll(t.Context()) })
	_, release, err := store.put("vega-r1", []byte("a key"))
	if err != nil {
		t.Fatalf("put() error = %v", err)
	}
	release()

	if _, err := os.Stat(unreadable); err != nil {
		t.Errorf("os.Stat() = %v, want a directory whose lock could not be read left alone", err)
	}
}

// A store that shuts down cleanly must let go of its lock, or the process
// sits on a file descriptor for the rest of its life - and a store whose
// directory is recreated (a temp cleaner took the old one) would leak one
// per recreation.
//
// Tested through a hard link, so the assertion is about the open file
// DESCRIPTOR and not about the directory entry: flock is held on the inode,
// and removeAll deletes the lock file along with everything else. Unlinking
// a file does not release a lock on it, so re-creating the path and locking
// that would be a different inode and would pass with the fix reverted.
func TestVegaKeyStoreReleasesItsLockOnRemoveAll(t *testing.T) {
	parent := t.TempDir()

	store := newVegaKeyStore(parent, 1<<20)
	_, release, err := store.put("vega-r1", []byte("a key"))
	if err != nil {
		t.Fatalf("put() error = %v", err)
	}
	release()

	// Same inode, a name that survives removeAll.
	linked := filepath.Join(parent, "held-lock")
	if err := os.Link(filepath.Join(store.dir, vegaKeyStoreLockName), linked); err != nil {
		t.Fatalf("os.Link() error = %v", err)
	}

	if lock, err := tryLockVegaKeyStoreFile(linked); err != nil || lock != nil {
		if lock != nil {
			_ = lock.Close()
		}
		t.Fatalf("tryLockVegaKeyStoreFile() = %v, %v, want the running store to be holding its lock", lock, err)
	}

	if err := store.removeAll(t.Context()); err != nil {
		t.Fatalf("removeAll() error = %v", err)
	}

	lock, err := tryLockVegaKeyStoreFile(linked)
	if err != nil || lock == nil {
		t.Fatalf("tryLockVegaKeyStoreFile() = %v, %v, want a lock the closed store no longer holds", lock, err)
	}
	_ = lock.Close()
}

// mkStoreDir writes a directory with a key file in it, and optionally the
// lock file a store directory carries.
func mkStoreDir(t *testing.T, dir string, withLock bool) {
	t.Helper()
	if err := os.MkdirAll(dir, vegaKeyStoreDirPerm); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "key"+vegaKeyFileSuffix), []byte("stale key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if withLock {
		if err := os.WriteFile(filepath.Join(dir, vegaKeyStoreLockName), nil, vegaKeyStoreLockPerm); err != nil {
			t.Fatal(err)
		}
	}
}
