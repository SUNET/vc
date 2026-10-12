//go:build unix

package mdoc

import (
	"errors"
	"os"
	"syscall"
)

// vegaKeyStoreLocksSupported reports whether this platform can tell a store
// directory belonging to a running process from one a crash left behind.
const vegaKeyStoreLocksSupported = true

// tryLockVegaKeyStoreFile opens path (creating it) and takes an exclusive
// advisory lock without blocking. It returns nil, nil when another process
// already holds the lock - not an error: that is the answer, and it means
// "in use".
//
// flock, rather than a pid file: the kernel drops the lock when the file
// descriptor goes, which includes SIGKILL, a panic and a power cut. A pid
// file has to be cleaned up by the very process that did not get to clean
// up, and pids are reused.
func tryLockVegaKeyStoreFile(path string) (*os.File, error) {
	return lockVegaKeyStoreFile(path, syscall.LOCK_EX|syscall.LOCK_NB)
}

// tryLockExistingVegaKeyStoreFile is tryLockVegaKeyStoreFile without the
// create: a path that is not there returns nil, nil, the same answer as a
// lock somebody holds.
//
// The distinction matters to the orphan sweep, which must never create
// anything in a directory it is considering deleting, and must read a
// missing lock file as "not mine to touch" rather than "abandoned": a
// directory another process made a moment ago has no lock file yet.
func tryLockExistingVegaKeyStoreFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR, vegaKeyStoreLockPerm)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, nil
		}
		return nil, err
	}
	return f, nil
}

func lockVegaKeyStoreFile(path string, how int) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, vegaKeyStoreLockPerm)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), how); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, nil
		}
		return nil, err
	}
	return f, nil
}
