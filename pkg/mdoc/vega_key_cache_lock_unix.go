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

// waitLockVegaKeyStoreDir takes an exclusive advisory lock on the PARENT
// directory itself, waiting for it, and serialises directory creation
// against the orphan sweep.
//
// The directory rather than a lock file in it, because this one could
// never be cleaned up: unlinking a lock file is what makes two processes
// think they hold "the" lock while holding different inodes, so the file
// would have to stay - and the store promises to leave the configured
// directory alone except for its own subdirectory.
func waitLockVegaKeyStoreDir(path string) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
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
