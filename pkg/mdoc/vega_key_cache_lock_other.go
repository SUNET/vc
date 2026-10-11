//go:build !unix

package mdoc

import "os"

// vegaKeyStoreLocksSupported is false here: without an advisory lock there
// is no way to tell a live store directory from an abandoned one, so the
// orphan sweep does not run and a persistent verifier.zk_key_cache.dir
// needs cleaning up from outside the process. Documented on the config
// field.
const vegaKeyStoreLocksSupported = false

func tryLockVegaKeyStoreFile(string) (*os.File, error) { return nil, nil }

func waitLockVegaKeyStoreDir(string) (*os.File, error) { return nil, nil }
