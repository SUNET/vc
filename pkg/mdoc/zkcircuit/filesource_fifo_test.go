//go:build unix

package zkcircuit

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A special file left at a mirror path must be refused, not read: os.Open on
// a FIFO blocks until a writer appears, so without the regular-file check
// fetchFile would hang issuance forever. The timeout turns that hang into a
// failure rather than a stuck test.
func TestFetchFileRefusesANonRegularFile(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "manifest.json")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := fetchFile("file://"+filepath.ToSlash(fifo), 1024)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected a refusal for a non-regular file")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fetchFile blocked on a FIFO instead of refusing it")
	}
}
