//go:build zknative

package mdoc

// Real, end-to-end tests for getOrLoadVerifier's in-flight-load
// de-duplication (zk_native_cgo.go): a waiter must (a) return promptly
// when its own context is cancelled, even while another goroutine's load
// is still running, and (b) see that other goroutine's real underlying
// error, not a generic placeholder. These exercise the real
// zkcircuit.Client against a real httptest.Server - zkCircuitSources is a
// genuine external parameter, so no internal test hooks are needed.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestGetOrLoadVerifier_ContextCancellationWhileWaiting confirms a waiter
// returns as soon as its own context is cancelled, rather than blocking
// until the in-flight load it's waiting on finishes - the bug this test
// guards against used a bare sync.WaitGroup.Wait(), which ignores
// ctx.Done() entirely.
func TestGetOrLoadVerifier_ContextCancellationWhileWaiting(t *testing.T) {
	const zkSystemID = "test-cancellation-circuit-id-does-not-exist"

	requestArrived := make(chan struct{})
	release := make(chan struct{})
	var arrivedOnce, releaseOnce sync.Once
	releaseFn := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseFn() // safety net: don't leak the leader goroutine if the test fails early

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrivedOnce.Do(func() { close(requestArrived) })
		<-release // held open until the test explicitly releases it
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	var leaderWG sync.WaitGroup
	leaderWG.Add(1)
	go func() {
		defer leaderWG.Done()
		// The leading load: registers zkSystemID as in-flight, then blocks
		// in the real HTTP fetch until release is closed below.
		_, _, _ = getOrLoadVerifier(context.Background(), zkSystemID, []string{server.URL})
	}()

	select {
	case <-requestArrived:
	case <-time.After(5 * time.Second):
		t.Fatal("leading load never reached the test server - in-flight registration didn't happen as expected")
	}

	// zkSystemID is now registered as in-flight (getOrLoadVerifier
	// registers it under its lock before making the HTTP call the server
	// handler above is currently blocking on). A second caller therefore
	// takes the "wait on the in-flight load" branch.
	waiterCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, _, err := getOrLoadVerifier(waiterCtx, zkSystemID, []string{server.URL})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error for a cancelled waiter")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected an error wrapping context.Canceled, got: %v", err)
	}
	// Generous upper bound: the leader's own fetch is held open by
	// `release` for a full 5-minute httptest default timeout if never
	// released, so any real wait-for-leader behavior would blow well past
	// this. The waiter should return within tens of milliseconds of
	// cancel() firing.
	if elapsed > 2*time.Second {
		t.Errorf("waiter took %v to return after its context was cancelled - should return promptly, not wait for the in-flight load to finish", elapsed)
	}

	releaseFn()
	leaderWG.Wait()
}

// TestGetOrLoadVerifier_WaiterSeesRealLoadError confirms a waiter gets the
// leading goroutine's actual underlying error (wrapped in its own
// message), not a generic placeholder like "failed to load on another
// goroutine" with no detail about what actually went wrong.
func TestGetOrLoadVerifier_WaiterSeesRealLoadError(t *testing.T) {
	const zkSystemID = "test-error-propagation-circuit-id-does-not-exist"

	requestArrived := make(chan struct{})
	release := make(chan struct{})
	var arrivedOnce, releaseOnce sync.Once
	releaseFn := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseFn()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrivedOnce.Do(func() { close(requestArrived) })
		<-release
		// 200 + unparseable body: fails at JSON-decode inside
		// zkcircuit.Client.FetchCircuit, producing a distinctive,
		// identifiable error message (not just a bare HTTP status) that a
		// waiter must actually see, proving real error propagation rather
		// than a generic placeholder.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not valid json {{{"))
	}))
	defer server.Close()

	var leaderWG sync.WaitGroup
	leaderWG.Add(1)
	var leaderErr error
	go func() {
		defer leaderWG.Done()
		_, _, leaderErr = getOrLoadVerifier(context.Background(), zkSystemID, []string{server.URL})
	}()

	select {
	case <-requestArrived:
	case <-time.After(5 * time.Second):
		t.Fatal("leading load never reached the test server")
	}

	waiterDone := make(chan error, 1)
	go func() {
		_, _, err := getOrLoadVerifier(context.Background(), zkSystemID, []string{server.URL})
		waiterDone <- err
	}()

	// Best-effort: give the waiter goroutine a moment to actually reach
	// the "wait on in-flight load" branch before releasing the server
	// response. The assertions below don't depend on strict ordering
	// (either way, the waiter is registered as a genuine waiter on the
	// in-flight load before this point in practice, since it started
	// before release is closed), just that it eventually observes the
	// leader's real error.
	time.Sleep(50 * time.Millisecond)
	releaseFn()

	leaderWG.Wait()
	waiterErr := <-waiterDone

	if leaderErr == nil {
		t.Fatal("expected the leading load to fail on unparseable JSON")
	}
	if !strings.Contains(leaderErr.Error(), "parse circuit descriptor") {
		t.Fatalf("leader error missing expected detail, got: %v", leaderErr)
	}
	if waiterErr == nil {
		t.Fatal("expected the waiter to also see an error")
	}
	if !strings.Contains(waiterErr.Error(), "parse circuit descriptor") {
		t.Errorf("waiter error should surface the real underlying failure (\"parse circuit descriptor...\"), not a generic placeholder; got: %v", waiterErr)
	}
}
