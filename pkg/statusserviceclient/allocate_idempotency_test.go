package statusserviceclient

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

// POST /allocate is the one call in this package that is not idempotent:
// the service reserves and records the index before it writes the
// response, and the request carries no idempotency key. A retry after an
// ambiguous outcome therefore does not re-ask for the same slot, it asks
// for another one - the slot named by the lost reply stays VALID forever,
// referenced by nothing, and nothing on either side can reconcile it.
//
// These tests pin the line between "proves nothing was reserved" (retry)
// and "unknowable" (stop).

// TestTakeDoesNotRetryAmbiguousAllocateFailure: a 503 may be a load
// balancer that never reached the handler, or it may be the service
// failing on the way out of a committed reservation. Nothing at this end
// can tell. Retrying it burned a fresh index per attempt, so a service
// flapping through a deploy could leak the whole retry budget's worth of
// capacity for every issuance that happened to land in the window.
//
// The fake is set to fail exactly once and then succeed, so the old
// behaviour had a visible success to reach: the test is not asserting that
// a permanently broken service fails.
func TestTakeDoesNotRetryAmbiguousAllocateFailure(t *testing.T) {
	fake := newFakeStatusService(t)
	fake.allocateFailureStatus = http.StatusServiceUnavailable

	cfg := fastConfig(fake, testKey(t))
	cfg.PoolSize = 1
	c, err := New(cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	for c.PoolLen() > 0 {
		if _, err := c.Take(context.Background()); err != nil {
			t.Fatalf("draining Take: %v", err)
		}
	}

	// Arm the failure only now, so the background refill that ran during
	// New cannot consume it.
	fake.allocateFailures.Store(1)
	before := fake.allocateCalls.Load()

	if _, err := c.Take(context.Background()); err == nil {
		t.Fatal("Take must fail on an ambiguous allocate outcome rather than reserve a second index")
	} else if !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("want ErrPoolExhausted, got %v", err)
	}

	if got := fake.allocateCalls.Load() - before; got != 1 {
		t.Fatalf("Take made %d allocate attempts after an ambiguous failure, want exactly 1 - each extra attempt reserves and strands another index", got)
	}
}

// TestAllocateDispatchIsRetryable_ConnectionRefused: a connection that was
// never established is the one transport failure that proves the request
// was not seen, and it is also the common one - a service restarting.
// Treating it as ambiguous would cost availability for nothing, so it must
// stay retryable.
//
// The error is produced by a real http.Client against a port with nothing
// on it, rather than constructed by hand, because the whole question is
// what Go's transport actually hands back.
func TestAllocateDispatchIsRetryable_ConnectionRefused(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	dead := "http://" + listener.Addr().String() + "/allocate"
	if err := listener.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, dead, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	_, err = (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err == nil {
		t.Skip("something answered on a port that was just closed; cannot produce a dial failure here")
	}
	if !allocateDispatchIsRetryable(err) {
		t.Fatalf("a connection that was never established must stay retryable, got %v", err)
	}
}

// TestAllocateDispatchIsRetryable_ResetAfterSend: the counterpart. Once
// bytes are on the wire, a failure is indistinguishable from "the service
// allocated and the response was lost", and must be treated as the latter.
//
// The server here accepts the connection and closes it without replying,
// which is exactly the shape of a crash between commit and response.
func TestAllocateDispatchIsRetryable_ResetAfterSend(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		_ = conn.Close()
	}()

	req, err := http.NewRequest(http.MethodPost, "http://"+listener.Addr().String()+"/allocate", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	_, err = (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err == nil {
		t.Fatal("want a transport error from a server that closes without replying")
	}
	if allocateDispatchIsRetryable(err) {
		t.Fatalf("a failure after the request was sent must not be retried, got %v", err)
	}
}

// TestClassifyAllocateStatus pins the status-code half of the same line in
// one place, so a later edit to classifyStatus cannot quietly make 5xx
// retryable again.
func TestClassifyAllocateStatus(t *testing.T) {
	for _, tc := range []struct {
		name      string
		code      int
		wantErr   bool
		wantRetry bool
	}{
		{"created", http.StatusCreated, false, false},
		{"stale token proves nothing was reserved", http.StatusUnauthorized, true, true},
		{"bad request is a refusal", http.StatusBadRequest, true, false},
		{"forbidden is a refusal", http.StatusForbidden, true, false},
		{"server error is ambiguous", http.StatusInternalServerError, true, false},
		{"unavailable is ambiguous", http.StatusServiceUnavailable, true, false},
		{"gateway timeout is ambiguous", http.StatusGatewayTimeout, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := classifyAllocateStatus(tc.code, []byte("body"))
			if tc.wantErr != (err != nil) {
				t.Fatalf("code %d: got err %v, wantErr %v", tc.code, err, tc.wantErr)
			}
			if err == nil {
				return
			}
			if retryable := !isPermanent(err); retryable != tc.wantRetry {
				t.Fatalf("code %d: retryable=%v, want %v (%v)", tc.code, retryable, tc.wantRetry, err)
			}
		})
	}
}
