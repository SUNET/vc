package sqlstore

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProbeStatus_ConcurrentCallsSafe is a regression test for a real data
// race Copilot flagged on PR #587: ProbeStatus's cached NextCheck/
// PreviousResult fields were read and written with no synchronization, so
// concurrent Status() calls (e.g. overlapping health-check/readiness
// requests) raced. Run with -race, this reliably caught the bug before
// ProbeCache added its mutex.
func TestProbeStatus_ConcurrentCallsSafe(t *testing.T) {
	cache := &ProbeCache{}
	var pingCount atomic.Int64
	ping := func(ctx context.Context) error {
		pingCount.Add(1)
		return nil
	}

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			probe := ProbeStatus(t.Context(), cache, ping)
			assert.NotNil(t, probe)
			assert.True(t, probe.Healthy)
		}()
	}
	wg.Wait()

	// ProbeCache's mutex serializes the whole check-then-ping-then-cache
	// sequence, so exactly one of these 50 concurrent calls actually pings -
	// every other one blocks on the lock and then sees an already-fresh
	// cache once it acquires it.
	require.Equal(t, int64(1), pingCount.Load())
}
