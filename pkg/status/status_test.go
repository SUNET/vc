package status

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SUNET/vc/internal/gen/status/apiv1_status"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAggregator_RegistersLocalProbes(t *testing.T) {
	a := New("apigw", WithCacheTTL(0)).
		RegisterFunc("db", func(ctx context.Context) error { return nil }).
		RegisterFunc("signer", func(ctx context.Context) error { return errors.New("no key") })

	reply := a.Reply(context.Background())

	require.Len(t, reply.Data.Probes, 2)
	assert.Equal(t, "apigw.db", reply.Data.Probes[0].Name)
	assert.True(t, reply.Data.Probes[0].Healthy)
	assert.Equal(t, "apigw.signer", reply.Data.Probes[1].Name)
	assert.False(t, reply.Data.Probes[1].Healthy)
	assert.Equal(t, "no key", reply.Data.Probes[1].Message)

	// One failing probe → service-level rollup FAIL.
	assert.Contains(t, reply.Data.Status, StatusFail)
}

func TestAggregator_InlinesDownstreamProbes(t *testing.T) {
	downstream := &apiv1_status.StatusReply{
		Data: &apiv1_status.StatusReply_Data{
			Probes: []*apiv1_status.StatusProbe{
				{Name: "registry.mongo", Healthy: true},
				{Name: "registry.signer", Healthy: false, Message: "no key"},
			},
		},
	}

	a := New("apigw", WithCacheTTL(0)).
		RegisterDownstream("registry", func(ctx context.Context) (*apiv1_status.StatusReply, error) {
			return downstream, nil
		})

	reply := a.Reply(context.Background())
	require.Len(t, reply.Data.Probes, 2)
	assert.Equal(t, "registry.mongo", reply.Data.Probes[0].Name)
	assert.Equal(t, "registry.signer", reply.Data.Probes[1].Name)
}

func TestAggregator_DownstreamErrorProducesFailingProbe(t *testing.T) {
	a := New("apigw", WithCacheTTL(0)).
		RegisterDownstream("issuer", func(ctx context.Context) (*apiv1_status.StatusReply, error) {
			return nil, errors.New("connection refused")
		})

	reply := a.Reply(context.Background())
	require.Len(t, reply.Data.Probes, 1)
	assert.Equal(t, "apigw.issuer", reply.Data.Probes[0].Name) // prefixed by Check
	assert.False(t, reply.Data.Probes[0].Healthy)
	assert.Equal(t, "connection refused", reply.Data.Probes[0].Message)
}

func TestAggregator_CachesReply(t *testing.T) {
	var calls atomic.Int32
	a := New("svc", WithCacheTTL(50*time.Millisecond)).
		RegisterFunc("db", func(ctx context.Context) error {
			calls.Add(1)
			return nil
		})

	// First call computes; subsequent calls within TTL are cached.
	_ = a.Reply(context.Background())
	_ = a.Reply(context.Background())
	_ = a.Reply(context.Background())
	assert.Equal(t, int32(1), calls.Load(), "cached calls should reuse result")

	// After TTL, the next call recomputes.
	time.Sleep(60 * time.Millisecond)
	_ = a.Reply(context.Background())
	assert.Equal(t, int32(2), calls.Load(), "call after TTL expiry should recompute")
}

func TestAggregator_SingleflightsRefresh(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})

	a := New("svc", WithCacheTTL(0)). // no caching, so every call would normally recompute
						RegisterFunc("slow", func(ctx context.Context) error {
			calls.Add(1)
			<-release
			return nil
		})

	// First goroutine starts the refresh and blocks in the probe.
	first := make(chan struct{})
	go func() {
		_ = a.Reply(context.Background())
		close(first)
	}()

	// Give the first goroutine time to grab the refreshing flag.
	time.Sleep(20 * time.Millisecond)

	// Second concurrent caller should NOT trigger a new probe run —
	// it should wait for the in-flight one.
	second := make(chan struct{})
	go func() {
		_ = a.Reply(context.Background())
		close(second)
	}()

	time.Sleep(20 * time.Millisecond)
	assert.Equal(t, int32(1), calls.Load(), "second concurrent caller must not run the probe")

	close(release)
	<-first
	<-second
	assert.Equal(t, int32(1), calls.Load())
}
