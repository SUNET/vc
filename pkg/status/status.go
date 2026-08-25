// Package status provides a small, reusable readiness aggregation layer.
//
// Microservice components implement the Prober interface — a single method
// Status(ctx) error where nil means healthy and any non-nil error means
// unhealthy (the error message is surfaced as the probe message).
//
// An Aggregator collects named local probes and downstream StatusReply
// sources, runs them (with per-probe timeouts), caches the merged
// StatusReply for a configurable TTL, and single-flights concurrent
// callers so /health cannot be turned into a DDoS amplifier.
package status

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/SUNET/vc/internal/gen/status/apiv1_status"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// Prober reports the readiness of a single component. Return nil when the
// component is healthy; any non-nil error is treated as unhealthy and its
// message is surfaced verbatim to the caller.
//
// The method is named HealthProbe (rather than Status) so it does not
// collide with unrelated Status methods on the same type (e.g. token
// status list operations, gRPC Status RPCs).
type Prober interface {
	HealthProbe(ctx context.Context) error
}

// ProberFunc adapts a plain function to the Prober interface.
type ProberFunc func(ctx context.Context) error

// HealthProbe implements Prober.
func (f ProberFunc) HealthProbe(ctx context.Context) error { return f(ctx) }

// DownstreamFetcher retrieves a StatusReply from a downstream service (for
// example via a gRPC Status RPC). The returned reply's probes are inlined
// verbatim into the aggregate — they should already be service-prefixed
// (e.g. "issuer.signer") by the callee's own Aggregator.
type DownstreamFetcher func(ctx context.Context) (*apiv1_status.StatusReply, error)

// Aggregator collects local probers and downstream services and produces a
// merged StatusReply. Safe for concurrent use.
type Aggregator struct {
	serviceName  string
	probeTimeout time.Duration
	cacheTTL     time.Duration

	local      []namedProber
	downstream []namedDownstream

	mu          sync.Mutex
	cached      *apiv1_status.StatusReply
	staleAfter  time.Time
	refreshing  bool
	refreshedCh chan struct{}
}

type namedProber struct {
	name   string
	prober Prober
}

type namedDownstream struct {
	name  string
	fetch DownstreamFetcher
}

// Option configures a new Aggregator.
type Option func(*Aggregator)

// WithCacheTTL sets how long a computed StatusReply is served before the
// next call recomputes it. Zero disables caching (every call recomputes).
func WithCacheTTL(ttl time.Duration) Option {
	return func(a *Aggregator) { a.cacheTTL = ttl }
}

// WithProbeTimeout sets the per-probe timeout applied to every Prober
// and DownstreamFetcher invocation.
func WithProbeTimeout(t time.Duration) Option {
	return func(a *Aggregator) { a.probeTimeout = t }
}

// New returns an Aggregator for the given service. Sensible defaults:
// 2 second probe timeout, 10 second cache TTL.
func New(serviceName string, opts ...Option) *Aggregator {
	a := &Aggregator{
		serviceName:  serviceName,
		probeTimeout: 2 * time.Second,
		cacheTTL:     10 * time.Second,
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// Register adds a local component to be probed. The probe will appear in
// the reply as "<serviceName>.<name>".
func (a *Aggregator) Register(name string, p Prober) *Aggregator {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.local = append(a.local, namedProber{name: name, prober: p})
	return a
}

// RegisterFunc is a convenience wrapper around Register for anonymous checks.
func (a *Aggregator) RegisterFunc(name string, fn func(ctx context.Context) error) *Aggregator {
	return a.Register(name, ProberFunc(fn))
}

// RegisterDownstream adds a downstream service whose probes are inlined
// into the aggregated reply. If fetch returns an error, a single failing
// probe named after the downstream is emitted instead.
func (a *Aggregator) RegisterDownstream(name string, fetch DownstreamFetcher) *Aggregator {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.downstream = append(a.downstream, namedDownstream{name: name, fetch: fetch})
	return a
}

// Reply returns the (possibly cached) aggregated StatusReply. Concurrent
// callers that arrive during a refresh block on the in-flight computation
// rather than starting their own, so downstream fanout is single-flighted.
// A nil receiver returns an empty (but well-formed) StatusReply so callers
// don't need to guard against uninitialized aggregators.
func (a *Aggregator) Reply(ctx context.Context) *apiv1_status.StatusReply {
	if a == nil {
		return Probes{}.Check("")
	}
	a.mu.Lock()
	if a.cached != nil && a.cacheTTL > 0 && time.Now().Before(a.staleAfter) {
		r := a.cached
		a.mu.Unlock()
		return r
	}
	if a.refreshing {
		ch := a.refreshedCh
		last := a.cached
		a.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			if last != nil {
				return last
			}
			return Probes{}.Check(a.serviceName)
		}
		a.mu.Lock()
		r := a.cached
		a.mu.Unlock()
		return r
	}
	a.refreshing = true
	a.refreshedCh = make(chan struct{})
	ch := a.refreshedCh
	a.mu.Unlock()

	reply := a.build(ctx)

	a.mu.Lock()
	a.cached = reply
	a.staleAfter = time.Now().Add(a.cacheTTL)
	a.refreshing = false
	a.mu.Unlock()
	close(ch)

	return reply
}

func (a *Aggregator) build(ctx context.Context) *apiv1_status.StatusReply {
	local, downstream := a.snapshot()

	probes := Probes{}
	for _, np := range local {
		probes = append(probes, runProbe(ctx, np.name, np.prober, a.probeTimeout))
	}
	for _, nd := range downstream {
		probes = append(probes, fetchDownstream(ctx, nd.name, nd.fetch, a.probeTimeout)...)
	}
	return probes.Check(a.serviceName)
}

func (a *Aggregator) snapshot() ([]namedProber, []namedDownstream) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]namedProber(nil), a.local...), append([]namedDownstream(nil), a.downstream...)
}

func runProbe(ctx context.Context, name string, p Prober, timeout time.Duration) *apiv1_status.StatusProbe {
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	probe := &apiv1_status.StatusProbe{
		Name:          name,
		Healthy:       true,
		Message:       "OK",
		LastCheckedTS: timestamppb.Now(),
	}
	if err := p.HealthProbe(callCtx); err != nil {
		probe.Healthy = false
		probe.Message = err.Error()
	}
	return probe
}

func fetchDownstream(ctx context.Context, name string, fetch DownstreamFetcher, timeout time.Duration) []*apiv1_status.StatusProbe {
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	reply, err := fetch(callCtx)
	if err != nil {
		return []*apiv1_status.StatusProbe{unreachable(name, err.Error())}
	}
	if reply == nil {
		return []*apiv1_status.StatusProbe{unreachable(name, "nil status reply")}
	}
	data := reply.GetData()
	if data == nil {
		return []*apiv1_status.StatusProbe{unreachable(name, "empty status reply")}
	}
	return data.Probes
}

func unreachable(name, msg string) *apiv1_status.StatusProbe {
	return &apiv1_status.StatusProbe{
		Name:          name,
		Healthy:       false,
		Message:       msg,
		LastCheckedTS: timestamppb.Now(),
	}
}

// ErrUninitialized is a convenience sentinel for probes that fail because
// their component was not wired up (e.g. optional gRPC client is nil).
var ErrUninitialized = errors.New("component not initialized")
