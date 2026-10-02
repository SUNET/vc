package notify

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/pubsub"
)

// Service is the verifier's SSE fanout layer. Public shape unchanged
// from the original per-process broadcaster:
//
//   - OpenListener(id) returns a channel the HTTP handler reads to
//     deliver one SSE message to the client.
//   - CloseListener(id, listener) tears down a single reader.
//   - Submit(id, msg) delivers msg to every live listener on id.
//
// Internally the message bus is a pubsub.PubSub (MemoryPubSub by
// default; Redis / Valkey when HA is configured). Multiple SSE
// listeners on one node for the same session share a single backend
// subscription via a ref-counted idGroup; a pump goroutine bridges
// the shared subscription into each local listener channel.
type Service struct {
	log *logger.Log
	cfg *model.Cfg

	bus pubsub.PubSub

	mu sync.Mutex
	// CH indexes per-id state. Kept exported for the lifecycle tests
	// in this package that assert reclamation behaviour.
	CH map[string]*idGroup
	// listeners counts active listener channels per id. Reclamation
	// is driven off this counter: when it hits zero the group's
	// backend subscription is closed and the entry is removed.
	listeners map[string]int
	// listenerOnces guards each listener channel's close against
	// duplicate CloseListener calls and a shutdown-vs-handler race:
	// CloseListener may run after Service.Close has already closed
	// the channel, and vice versa. Both paths resolve the sync.Once
	// here before touching the channel.
	listenerOnces map[chan any]*sync.Once

	closed bool
}

// idGroup bridges one backend subscription to the N local SSE
// listeners currently subscribed to the same session id on this
// node. Its own mutex serializes fan-out, listener edits, and close
// so a Submit racing with CloseListener cannot send on a channel
// about to be closed.
type idGroup struct {
	sub    pubsub.Subscription
	done   chan struct{}
	pumpWg sync.WaitGroup

	mu        sync.Mutex
	listeners []chan any
	closed    bool
}

func (g *idGroup) register(ch chan any) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return false
	}
	g.listeners = append(g.listeners, ch)
	return true
}

func (g *idGroup) unregister(ch chan any) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for i, l := range g.listeners {
		if l == ch {
			g.listeners = append(g.listeners[:i], g.listeners[i+1:]...)
			return
		}
	}
}

// deliver fans a single decoded payload out to every local listener.
// Non-blocking: a listener that is not reading drops the message.
func (g *idGroup) deliver(msg any) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return
	}
	for _, ch := range g.listeners {
		select {
		case ch <- msg:
		default:
		}
	}
}

// close tears down the group: stop the pump, close the backend
// subscription. Local listener channels are closed by CloseListener
// (so the HTTP goroutine owning that channel observes the close
// synchronously).
func (g *idGroup) close() {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return
	}
	g.closed = true
	g.listeners = nil
	g.mu.Unlock()

	close(g.done)
	if g.sub != nil {
		_ = g.sub.Close()
	}
	g.pumpWg.Wait()
}

// New builds a Service wired to a MemoryPubSub. Standalone deployments
// use this constructor; HA deployments should prefer NewWithBus so the
// backend matches cfg.Common.HA.PubSub.
func New(ctx context.Context, cfg *model.Cfg, log *logger.Log) (*Service, error) {
	return NewWithBus(ctx, cfg, log, pubsub.NewMemoryPubSub())
}

// NewWithBus builds a Service around the supplied pub/sub bus. The
// caller owns bus.Close - Service.Close only tears down its own
// subscriptions, not the bus itself, so one bus may back multiple
// Services if that ever becomes useful.
func NewWithBus(_ context.Context, cfg *model.Cfg, log *logger.Log, bus pubsub.PubSub) (*Service, error) {
	if bus == nil {
		bus = pubsub.NewMemoryPubSub()
	}
	return &Service{
		cfg:           cfg,
		log:           log.New("notify"),
		bus:           bus,
		CH:            make(map[string]*idGroup),
		listeners:     make(map[string]int),
		listenerOnces: make(map[chan any]*sync.Once),
	}, nil
}

// OpenListener registers a new SSE listener for id. If this is the
// first listener on this node for the id, a backend subscription is
// opened and a pump goroutine is started that decodes backend
// payloads into the local listener channels.
func (s *Service) OpenListener(id string) chan any {
	listener := make(chan any, 1)

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		close(listener)
		return listener
	}

	g := s.CH[id]
	isNew := false
	if g == nil {
		sub, err := s.bus.Subscribe(context.Background(), id)
		if err != nil {
			s.mu.Unlock()
			s.log.Error(err, "notify: pubsub Subscribe failed", "id", id)
			// Close so the SSE handler's receive returns ok==false and
			// the HTTP stream terminates; otherwise the browser's
			// EventSource holds the connection open and never retries
			// against a recovered backend.
			close(listener)
			return listener
		}
		g = &idGroup{sub: sub, done: make(chan struct{})}
		s.CH[id] = g
		isNew = true
	}
	s.listeners[id]++
	s.listenerOnces[listener] = &sync.Once{}
	s.mu.Unlock()

	if isNew {
		g.pumpWg.Add(1)
		go s.pump(id, g)
	}

	if !g.register(listener) {
		s.mu.Lock()
		s.listeners[id]--
		if s.listeners[id] <= 0 {
			delete(s.listeners, id)
		}
		delete(s.listenerOnces, listener)
		s.mu.Unlock()
		// Group was closed under us (shutdown or lifecycle reclaim)
		// between creation and registration. Close the listener so the
		// handler's receive observes end-of-stream.
		close(listener)
	}

	s.log.Debug("OpenListener", "id", id)
	return listener
}

// pump bridges g.sub.C() → every local listener on g. One goroutine
// per idGroup, started by OpenListener when the group is created,
// torn down by g.close() via the g.done channel.
func (s *Service) pump(id string, g *idGroup) {
	defer g.pumpWg.Done()
	ch := g.sub.C()
	for {
		select {
		case <-g.done:
			return
		case payload, ok := <-ch:
			if !ok {
				return
			}
			msg, err := decodePayload(payload)
			if err != nil {
				s.log.Error(err, "notify: pubsub payload decode failed", "id", id)
				continue
			}
			g.deliver(msg)
		}
	}
}

// CloseListener removes one listener registration. The last close on
// an id reclaims the group and its backend subscription, so a stream
// of transient ids cannot inflate CH. Idempotent and safe to call
// after Service.Close has already closed the listener channel: a
// handler's deferred CloseListener runs in both the normal and the
// shutdown-race path.
func (s *Service) CloseListener(id string, listener chan any) {
	s.mu.Lock()
	once, firstCall := s.listenerOnces[listener]
	if firstCall {
		delete(s.listenerOnces, listener)
	}
	g, groupOk := s.CH[id]
	s.mu.Unlock()

	// A second call for the same listener must not touch any shared
	// state: the first call already decremented s.listeners[id] and
	// closed the channel. Decrementing again would steal a slot from
	// a sibling listener on the same id and prematurely close the
	// group.
	if !firstCall {
		s.log.Debug("CloseListener (noop)", "id", id)
		return
	}

	if groupOk {
		g.unregister(listener)
	}
	if once != nil {
		once.Do(func() { close(listener) })
	}

	s.mu.Lock()
	s.listeners[id]--
	remaining := s.listeners[id]
	var toClose *idGroup
	if remaining <= 0 {
		delete(s.listeners, id)
		if g2, ok2 := s.CH[id]; ok2 {
			toClose = g2
			delete(s.CH, id)
		}
	}
	s.mu.Unlock()

	if toClose != nil {
		toClose.close()
	}
	s.log.Debug("CloseListener", "id", id, "remaining", remaining)
}

// Submit publishes msg on the bus for id. Encoded as JSON for backend
// transport; MemoryPubSub paths pay one marshal/unmarshal per message,
// cheap compared to the SSE round trip and keeps backend swapping
// transparent to callers.
func (s *Service) Submit(id string, msg any) {
	payload, err := json.Marshal(msg)
	if err != nil {
		s.log.Error(err, "notify: payload marshal failed", "id", id)
		return
	}
	if err := s.bus.Publish(context.Background(), id, payload); err != nil {
		s.log.Error(err, "notify: pubsub Publish failed", "id", id)
	}
}

// Close terminates every outstanding group and closes every live
// listener channel so handlers blocked on <-listener wake up with a
// closed channel instead of hanging. Groups are closed FIRST so each
// pump goroutine exits and deliver is quiescent before any listener
// channel is closed - otherwise a backend message in flight could
// select the send branch on a channel we are about to close here and
// panic. The bus itself is NOT closed here - its lifecycle is owned
// by the caller that constructed it (today: cmd/verifier).
func (s *Service) Close(_ context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	groups := s.CH
	onces := s.listenerOnces
	s.CH = make(map[string]*idGroup)
	s.listeners = make(map[string]int)
	s.listenerOnces = make(map[chan any]*sync.Once)
	s.mu.Unlock()

	for _, g := range groups {
		g.close()
	}
	for ch, once := range onces {
		once.Do(func() { close(ch) })
	}
	return nil
}

// decodePayload reverses json.Marshal. The verifier only ever submits
// a map[string]string today; a generic any keeps future shape changes
// local to the caller.
func decodePayload(b []byte) (any, error) {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	return v, nil
}
