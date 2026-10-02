package pubsub

import (
	"context"
	"sync"
)

// MemoryPubSub is a single-process PubSub implementation: publish and
// subscribe share the same goroutine-safe map of topic groups. It is
// the standalone default and the test backend; cross-node delivery is
// outside its remit.
//
// The lifecycle contract matches the needs of SSE fanout:
//   - Publish to a topic with no subscriber is a no-op (does not
//     create a lingering group).
//   - A subscriber whose channel is not being drained drops messages
//     rather than back-pressuring the publisher.
//   - Close on either the Subscription or the PubSub is safe under
//     concurrent Publish - a close marks the group so a racing
//     Publish becomes a no-op before it can send on torn-down channels.
type MemoryPubSub struct {
	mu     sync.Mutex
	topics map[string]*memoryGroup
	closed bool
}

// NewMemoryPubSub returns a ready-to-use in-process PubSub.
func NewMemoryPubSub() *MemoryPubSub {
	return &MemoryPubSub{
		topics: make(map[string]*memoryGroup),
	}
}

// memoryGroup owns the subscriber channels for one topic. Its own
// mutex serializes submit and close so a racing Publish cannot send
// on a channel the close goroutine is about to tear down.
type memoryGroup struct {
	mu          sync.Mutex
	subscribers []*memorySub
	closed      bool
}

type memorySub struct {
	parent *MemoryPubSub
	topic  string
	group  *memoryGroup
	ch     chan []byte
	once   sync.Once
}

// C returns the delivery channel.
func (s *memorySub) C() <-chan []byte { return s.ch }

// Close removes the subscriber from its group and closes its channel.
// If this was the last subscriber for the topic, the group is reclaimed
// from the parent so a long-running process does not accumulate empty
// groups per transient topic.
func (s *memorySub) Close() error {
	s.once.Do(func() {
		remaining := s.group.removeSubscriber(s)
		close(s.ch)
		if remaining == 0 {
			s.parent.reapIfEmpty(s.topic, s.group)
		}
	})
	return nil
}

// addSubscriber appends sub to the group unless the group is already
// closed. Returns true when the subscriber is live.
func (g *memoryGroup) addSubscriber(sub *memorySub) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return false
	}
	g.subscribers = append(g.subscribers, sub)
	return true
}

// removeSubscriber drops sub from the group and returns the remaining
// subscriber count.
func (g *memoryGroup) removeSubscriber(sub *memorySub) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	for i, s := range g.subscribers {
		if s == sub {
			g.subscribers = append(g.subscribers[:i], g.subscribers[i+1:]...)
			break
		}
	}
	return len(g.subscribers)
}

// publish delivers payload to every current subscriber. Delivery is
// non-blocking: a subscriber that is not reading drops the message.
func (g *memoryGroup) publish(payload []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return
	}
	for _, sub := range g.subscribers {
		select {
		case sub.ch <- payload:
		default:
		}
	}
}

// close marks the group terminated so a racing publish is a no-op, and
// closes every subscriber channel so pending receivers on Subscription.C()
// observe end-of-stream rather than blocking forever. Each subscriber's
// own sync.Once guards against a double close from a concurrent
// memorySub.Close.
func (g *memoryGroup) close() {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return
	}
	g.closed = true
	subs := g.subscribers
	g.subscribers = nil
	g.mu.Unlock()

	for _, sub := range subs {
		sub.once.Do(func() { close(sub.ch) })
	}
}

// Publish fans payload out to every subscriber of topic.
func (m *MemoryPubSub) Publish(_ context.Context, topic string, payload []byte) error {
	m.mu.Lock()
	g, ok := m.topics[topic]
	closed := m.closed
	m.mu.Unlock()
	if closed || !ok {
		return nil
	}
	g.publish(payload)
	return nil
}

// Subscribe returns a fresh Subscription for topic. Each call allocates
// a new buffered channel; the Subscription owns it until Close.
func (m *MemoryPubSub) Subscribe(_ context.Context, topic string) (Subscription, error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, ErrClosed
	}
	g, ok := m.topics[topic]
	if !ok {
		g = &memoryGroup{}
		m.topics[topic] = g
	}
	m.mu.Unlock()

	sub := &memorySub{
		parent: m,
		topic:  topic,
		group:  g,
		ch:     make(chan []byte, memorySubscriberBuffer),
	}
	if !g.addSubscriber(sub) {
		close(sub.ch)
		return nil, ErrClosed
	}
	return sub, nil
}

// Close terminates every topic group and lets outstanding Subscriptions
// observe end-of-stream on their next read. Idempotent.
func (m *MemoryPubSub) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	topics := m.topics
	m.topics = make(map[string]*memoryGroup)
	m.mu.Unlock()

	for _, g := range topics {
		g.close()
	}
	return nil
}

// reapIfEmpty removes the group from the parent map when it still
// matches the one we hold and has no live subscribers. Needed so a
// stream of transient topics (random session ids) cannot inflate the
// topics map.
func (m *MemoryPubSub) reapIfEmpty(topic string, g *memoryGroup) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.topics[topic]
	if !ok || cur != g {
		return
	}
	g.mu.Lock()
	empty := len(g.subscribers) == 0
	g.mu.Unlock()
	if empty {
		delete(m.topics, topic)
		g.close()
	}
}

// memorySubscriberBuffer sizes each subscriber channel. A buffer of 1
// is enough for the one-shot messages this package was built for and
// keeps memory per subscription small.
const memorySubscriberBuffer = 1
