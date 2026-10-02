package pubsub

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/redis/go-redis/v9"
)

// respPubSub is the shared Redis/Valkey PubSub implementation. The two
// backends speak the same RESP protocol, so one struct covers both; the
// backend tag only drives log labels.
type respPubSub struct {
	client  redis.UniversalClient
	prefix  string
	backend Backend
	log     Logger

	mu     sync.Mutex
	subs   map[*respSubscription]struct{}
	closed bool
}

// NewRedisPubSub creates a Redis-backed PubSub. prefix namespaces every
// channel name as "<prefix>:<topic>" so multiple buses may share one
// Redis keyspace without colliding. client ownership stays with the
// caller.
func NewRedisPubSub(client redis.UniversalClient, prefix string, log Logger) (PubSub, error) {
	return newRESP(client, prefix, BackendRedis, log)
}

// NewValkeyPubSub creates a Valkey-backed PubSub. Valkey is the
// Linux-Foundation-maintained Redis fork and speaks the same RESP
// protocol, so the implementation is shared with NewRedisPubSub; the
// separate constructor exists so operators pick the backend they
// actually run and so logs identify it correctly.
func NewValkeyPubSub(client redis.UniversalClient, prefix string, log Logger) (PubSub, error) {
	return newRESP(client, prefix, BackendValkey, log)
}

func newRESP(client redis.UniversalClient, prefix string, backend Backend, log Logger) (PubSub, error) {
	if client == nil {
		return nil, fmt.Errorf("pubsub: %s client cannot be nil", backend)
	}
	if strings.ContainsAny(prefix, "*?[]\\") {
		return nil, fmt.Errorf("pubsub: prefix %q must not contain glob metacharacters (*?[]\\)", prefix)
	}
	return newRESPPubSub(client, prefix, backend, log), nil
}

// newRESPPubSub is the shared constructor used by both the public
// NewRedisPubSub/NewValkeyPubSub and the Service factory. The public
// constructors run input validation; the Service already validated at
// New time.
func newRESPPubSub(client redis.UniversalClient, prefix string, backend Backend, log Logger) *respPubSub {
	if log == nil {
		log = nopLogger{}
	}
	return &respPubSub{
		client:  client,
		prefix:  prefix,
		backend: backend,
		log:     log,
		subs:    make(map[*respSubscription]struct{}),
	}
}

func (r *respPubSub) channel(topic string) string {
	if r.prefix == "" {
		return topic
	}
	return r.prefix + ":" + topic
}

// Publish delivers payload via Redis/Valkey PUBLISH. A publish with no
// subscribers returns nil, matching the server's own fire-and-forget
// semantics and the MemoryPubSub contract.
func (r *respPubSub) Publish(ctx context.Context, topic string, payload []byte) error {
	if r.isClosed() {
		return ErrClosed
	}
	if err := r.client.Publish(ctx, r.channel(topic), payload).Err(); err != nil {
		r.log.Error(err, "pubsub: publish failed", "backend", r.backend.String(), "topic", topic)
		return err
	}
	return nil
}

// Subscribe opens a RESP SUBSCRIBE on the namespaced channel and
// bridges incoming messages to a buffered Go channel the caller reads
// through Subscription.C.
func (r *respPubSub) Subscribe(ctx context.Context, topic string) (Subscription, error) {
	if r.isClosed() {
		return nil, ErrClosed
	}

	pubsub := r.client.Subscribe(ctx, r.channel(topic))
	if _, err := pubsub.Receive(ctx); err != nil {
		_ = pubsub.Close()
		r.log.Error(err, "pubsub: subscribe handshake failed", "backend", r.backend.String(), "topic", topic)
		return nil, err
	}

	sub := &respSubscription{
		parent: r,
		pubsub: pubsub,
		topic:  topic,
		ch:     make(chan []byte, respSubscriberBuffer),
		done:   make(chan struct{}),
	}

	if err := r.register(sub); err != nil {
		_ = pubsub.Close()
		close(sub.ch)
		return nil, err
	}

	go sub.pump()
	return sub, nil
}

// Close closes every live Subscription and the underlying client's
// pub/sub state owned by this Service. The redis.UniversalClient
// itself is NOT closed - callers own it.
func (r *respPubSub) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	subs := make([]*respSubscription, 0, len(r.subs))
	for s := range r.subs {
		subs = append(subs, s)
	}
	r.subs = make(map[*respSubscription]struct{})
	r.mu.Unlock()

	var firstErr error
	for _, s := range subs {
		if err := s.closeInternal(false); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (r *respPubSub) register(s *respSubscription) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	r.subs[s] = struct{}{}
	return nil
}

func (r *respPubSub) unregister(s *respSubscription) {
	r.mu.Lock()
	delete(r.subs, s)
	r.mu.Unlock()
}

func (r *respPubSub) isClosed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}

// respSubscription bridges a redis.PubSub (one open RESP SUBSCRIBE)
// into the Subscription contract. pump() runs for the subscription's
// lifetime, forwarding messages from the backend channel into ch.
type respSubscription struct {
	parent *respPubSub
	pubsub *redis.PubSub
	topic  string
	ch     chan []byte
	done   chan struct{}
	once   sync.Once
}

func (s *respSubscription) C() <-chan []byte { return s.ch }

// Close terminates the backend subscription and the pump goroutine.
// Idempotent.
func (s *respSubscription) Close() error {
	return s.closeInternal(true)
}

func (s *respSubscription) closeInternal(unregister bool) error {
	var err error
	s.once.Do(func() {
		close(s.done)
		err = s.pubsub.Close()
		if unregister {
			s.parent.unregister(s)
		}
	})
	return err
}

// pump forwards messages from the backend pub/sub channel into s.ch
// until the subscription is closed. A slow reader drops messages
// instead of back-pressuring the Redis receiver goroutine, matching
// the MemoryPubSub contract.
func (s *respSubscription) pump() {
	backend := s.pubsub.Channel()
	defer close(s.ch)
	for {
		select {
		case <-s.done:
			return
		case msg, ok := <-backend:
			if !ok {
				return
			}
			if msg == nil {
				continue
			}
			select {
			case s.ch <- []byte(msg.Payload):
			default:
				// Reader is behind: drop, matching the non-blocking
				// contract. The backend's own receive buffer still
				// absorbs short bursts.
			}
		}
	}
}

const respSubscriberBuffer = 1
