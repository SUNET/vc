// Package pubsub is a tiny message-fanout abstraction with pluggable
// backends. Standalone deployments use MemoryPubSub (same-process,
// zero-config); HA deployments can opt into a RESP-protocol backend
// (Redis or Valkey) for cross-node delivery.
//
// The package is deliberately shaped like pkg/cache: one interface, one
// in-memory default, one or more opt-in HA backends, one factory. See
// Service for the entry point.
package pubsub

import "context"

// PubSub is a topic-based publish/subscribe bus. Payloads are opaque
// bytes; callers choose their own encoding.
//
// Delivery is best-effort fire-and-forget: a message published to a
// topic with no live subscriber is dropped, and a subscriber whose
// channel is not being drained drops the message rather than blocking
// publishers. Durable delivery is a caller concern - see
// internal/verifier/apiv1 for the completion-marker pattern that
// handles reload survival for the verifier notify flow.
type PubSub interface {
	// Publish sends payload to every live subscriber of topic. It is
	// a no-op when no subscriber exists. Non-blocking: a slow
	// subscriber loses the message rather than back-pressuring the
	// publisher.
	Publish(ctx context.Context, topic string, payload []byte) error

	// Subscribe returns a Subscription delivering future publishes on
	// topic. The caller MUST Close the returned Subscription when
	// done to release backend resources.
	Subscribe(ctx context.Context, topic string) (Subscription, error)

	// Close releases backend resources and closes every outstanding
	// Subscription. Safe to call multiple times.
	Close() error
}

// Subscription is a single subscriber's handle to a topic. Each
// Subscribe call returns a fresh Subscription with its own channel;
// Close is the only path to release it.
type Subscription interface {
	// C returns the delivery channel. It is closed by Close and by
	// Close on the owning PubSub; readers should treat a closed
	// channel as "subscription ended" rather than an error.
	C() <-chan []byte

	// Close cancels the subscription and closes C. Idempotent.
	Close() error
}

// Logger mirrors pkg/cache.Logger: a minimal operational-error sink
// that both *logger.Log and logr.Logger satisfy. Nil is accepted
// everywhere and swapped for a silent no-op.
type Logger interface {
	Error(err error, msg string, keysAndValues ...any)
}

type nopLogger struct{}

func (nopLogger) Error(_ error, _ string, _ ...any) {}
