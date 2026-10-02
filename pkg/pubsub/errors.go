package pubsub

import "errors"

// ErrClosed is returned by PubSub operations on a closed instance.
var ErrClosed = errors.New("pubsub: closed")

// ErrBackendUnavailable is returned by the factory when an HA backend
// is requested but its dependency (a redis.UniversalClient) is nil. In
// that case callers get a MemoryPubSub plus a logged warning rather
// than a hard failure, so a misconfigured HA deployment degrades to
// single-node behaviour instead of refusing to start.
var ErrBackendUnavailable = errors.New("pubsub: backend unavailable")
