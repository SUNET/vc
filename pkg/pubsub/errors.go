package pubsub

import "errors"

// ErrClosed is returned by PubSub operations on a closed instance.
var ErrClosed = errors.New("pubsub: closed")

// ErrBackendUnavailable is logged (not returned) by Service.NewPubSub
// when an HA backend is requested but its dependency (a
// redis.UniversalClient) is nil. The factory then yields a MemoryPubSub
// with a nil error so a misconfigured HA deployment degrades to
// single-node behaviour instead of refusing to start. Callers cannot
// use errors.Is(err, ErrBackendUnavailable) to detect the fallback;
// inspect the log stream or the Service's configured backend instead.
var ErrBackendUnavailable = errors.New("pubsub: backend unavailable")
