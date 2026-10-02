package pubsub

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemoryPubSub_PublishAfterSubscribeDelivers(t *testing.T) {
	ps := NewMemoryPubSub()
	defer func() { _ = ps.Close() }()

	sub, err := ps.Subscribe(t.Context(), "topic-a")
	require.NoError(t, err)

	require.NoError(t, ps.Publish(t.Context(), "topic-a", []byte("payload")))

	select {
	case got := <-sub.C():
		assert.Equal(t, []byte("payload"), got)
	case <-time.After(time.Second):
		t.Fatal("publish not delivered within 1s")
	}

	assert.NoError(t, sub.Close())
}

func TestMemoryPubSub_PublishWithoutSubscriberIsNoOp(t *testing.T) {
	ps := NewMemoryPubSub()
	defer func() { _ = ps.Close() }()

	require.NoError(t, ps.Publish(t.Context(), "nobody-home", []byte("dropped")))

	ps.mu.Lock()
	_, present := ps.topics["nobody-home"]
	ps.mu.Unlock()
	assert.False(t, present, "publish must not create a topic entry when nobody is subscribed")
}

func TestMemoryPubSub_LastCloseReapsTopic(t *testing.T) {
	ps := NewMemoryPubSub()
	defer func() { _ = ps.Close() }()

	sub, err := ps.Subscribe(t.Context(), "topic-reap")
	require.NoError(t, err)

	ps.mu.Lock()
	_, present := ps.topics["topic-reap"]
	ps.mu.Unlock()
	require.True(t, present)

	require.NoError(t, sub.Close())

	ps.mu.Lock()
	_, stillPresent := ps.topics["topic-reap"]
	ps.mu.Unlock()
	assert.False(t, stillPresent, "last Subscription.Close must reap the topic group")
}

func TestMemoryPubSub_SecondSubscriberKeepsTopicAlive(t *testing.T) {
	ps := NewMemoryPubSub()
	defer func() { _ = ps.Close() }()

	a, err := ps.Subscribe(t.Context(), "shared")
	require.NoError(t, err)
	b, err := ps.Subscribe(t.Context(), "shared")
	require.NoError(t, err)

	require.NoError(t, a.Close())

	ps.mu.Lock()
	_, present := ps.topics["shared"]
	ps.mu.Unlock()
	assert.True(t, present, "topic must survive while a second subscriber holds it")

	require.NoError(t, b.Close())

	ps.mu.Lock()
	_, present = ps.topics["shared"]
	ps.mu.Unlock()
	assert.False(t, present, "last subscriber leaving must reap the topic")
}

// Publish must deliver to every live subscriber on a topic.
func TestMemoryPubSub_FanoutToMultipleSubscribers(t *testing.T) {
	ps := NewMemoryPubSub()
	defer func() { _ = ps.Close() }()

	a, err := ps.Subscribe(t.Context(), "fanout")
	require.NoError(t, err)
	b, err := ps.Subscribe(t.Context(), "fanout")
	require.NoError(t, err)

	require.NoError(t, ps.Publish(t.Context(), "fanout", []byte("hi")))

	for i, sub := range []Subscription{a, b} {
		select {
		case got := <-sub.C():
			assert.Equal(t, []byte("hi"), got, "subscriber %d missed payload", i)
		case <-time.After(time.Second):
			t.Fatalf("subscriber %d did not receive within 1s", i)
		}
	}
}

// A Publish arriving concurrently with a Subscription.Close must not
// panic, deadlock, or send on a closed channel. Run under -race.
func TestMemoryPubSub_PublishRacesWithClose(t *testing.T) {
	ps := NewMemoryPubSub()
	defer func() { _ = ps.Close() }()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			sub, err := ps.Subscribe(t.Context(), "race")
			require.NoError(t, err)
			drained := make(chan struct{})
			go func() {
				for range sub.C() {
				}
				close(drained)
			}()
			_ = ps.Publish(t.Context(), "race", []byte("msg"))
			require.NoError(t, sub.Close())
			<-drained
		}
	}()

	for i := 0; i < 200; i++ {
		_ = ps.Publish(t.Context(), "race", []byte("concurrent"))
	}

	wg.Wait()
}

func TestMemoryPubSub_CloseIsIdempotent(t *testing.T) {
	ps := NewMemoryPubSub()
	assert.NoError(t, ps.Close())
	assert.NoError(t, ps.Close())

	_, err := ps.Subscribe(t.Context(), "any")
	assert.ErrorIs(t, err, ErrClosed, "Subscribe on closed PubSub must return ErrClosed")

	assert.ErrorIs(t, ps.Publish(t.Context(), "any", []byte("x")), ErrClosed,
		"Publish on closed PubSub must return ErrClosed")
}

func TestMemoryPubSub_SlowSubscriberDropsRatherThanBlocks(t *testing.T) {
	ps := NewMemoryPubSub()
	defer func() { _ = ps.Close() }()

	// Subscribe but never read.
	sub, err := ps.Subscribe(t.Context(), "slow")
	require.NoError(t, err)
	defer func() { _ = sub.Close() }()

	// With a buffer of 1, the first publish lands and the next ones
	// drop. Publishes must not block.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			_ = ps.Publish(t.Context(), "slow", []byte("x"))
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked on a slow subscriber")
	}
}

func TestService_MemoryDefault(t *testing.T) {
	svc := New(BackendMemory, nil, nil)
	ps, err := svc.NewPubSub("test")
	require.NoError(t, err)
	defer func() { _ = ps.Close() }()

	_, isMem := ps.(*MemoryPubSub)
	assert.True(t, isMem, "memory backend must yield *MemoryPubSub")
}

func TestService_HAWithoutRedisFallsBackToMemory(t *testing.T) {
	svc := New(BackendRedis, nil, &capturingLogger{})
	ps, err := svc.NewPubSub("test")
	require.NoError(t, err)
	defer func() { _ = ps.Close() }()

	_, isMem := ps.(*MemoryPubSub)
	assert.True(t, isMem, "nil redis client must fall back to memory")
}

func TestParseBackend(t *testing.T) {
	for in, want := range map[string]Backend{
		"":        BackendMemory,
		"memory":  BackendMemory,
		"redis":   BackendRedis,
		"valkey":  BackendValkey,
		"nonsense": BackendMemory,
	} {
		assert.Equal(t, want, ParseBackend(in), "ParseBackend(%q)", in)
	}
}

type capturingLogger struct {
	mu   sync.Mutex
	last error
}

func (c *capturingLogger) Error(err error, _ string, _ ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.last = err
}

// Context helper so tests on older Go stdlib still compile. Prefer
// t.Context() where available.
var _ = context.Background
