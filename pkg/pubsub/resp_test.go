package pubsub

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
)

// isDockerAvailable reports whether a working Docker daemon is
// reachable. Mirrors pkg/cache test helpers rather than importing
// testsupport to keep this package's test deps minimal.
func isDockerAvailable() bool {
	dockerPath, err := exec.LookPath("docker")
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, dockerPath, "version").Run() == nil // #nosec G204
}

// startRESPContainer spins up img (Redis or Valkey — same RESP
// protocol, same port) and returns a connected client plus cleanup.
// Mirrors pkg/cache/generic_redis_test.go.
func startRESPContainer(t *testing.T, img string) (redis.UniversalClient, func()) {
	t.Helper()
	if !isDockerAvailable() {
		t.Skip("Skipping test: Docker is not available")
	}
	ctx := t.Context()

	container, err := tcredis.Run(ctx, img)
	if err != nil {
		t.Fatalf("start %s container: %v", img, err)
	}

	connStr, err := container.ConnectionString(ctx)
	if err != nil {
		_ = container.Terminate(context.Background())
		t.Fatalf("%s connection string: %v", img, err)
	}

	opts, err := redis.ParseURL(connStr)
	if err != nil {
		_ = container.Terminate(context.Background())
		t.Fatalf("parse %s url: %v", img, err)
	}
	client := redis.NewClient(opts)

	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		_ = container.Terminate(context.Background())
		t.Fatalf("ping %s: %v", img, err)
	}

	cleanup := func() {
		_ = client.Close()
		_ = container.Terminate(context.Background())
	}
	return client, cleanup
}

func startRedisContainer(t *testing.T) (redis.UniversalClient, func()) {
	return startRESPContainer(t, "redis:7")
}

func startValkeyContainer(t *testing.T) (redis.UniversalClient, func()) {
	return startRESPContainer(t, "valkey/valkey:8")
}

// runRESPContractTests exercises the PubSub contract against a RESP
// backend. The exact same body runs against Redis and Valkey so a
// protocol divergence between them cannot silently break one path.
func runRESPContractTests(t *testing.T, newPS func() PubSub) {
	t.Run("publish after subscribe delivers", func(t *testing.T) {
		ps := newPS()
		defer func() { _ = ps.Close() }()

		sub, err := ps.Subscribe(t.Context(), "topic-a")
		require.NoError(t, err)
		defer func() { _ = sub.Close() }()

		require.NoError(t, ps.Publish(t.Context(), "topic-a", []byte("payload")))

		select {
		case got := <-sub.C():
			assert.Equal(t, []byte("payload"), got)
		case <-time.After(5 * time.Second):
			t.Fatal("publish not delivered within 5s")
		}
	})

	t.Run("publish before subscribe is dropped", func(t *testing.T) {
		ps := newPS()
		defer func() { _ = ps.Close() }()

		require.NoError(t, ps.Publish(t.Context(), "early", []byte("missed")))

		sub, err := ps.Subscribe(t.Context(), "early")
		require.NoError(t, err)
		defer func() { _ = sub.Close() }()

		select {
		case got := <-sub.C():
			t.Fatalf("subscribe-after-publish must not deliver, got %q", got)
		case <-time.After(250 * time.Millisecond):
			// Expected: nothing.
		}
	})

	t.Run("subscription close stops delivery", func(t *testing.T) {
		ps := newPS()
		defer func() { _ = ps.Close() }()

		sub, err := ps.Subscribe(t.Context(), "ending")
		require.NoError(t, err)

		require.NoError(t, sub.Close())
		// Second close must be a no-op.
		assert.NoError(t, sub.Close())

		// Channel must close.
		select {
		case _, ok := <-sub.C():
			assert.False(t, ok, "C() must be closed after Subscription.Close")
		case <-time.After(time.Second):
			t.Fatal("Subscription.C did not close within 1s of Subscription.Close")
		}
	})

	t.Run("fanout to multiple subscribers on same topic", func(t *testing.T) {
		ps := newPS()
		defer func() { _ = ps.Close() }()

		a, err := ps.Subscribe(t.Context(), "fanout")
		require.NoError(t, err)
		defer func() { _ = a.Close() }()
		b, err := ps.Subscribe(t.Context(), "fanout")
		require.NoError(t, err)
		defer func() { _ = b.Close() }()

		require.NoError(t, ps.Publish(t.Context(), "fanout", []byte("hi")))

		for i, sub := range []Subscription{a, b} {
			select {
			case got := <-sub.C():
				assert.Equal(t, []byte("hi"), got, "subscriber %d missed payload", i)
			case <-time.After(5 * time.Second):
				t.Fatalf("subscriber %d did not receive within 5s", i)
			}
		}
	})

	t.Run("close closes outstanding subscriptions", func(t *testing.T) {
		ps := newPS()

		sub, err := ps.Subscribe(t.Context(), "orphan")
		require.NoError(t, err)

		require.NoError(t, ps.Close())
		// Second Close is a no-op.
		assert.NoError(t, ps.Close())

		select {
		case _, ok := <-sub.C():
			assert.False(t, ok, "sub channel must close when the PubSub closes")
		case <-time.After(time.Second):
			t.Fatal("sub channel did not close within 1s of PubSub.Close")
		}

		_, err = ps.Subscribe(t.Context(), "any")
		assert.ErrorIs(t, err, ErrClosed)
	})
}

func TestRedisPubSub_Contract(t *testing.T) {
	client, cleanup := startRedisContainer(t)
	defer cleanup()

	runRESPContractTests(t, func() PubSub {
		ps, err := NewRedisPubSub(client, "test", nil)
		require.NoError(t, err)
		return ps
	})
}

func TestValkeyPubSub_Contract(t *testing.T) {
	client, cleanup := startValkeyContainer(t)
	defer cleanup()

	runRESPContractTests(t, func() PubSub {
		ps, err := NewValkeyPubSub(client, "test", nil)
		require.NoError(t, err)
		return ps
	})
}

func TestNewRedisPubSub_RejectsNilClient(t *testing.T) {
	_, err := NewRedisPubSub(nil, "test", nil)
	assert.Error(t, err)
}

func TestNewValkeyPubSub_RejectsNilClient(t *testing.T) {
	_, err := NewValkeyPubSub(nil, "test", nil)
	assert.Error(t, err)
}

func TestNewRedisPubSub_RejectsGlobPrefix(t *testing.T) {
	// Use an obviously-unusable client; the prefix check must fire
	// before any network interaction.
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:0"})
	defer func() { _ = client.Close() }()

	_, err := NewRedisPubSub(client, "bad*prefix", nil)
	assert.Error(t, err)
}

// Factory selects the RESP backend when a client is supplied.
func TestService_RedisBackendYieldsRESPPubSub(t *testing.T) {
	client, cleanup := startRedisContainer(t)
	defer cleanup()

	svc := New(BackendRedis, client, nil)
	ps, err := svc.NewPubSub("factory")
	require.NoError(t, err)
	defer func() { _ = ps.Close() }()

	_, isMem := ps.(*MemoryPubSub)
	assert.False(t, isMem, "redis backend with a non-nil client must not fall back to memory")
}
