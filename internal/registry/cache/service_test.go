package cache

import (
	"context"
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/creasty/defaults"

	"vc/internal/registry/db"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func testCfg(ha bool) *model.Cfg {
	cfg := &model.Cfg{
		Common:   &model.Common{HA: model.HAConfig{Enable: ha, CacheDatabaseName: "vc_cache"}},
		Registry: &model.Registry{TokenStatusLists: &model.TokenStatusLists{TokenRefreshInterval: 3600}},
	}
	_ = defaults.Set(cfg)
	return cfg
}

func testLogger(t *testing.T) *logger.Log {
	t.Helper()
	log, err := logger.New("test", "", false)
	require.NoError(t, err)
	return log
}

func testTracer(t *testing.T, cfg *model.Cfg, log *logger.Log) *trace.Tracer {
	t.Helper()
	tracer, err := trace.New(t.Context(), cfg, "cache-test", log)
	require.NoError(t, err)
	return tracer
}

func isDockerAvailable() bool {
	dockerPath, err := exec.LookPath("docker")
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, dockerPath, "version").Run() == nil
}

func startMongoContainer(t *testing.T) (*mongo.Client, func()) {
	t.Helper()
	if !isDockerAvailable() {
		t.Skip("Docker is not available")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "mongo:7",
			ExposedPorts: []string{"27017/tcp"},
			WaitingFor:   wait.ForLog("Waiting for connections"),
		},
		Started: true,
	})
	if err != nil {
		cancel()
		t.Fatalf("start mongo container: %v", err)
	}

	port, err := container.MappedPort(ctx, "27017")
	if err != nil {
		cancel()
		t.Fatalf("mapped port: %v", err)
	}
	host, err := container.Host(ctx)
	if err != nil {
		cancel()
		t.Fatalf("container host: %v", err)
	}

	client, err := mongo.Connect(options.Client().ApplyURI(fmt.Sprintf("mongodb://%s:%s", host, port.Port())))
	if err != nil {
		cancel()
		t.Fatalf("mongo connect: %v", err)
	}

	return client, func() {
		client.Disconnect(ctx)
		container.Terminate(ctx)
		cancel()
	}
}

// TestNew_Memory verifies New() with in-memory backend (ha=false).
func TestNew_Memory(t *testing.T) {
	cfg := testCfg(false)
	log := testLogger(t)
	tracer := testTracer(t, cfg, log)

	dbService := &db.Service{MongoClient: nil}

	s, err := New(t.Context(), cfg, dbService, tracer, log)
	require.NoError(t, err)
	require.NotNil(t, s)

	assert.NotNil(t, s.JWT, "JWT cache")
	assert.NotNil(t, s.CWT, "CWT cache")

	ctx := t.Context()

	// JWT round-trip
	s.JWT.Set(ctx, "section-0", "eyJhbGciOiJFUzI1NiJ9...")
	v, ok := s.JWT.Get(ctx, "section-0")
	assert.True(t, ok)
	assert.Equal(t, "eyJhbGciOiJFUzI1NiJ9...", v)

	// CWT round-trip
	cwtData := []byte{0xd2, 0x84, 0x43}
	s.CWT.Set(ctx, "section-0", cwtData)
	b, ok := s.CWT.Get(ctx, "section-0")
	assert.True(t, ok)
	assert.Equal(t, cwtData, b)
}

// TestNew_Mongo verifies New() with MongoDB backend (ha=true).
func TestNew_Mongo(t *testing.T) {
	client, cleanup := startMongoContainer(t)
	defer cleanup()

	cfg := testCfg(true)
	log := testLogger(t)
	tracer := testTracer(t, cfg, log)

	dbService := &db.Service{MongoClient: client}

	s, err := New(t.Context(), cfg, dbService, tracer, log)
	require.NoError(t, err)
	require.NotNil(t, s)

	assert.NotNil(t, s.JWT, "JWT cache")
	assert.NotNil(t, s.CWT, "CWT cache")

	ctx := t.Context()

	// JWT round-trip
	s.JWT.Set(ctx, "msection-0", "mongo-jwt-token")
	v, ok := s.JWT.Get(ctx, "msection-0")
	assert.True(t, ok)
	assert.Equal(t, "mongo-jwt-token", v)

	// CWT round-trip
	cwtData := []byte{0xd2, 0x84, 0x43}
	s.CWT.Set(ctx, "msection-0", cwtData)
	b, ok := s.CWT.Get(ctx, "msection-0")
	assert.True(t, ok)
	assert.Equal(t, cwtData, b)
}

// TestNew_NilMongoClient verifies New() returns an error when ha=true but client is nil.
func TestNew_NilMongoClient(t *testing.T) {
	cfg := testCfg(true)
	log := testLogger(t)
	tracer := testTracer(t, cfg, log)

	dbService := &db.Service{MongoClient: nil}

	s, err := New(t.Context(), cfg, dbService, tracer, log)
	assert.Error(t, err)
	assert.Nil(t, s)
	assert.Contains(t, err.Error(), "cache:")
}

// TestNew_DefaultTokenRefreshInterval verifies the default is used when TokenRefreshInterval <= 0.
func TestNew_DefaultTokenRefreshInterval(t *testing.T) {
	cfg := &model.Cfg{
		Common:   &model.Common{HA: model.HAConfig{Enable: false, CacheDatabaseName: "vc_cache"}},
		Registry: &model.Registry{TokenStatusLists: &model.TokenStatusLists{TokenRefreshInterval: 0}},
	}
	log := testLogger(t)
	tracer := testTracer(t, cfg, log)

	dbService := &db.Service{MongoClient: nil}

	s, err := New(t.Context(), cfg, dbService, tracer, log)
	require.NoError(t, err)
	require.NotNil(t, s)
	assert.NotNil(t, s.JWT)
	assert.NotNil(t, s.CWT)
}
