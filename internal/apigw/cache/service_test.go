package cache

import (
	"context"
	"fmt"
	"os/exec"
	"testing"
	"time"

	"vc/internal/apigw/db"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func testCfg(ha bool) *model.Cfg {
	return &model.Cfg{
		Common: &model.Common{HA: model.HAConfig{Enable: ha, CacheDatabaseName: "vc_cache"}},
		APIGW: &model.APIGW{
			OIDCRP: model.OIDCRPConfig{SessionDuration: 300},
			SAML:   model.SAMLConfig{SessionDuration: 300},
		},
	}
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

	assert.NotNil(t, s.AuthContext, "AuthContext cache")
	assert.NotNil(t, s.EphemeralEncryptionKey, "EphemeralEncryptionKey cache")
	assert.NotNil(t, s.SVGTemplate, "SVGTemplate cache")
	assert.NotNil(t, s.Document, "Document cache")
	assert.NotNil(t, s.DPopJTI, "DPopJTI cache")
	assert.NotNil(t, s.OIDCRPSession, "OIDCRPSession cache")
	assert.NotNil(t, s.SAMLSession, "SAMLSession cache")

	ctx := t.Context()

	// AuthContext round-trip
	ac := &AuthorizationContext{SessionID: "s1", Code: "c1"}
	require.NoError(t, s.AuthContext.Save(ctx, ac))
	got, err := s.AuthContext.GetByID(ctx, "s1")
	require.NoError(t, err)
	assert.Equal(t, "c1", got.Code)

	// EphemeralEncryptionKey round-trip
	key, err := jwk.Import([]byte("test-symmetric-key-32-bytes!!!!"))
	require.NoError(t, err)
	s.EphemeralEncryptionKey.Set(ctx, "ek1", key)
	_, ok := s.EphemeralEncryptionKey.Get(ctx, "ek1")
	assert.True(t, ok, "EphemeralEncryptionKey Get")

	// SVGTemplate round-trip
	s.SVGTemplate.Set(ctx, "svg1", "<svg>test</svg>")
	v, ok := s.SVGTemplate.Get(ctx, "svg1")
	assert.True(t, ok)
	assert.Equal(t, "<svg>test</svg>", v)

	// Document round-trip
	docs := map[string]*model.CompleteDocument{"src": {}}
	s.Document.Set(ctx, "doc1", docs)
	_, ok = s.Document.Get(ctx, "doc1")
	assert.True(t, ok, "Document Get")

	// DPopJTI round-trip
	s.DPopJTI.Set(ctx, "jti1", true)
	b, ok := s.DPopJTI.Get(ctx, "jti1")
	assert.True(t, ok)
	assert.True(t, b)
}

// TestNewTestMemoryCache verifies the test helper constructor.
func TestNewTestMemoryCache(t *testing.T) {
	c := NewTestMemoryCache[string](5 * time.Minute)
	require.NotNil(t, c)

	ctx := t.Context()
	c.Set(ctx, "k", "v")
	v, ok := c.Get(ctx, "k")
	assert.True(t, ok)
	assert.Equal(t, "v", v)
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

	assert.NotNil(t, s.AuthContext, "AuthContext cache")
	assert.NotNil(t, s.EphemeralEncryptionKey, "EphemeralEncryptionKey cache")
	assert.NotNil(t, s.SVGTemplate, "SVGTemplate cache")
	assert.NotNil(t, s.Document, "Document cache")
	assert.NotNil(t, s.DPopJTI, "DPopJTI cache")
	assert.NotNil(t, s.OIDCRPSession, "OIDCRPSession cache")
	assert.NotNil(t, s.SAMLSession, "SAMLSession cache")

	ctx := t.Context()

	// AuthContext round-trip
	ac := &AuthorizationContext{SessionID: "ms1", Code: "mc1"}
	require.NoError(t, s.AuthContext.Save(ctx, ac))
	got, err := s.AuthContext.GetByID(ctx, "ms1")
	require.NoError(t, err)
	assert.Equal(t, "mc1", got.Code)

	// SVGTemplate round-trip
	s.SVGTemplate.Set(ctx, "msvg1", "<svg>mongo</svg>")
	v, ok := s.SVGTemplate.Get(ctx, "msvg1")
	assert.True(t, ok)
	assert.Equal(t, "<svg>mongo</svg>", v)

	// DPopJTI round-trip
	s.DPopJTI.Set(ctx, "mjti1", true)
	b, ok := s.DPopJTI.Get(ctx, "mjti1")
	assert.True(t, ok)
	assert.True(t, b)
}
