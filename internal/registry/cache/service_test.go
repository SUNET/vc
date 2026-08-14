package cache

import (
	"testing"

	"github.com/creasty/defaults"

	"github.com/SUNET/vc/internal/registry/db"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/testsupport"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/mongo"
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
	return testsupport.IsDockerAvailable()
}

func startMongoContainer(t *testing.T) (*mongo.Client, func()) {
	t.Helper()
	_, client, cleanup := testsupport.StartMongoContainer(t)
	return client, cleanup
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
