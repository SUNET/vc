package cache

import (
	"testing"
	"time"

	"github.com/SUNET/vc/internal/verifier/db"
	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/sdjwtvc"
	"github.com/SUNET/vc/pkg/testsupport"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testCfg(ha bool) *model.Cfg {
	return &model.Cfg{
		Common: &model.Common{HA: model.HAConfig{Enable: ha, CacheDatabaseName: "vc_cache"}},
	}
}

func testTracer(t *testing.T, cfg *model.Cfg, log *logger.Log) *trace.Tracer {
	t.Helper()
	tracer, err := trace.New(t.Context(), cfg, "cache-test", log)
	require.NoError(t, err)
	return tracer
}

// TestNew_Memory verifies New() with in-memory backend (ha=false).
func TestNew_Memory(t *testing.T) {
	cfg := testCfg(false)
	log := testsupport.TestLogger(t)
	tracer := testTracer(t, cfg, log)

	dbService := &db.Service{MongoClient: nil}

	s, err := New(t.Context(), cfg, dbService, tracer, log)
	require.NoError(t, err)
	require.NotNil(t, s)

	assert.NotNil(t, s.AuthContext, "AuthContext cache")
	assert.NotNil(t, s.Credential, "Credential cache")
	assert.NotNil(t, s.EphemeralEncryptionKey, "EphemeralEncryptionKey cache")
	assert.NotNil(t, s.RequestObject, "RequestObject cache")

	ctx := t.Context()

	// AuthContext round-trip
	ac := &cache.AuthorizationContext{SessionID: "s1", Code: "c1"}
	require.NoError(t, s.AuthContext.Save(ctx, ac))
	got, err := s.AuthContext.GetByID(ctx, "s1")
	require.NoError(t, err)
	assert.Equal(t, "c1", got.Code)

	// Credential round-trip
	creds := []sdjwtvc.CredentialCache{{Claims: nil, Credential: map[string]any{"vct": "vc1"}}}
	s.Credential.Set(ctx, "cred1", creds)
	gotCreds, ok := s.Credential.Get(ctx, "cred1")
	assert.True(t, ok)
	assert.Len(t, gotCreds, 1)
	assert.Equal(t, "vc1", gotCreds[0].Credential["vct"])

	// EphemeralEncryptionKey round-trip
	key, err := jwk.Import([]byte("test-symmetric-key-32-bytes!!!!"))
	require.NoError(t, err)
	s.EphemeralEncryptionKey.Set(ctx, "ek1", key)
	_, ok = s.EphemeralEncryptionKey.Get(ctx, "ek1")
	assert.True(t, ok, "EphemeralEncryptionKey Get")

	// RequestObject round-trip
	ro := &openid4vp.RequestObject{State: "st1"}
	s.RequestObject.Set(ctx, "ro1", ro)
	gotRO, ok := s.RequestObject.Get(ctx, "ro1")
	assert.True(t, ok)
	assert.Equal(t, "st1", gotRO.State)
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
	log := testsupport.TestLogger(t)
	tracer := testTracer(t, cfg, log)

	dbService := &db.Service{MongoClient: nil}

	s, err := New(t.Context(), cfg, dbService, tracer, log)
	assert.Error(t, err)
	assert.Nil(t, s)
	assert.Contains(t, err.Error(), "cache:")
}

// TestNew_Mongo verifies New() with MongoDB backend (ha=true).
func TestNew_Mongo(t *testing.T) {
	_, client, cleanup := testsupport.StartMongoContainer(t)
	defer cleanup()

	cfg := testCfg(true)
	log := testsupport.TestLogger(t)
	tracer := testTracer(t, cfg, log)

	dbService := &db.Service{MongoClient: client}

	s, err := New(t.Context(), cfg, dbService, tracer, log)
	require.NoError(t, err)
	require.NotNil(t, s)

	assert.NotNil(t, s.AuthContext, "AuthContext cache")
	assert.NotNil(t, s.Credential, "Credential cache")
	assert.NotNil(t, s.EphemeralEncryptionKey, "EphemeralEncryptionKey cache")
	assert.NotNil(t, s.RequestObject, "RequestObject cache")

	ctx := t.Context()

	// AuthContext round-trip
	ac := &cache.AuthorizationContext{SessionID: "ms1", Code: "mc1"}
	require.NoError(t, s.AuthContext.Save(ctx, ac))
	got, err := s.AuthContext.GetByID(ctx, "ms1")
	require.NoError(t, err)
	assert.Equal(t, "mc1", got.Code)

	// Credential round-trip
	creds := []sdjwtvc.CredentialCache{{Claims: nil, Credential: map[string]any{"vct": "mvc1"}}}
	s.Credential.Set(ctx, "mcred1", creds)
	gotCreds, ok := s.Credential.Get(ctx, "mcred1")
	assert.True(t, ok)
	assert.Len(t, gotCreds, 1)
	assert.Equal(t, "mvc1", gotCreds[0].Credential["vct"])

	// RequestObject round-trip
	ro := &openid4vp.RequestObject{State: "mst1"}
	s.RequestObject.Set(ctx, "mro1", ro)
	gotRO, ok := s.RequestObject.Get(ctx, "mro1")
	assert.True(t, ok)
	assert.Equal(t, "mst1", gotRO.State)
}
