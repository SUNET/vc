package cache

import (
	"testing"
	"time"

	"github.com/SUNET/vc/internal/apigw/db"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/testsupport"
	"github.com/SUNET/vc/pkg/testsupport/cachetest"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testCfg(ha bool) *model.Cfg {
	return &model.Cfg{
		Common: &model.Common{HA: model.HAConfig{Enable: ha, CacheDatabaseName: "vc_cache"}},
		APIGW: &model.APIGW{
			AuthProviders: model.APIGWAuthProviders{
				OIDC: model.OIDCRP{SessionDuration: 300},
				SAML: model.SAMLSP{SessionDuration: 300},
			},
		},
	}
}

// TestNew_Memory verifies New() with in-memory backend (ha=false).
func TestNew_Memory(t *testing.T) {
	cfg := testCfg(false)
	s, err := cachetest.New(t, cfg, &db.Service{MongoClient: nil}, New)
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
	s, err := cachetest.New(t, cfg, &db.Service{MongoClient: nil}, New)
	assert.Error(t, err)
	assert.Nil(t, s)
	assert.Contains(t, err.Error(), "cache:")
}

// TestNew_Mongo verifies New() with MongoDB backend (ha=true).
func TestNew_Mongo(t *testing.T) {
	_, client, cleanup := testsupport.StartMongoContainer(t)
	defer cleanup()

	cfg := testCfg(true)
	s, err := cachetest.New(t, cfg, &db.Service{MongoClient: client}, New)
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
