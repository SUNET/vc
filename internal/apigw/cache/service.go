package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/SUNET/vc/internal/apigw/auth_providers/oidcrp"
	"github.com/SUNET/vc/internal/apigw/auth_providers/samlsp"
	"github.com/SUNET/vc/internal/apigw/db"
	pkgcache "github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// Re-export types from pkg/cache so consumers only need this import.
type (
	AuthContextStore     = pkgcache.AuthContextStore
	AuthorizationContext = pkgcache.AuthorizationContext
	Cache[V any]         = pkgcache.Cache[V]
	Token                = pkgcache.Token
)

// NewTestMemoryStore returns an in-memory AuthContextStore for use in tests only.
var NewTestMemoryStore = pkgcache.NewMemoryStore

// NewTestMemoryCache returns an in-memory Cache for use in tests only.
func NewTestMemoryCache[V any](ttl time.Duration) *pkgcache.MemoryCache[V] {
	return pkgcache.NewMemoryCache[V](ttl)
}

// Service holds all caches used by the apigw service.
type Service struct {
	cfg    *model.Cfg
	log    *logger.Log
	tracer *trace.Tracer

	AuthContext            AuthContextStore
	EphemeralEncryptionKey Cache[jwk.Key]
	SVGTemplate            Cache[string]
	Document               Cache[map[string]*model.CompleteDocument]
	DPopJTI                Cache[bool]

	// VCINonce caches c_nonce values issued by the nonce endpoint.
	// Key is the nonce value; value is true. TTL matches c_nonce_expires_in.
	VCINonce Cache[bool]

	// JWKS caches the raw JWKS JSON fetched from an identity provider's JWKS URL.
	// The key is the JWKS URL; the value is the raw JSON response ([]byte).
	JWKS Cache[[]byte]

	// OIDCRPSession stores OIDC RP authentication flow state (state, nonce, PKCE verifier).
	OIDCRPSession Cache[*oidcrp.Session]

	// SAMLSession stores SAML authentication flow state.
	SAMLSession Cache[*samlsp.Session]

	// AdminIDToken stores raw OIDC ID tokens server-side, keyed by an opaque
	// reference that is kept in the cookie session instead of the full token.
	AdminIDToken Cache[string]

	// SignedMetadata caches signed_metadata JWTs produced by the issuer.
	// Key is the metadata type (e.g. "vci", "oauth2"); value is the signed JWT string.
	// TTL is 1 hour; a background ticker refreshes every 55 minutes.
	SignedMetadata Cache[string]

	// SessionAuthKey is the HMAC key for session cookies, shared across HA instances.
	SessionAuthKey string
	// SessionEncKey is the AES encryption key for session cookies, shared across HA instances.
	SessionEncKey string
}

// New creates the apigw cache service and initialises all caches.
func New(ctx context.Context, cfg *model.Cfg, dbService *db.Service, tracer *trace.Tracer, log *logger.Log) (*Service, error) {
	s := &Service{
		cfg:    cfg,
		log:    log.New("cache"),
		tracer: tracer,
	}
	cs := pkgcache.New(s.cfg.Common.HA.Enable, s.cfg.Common.HA.CacheDatabaseName, dbService.MongoClient, s.log)
	var err error

	if s.AuthContext, err = cs.NewAuthContextCache(ctx, "apigw_auth_context", 10*time.Minute); err != nil {
		return nil, fmt.Errorf("cache: auth_context: %w", err)
	}

	if s.EphemeralEncryptionKey, err = pkgcache.NewGenericCache[jwk.Key](cs, ctx, "apigw_ephemeral_keys", 10*time.Minute, pkgcache.WithDecoder(jwkKeyDecoder)); err != nil {
		return nil, fmt.Errorf("cache: ephemeral_keys: %w", err)
	}

	if s.SVGTemplate, err = pkgcache.NewGenericCache[string](cs, ctx, "apigw_svg_templates", 2*time.Hour); err != nil {
		return nil, fmt.Errorf("cache: svg_templates: %w", err)
	}

	if s.Document, err = pkgcache.NewGenericCache[map[string]*model.CompleteDocument](cs, ctx, "apigw_documents", 5*time.Minute); err != nil {
		return nil, fmt.Errorf("cache: documents: %w", err)
	}

	if s.DPopJTI, err = pkgcache.NewGenericCache[bool](cs, ctx, "apigw_dpop_jti", 5*time.Minute); err != nil {
		return nil, fmt.Errorf("cache: dpop_jti: %w", err)
	}

	if s.VCINonce, err = pkgcache.NewGenericCache[bool](cs, ctx, "apigw_vci_nonce", 1*time.Hour); err != nil {
		return nil, fmt.Errorf("cache: vci_nonce: %w", err)
	}

	if s.JWKS, err = pkgcache.NewGenericCache[[]byte](cs, ctx, "apigw_jwks", 15*time.Minute); err != nil {
		return nil, fmt.Errorf("cache: jwks: %w", err)
	}

	if s.OIDCRPSession, err = pkgcache.NewGenericCache[*oidcrp.Session](cs, ctx, "apigw_oidcrp_sessions", time.Duration(cfg.APIGW.AuthProviders.OIDC.SessionDuration)*time.Second); err != nil {
		return nil, fmt.Errorf("cache: oidcrp_sessions: %w", err)
	}

	if s.SAMLSession, err = pkgcache.NewGenericCache[*samlsp.Session](cs, ctx, "apigw_saml_sessions", time.Duration(cfg.APIGW.AuthProviders.SAML.SessionDuration)*time.Second); err != nil {
		return nil, fmt.Errorf("cache: saml_sessions: %w", err)
	}

	if s.AdminIDToken, err = pkgcache.NewGenericCache[string](cs, ctx, "apigw_admin_id_tokens", 1*time.Hour); err != nil {
		return nil, fmt.Errorf("cache: admin_id_tokens: %w", err)
	}

	if s.SignedMetadata, err = pkgcache.NewGenericCache[string](cs, ctx, "apigw_signed_metadata", 1*time.Hour); err != nil {
		return nil, fmt.Errorf("cache: signed_metadata: %w", err)
	}

	// Resolve HA-shared session keys (atomic upsert in MongoDB when HA, ephemeral otherwise).
	sharedSecrets, err := pkgcache.EnsureSharedSecrets(ctx, cs, "apigw")
	if err != nil {
		return nil, fmt.Errorf("cache: shared_secrets: %w", err)
	}
	s.SessionAuthKey = sharedSecrets.SessionAuthKey
	s.SessionEncKey = sharedSecrets.SessionEncKey

	return s, nil
}

// jwkKeyDecoder parses raw JSON bytes into a jwk.Key.
func jwkKeyDecoder(data []byte) (jwk.Key, error) {
	return jwk.ParseKey(data)
}
