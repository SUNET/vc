package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/SUNET/vc/internal/verifier/db"
	pkgcache "github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/sdjwtvc"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// Re-export types from pkg/cache so consumers only need this import.
type (
	AuthContextStore     = pkgcache.AuthContextStore
	AuthorizationContext = pkgcache.AuthorizationContext
	Cache[V any]         = pkgcache.Cache[V]
)

// NewTestMemoryStore returns an in-memory AuthContextStore for use in tests only.
var NewTestMemoryStore = pkgcache.NewMemoryStore

// NewTestMemoryCache returns an in-memory Cache for use in tests only.
func NewTestMemoryCache[V any](ttl time.Duration) *pkgcache.MemoryCache[V] {
	return pkgcache.NewMemoryCache[V](ttl)
}

// Service holds all caches used by the verifier service.
type Service struct {
	cfg    *model.Cfg
	log    *logger.Log
	tracer *trace.Tracer

	AuthContext            AuthContextStore
	Credential             Cache[[]sdjwtvc.CredentialCache]
	EphemeralEncryptionKey Cache[jwk.Key]
	RequestObject          Cache[*openid4vp.RequestObject]

	// SessionAuthKey is the HMAC key for session cookies, shared across HA instances.
	SessionAuthKey string
	// SessionEncKey is the AES encryption key for session cookies, shared across HA instances.
	SessionEncKey string
}

// New creates the verifier cache service and initialises all caches.
func New(ctx context.Context, cfg *model.Cfg, dbService *db.Service, tracer *trace.Tracer, log *logger.Log) (*Service, error) {
	s := &Service{
		cfg:    cfg,
		log:    log.New("cache"),
		tracer: tracer,
	}
	cs := pkgcache.New(s.cfg.Common.HA.Enable, s.cfg.Common.HA.CacheDatabaseName, dbService.MongoClient, s.log)
	var err error

	if s.AuthContext, err = cs.NewAuthContextCache(ctx, "verifier_auth_context", authContextRetention(cfg)); err != nil {
		return nil, fmt.Errorf("cache: auth_context: %w", err)
	}

	if s.Credential, err = pkgcache.NewGenericCache[[]sdjwtvc.CredentialCache](cs, ctx, "verifier_credentials", 5*time.Minute); err != nil {
		return nil, fmt.Errorf("cache: credentials: %w", err)
	}

	// These two have to outlive the presentation as well: the wallet
	// resolves the request URI out of RequestObject and encrypts its
	// response to the key in EphemeralEncryptionKey. At 5 and 10 minutes
	// against a 30-minute window, the request URI stopped resolving and
	// encrypted responses stopped decrypting while ExpiresAt still said the
	// session was live.
	if s.EphemeralEncryptionKey, err = pkgcache.NewGenericCache[jwk.Key](cs, ctx, "verifier_ephemeral_keys", presentationScopedTTL(cfg, 10*time.Minute), pkgcache.WithDecoder(jwkKeyDecoder)); err != nil {
		return nil, fmt.Errorf("cache: ephemeral_keys: %w", err)
	}

	if s.RequestObject, err = pkgcache.NewGenericCache[*openid4vp.RequestObject](cs, ctx, "verifier_request_objects", presentationScopedTTL(cfg, 5*time.Minute), pkgcache.WithDecoder(requestObjectDecoder)); err != nil {
		return nil, fmt.Errorf("cache: request_objects: %w", err)
	}

	// Resolve HA-shared session keys (atomic upsert in MongoDB when HA, ephemeral otherwise).
	sharedSecrets, err := pkgcache.EnsureSharedSecrets(ctx, cs, "verifier")
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

// requestObjectDecoder parses raw JSON into a RequestObject. Explicit
// so the custom UnmarshalJSON on openid4vp.Keys (which jwk.ParseKey's
// each interface entry) runs on the Mongo round-trip too; a plain
// json.Unmarshal on the Cache's zero value would also reach it, but
// going through this decoder keeps parity with the EphemeralEncryptionKey
// cache and leaves one place to extend if a nested value ever needs
// post-processing.
func requestObjectDecoder(data []byte) (*openid4vp.RequestObject, error) {
	ro := &openid4vp.RequestObject{}
	if err := json.Unmarshal(data, ro); err != nil {
		return nil, err
	}
	return ro, nil
}

// minAuthContextRetention is the floor on how long an authorization context
// is kept. It is the value this retention was hardcoded at.
//
// It no longer binds for a default configuration: two interaction windows
// plus the code duration and the margin come to 16 minutes, so the default
// retention is one minute longer than the 15 this was fixed at. The floor
// still covers configurations whose deadlines are shorter than it.
const minAuthContextRetention = 15 * time.Minute

// authContextRetention is how long an authorization context is kept.
//
// This is the outer bound on the whole flow, not an authorization decision:
// AuthorizationContext.ExpiresAt and CodeExpiresAt are checked explicitly and
// are what actually refuse a stale session. But an eviction before those
// deadlines makes a live session vanish mid-flow and surface as "session not
// found", so the retention has to cover them.
//
// It was a flat 15 minutes, which covered the deadlines only because both
// were themselves hardcoded to code_duration. Now that presentation_timeout
// is read (SUNET/vc#756) an operator can set a presentation window longer
// than the retention, so the retention is derived from the deadlines rather
// than assumed to exceed them: the user spends up to presentation_timeout
// presenting, and the code issued afterwards lives a further code_duration.
//
// The 15-minute floor is kept, so the default configuration - 300s + 300s -
// retains for exactly as long as it always has.
func authContextRetention(cfg *model.Cfg) time.Duration {
	if cfg == nil || cfg.Verifier == nil {
		return minAuthContextRetention
	}
	// Twice, because a session that shows a credential display has two
	// timed interactions in series: the wallet presenting, then a person
	// reading the display and confirming. Each gets presentation_timeout.
	needed := 2 * cfg.Verifier.Inbound.OpenID4VP.GetPresentationTimeout()
	if op := cfg.Verifier.Outbound.OIDCProvider; op != nil && op.CodeDuration > 0 {
		needed += time.Duration(op.CodeDuration) * time.Second
	}
	return max(needed+codeIssuanceMargin, minAuthContextRetention)
}

// codeIssuanceMargin covers the gap between a presentation being accepted
// and its authorization code being written.
//
// presentation_timeout + code_duration is the deadline arithmetic, and it
// is exact only if the code is issued at the instant the window closes. It
// is not: the deadline is checked, then the presentation is verified, then
// the code is stored - and MongoDB anchors its retention to the original
// CreatedAt, so unlike MemoryStore it does not get a fresh lease on that
// write. Without a margin a code issued right at the deadline could be
// evicted in the same second it became valid.
const codeIssuanceMargin = time.Minute

// PresentationScopedTTL is the retention for a cache a live presentation
// depends on: at least floor, and never less than the presentation window.
//
// Exported so the request-object cache can be written with the same TTL it
// was built with, rather than a second literal that drifts.
func PresentationScopedTTL(cfg *model.Cfg, floor time.Duration) time.Duration {
	return presentationScopedTTL(cfg, floor)
}

func presentationScopedTTL(cfg *model.Cfg, floor time.Duration) time.Duration {
	if cfg == nil || cfg.Verifier == nil {
		return floor
	}
	return max(cfg.Verifier.Inbound.OpenID4VP.GetPresentationTimeout(), floor)
}
