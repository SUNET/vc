package pubsub

import (
	"crypto/tls"

	"github.com/redis/go-redis/v9"
)

// ClientConfig captures the fields needed to construct a
// redis.UniversalClient. Low-level builder input; the deployment-facing
// yaml-tagged shape lives in pubsub.Config, and cmd/verifier maps between
// the two.
type ClientConfig struct {
	// Addrs lists one or more "<host>:<port>" endpoints. A single entry
	// yields a plain client; multiple entries yield a cluster client,
	// matching redis.UniversalOptions semantics.
	Addrs []string
	// Username and Password carry ACL credentials (Redis 6+ / Valkey)
	// or the single AUTH password on older servers.
	Username string
	Password string
	// DB is the logical database number used by single-node mode
	// (ignored in cluster mode).
	DB int
	// TLS enables TLS for the connection using the system root CAs.
	// Finer-grained control (custom CA, mTLS) belongs behind a dedicated
	// builder; this one is deliberately boring.
	TLS bool
}

// NewClient builds a redis.UniversalClient from cfg. Returns nil
// without error when cfg has no addresses, so callers can treat
// "Redis section omitted" as "no HA pub/sub" without extra branching.
func NewClient(cfg ClientConfig) (redis.UniversalClient, error) {
	if len(cfg.Addrs) == 0 {
		return nil, nil
	}
	opts := &redis.UniversalOptions{
		Addrs:    cfg.Addrs,
		Username: cfg.Username,
		Password: cfg.Password,
		DB:       cfg.DB,
	}
	if cfg.TLS {
		opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return redis.NewUniversalClient(opts), nil
}
