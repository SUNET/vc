package pubsub

// Config is the deployment-facing configuration for the pub/sub bus.
//
// Supports Redis and Valkey today (both speak RESP, so the same client
// serves both; Backend only decides what logs and metrics identify it as).
// Omitted in standalone deployments; when omitted in HA, notifications
// stay in-process and do not cross nodes.
type Config struct {
	// Backend selects the RESP backend; "redis" or "valkey". Defaults
	// to "redis" when omitted.
	Backend string `yaml:"backend" validate:"omitempty,oneof=redis valkey" default:"redis"`
	// Addrs lists one or more "<host>:<port>" endpoints. A single entry
	// yields a plain client; multiple entries yield a cluster client.
	Addrs []string `yaml:"addrs" validate:"required,min=1,dive,hostname_port" doc_example:"[\"redis:6379\"]"`
	// Username is the ACL username (Redis 6+ / Valkey). Optional.
	Username string `yaml:"username,omitempty"`
	// Password is the ACL password (Redis 6+ / Valkey) or the single
	// AUTH password on older servers. Optional.
	Password string `yaml:"password,omitempty"`
	// DB is the logical database number used by single-node mode
	// (ignored in cluster mode).
	DB int `yaml:"db" default:"0"`
	// TLS enables TLS for the client connection, using system roots.
	TLS bool `yaml:"tls" default:"false"`
}
