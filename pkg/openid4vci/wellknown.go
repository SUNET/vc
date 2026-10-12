package openid4vci

import (
	"net/url"
	"strings"
)

// WellKnownURL builds the URL at which an entity publishes a well-known
// document, per RFC 8615 §3.
//
// The suffix is INSERTED between the host and the path, rather than
// appended to the whole identifier. OpenID4VCI 1.0 requires this for
// Credential Issuer Metadata, and RFC 8414 §3 requires the same for
// Authorization Server Metadata, so an identifier carrying a tenant path
// publishes at the host root:
//
//	https://example.com         → https://example.com/.well-known/<suffix>
//	https://example.com/tenant  → https://example.com/.well-known/<suffix>/tenant
//
// A terminating "/" on the identifier is removed first. That sentence is
// the only normative difference OpenID4VCI 1.1 makes here, and it closes a
// real gap: without it `https://example.com/tenant` and
// `https://example.com/tenant/` resolve to different URLs, so two
// conformant wallets can disagree about where one tenant publishes.
//
// An identifier that will not parse, or has no host, falls back to plain
// appending. That is not correct, but it is what the caller would have
// done anyway, and refusing here would turn a malformed configuration into
// a nil URL far from where it was written.
func WellKnownURL(entity, suffix string) string {
	entity = strings.TrimSuffix(entity, "/")

	parsed, err := url.Parse(entity)
	if err != nil || parsed.Host == "" {
		return entity + "/.well-known/" + suffix
	}

	path := strings.TrimPrefix(parsed.Path, "/")
	base := parsed.Scheme + "://" + parsed.Host
	if path == "" {
		return base + "/.well-known/" + suffix
	}
	return base + "/.well-known/" + suffix + "/" + path
}
