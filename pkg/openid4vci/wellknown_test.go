package openid4vci

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The suffix goes BETWEEN the host and the path, and a terminating slash
// on the identifier is removed first.
//
// The insertion is OpenID4VCI 1.0 §12.2.2 and RFC 8414 §3; the trailing
// slash is the only normative difference 1.1 makes here. Both halves are
// asserted separately below, because they fail separately: appending
// instead of inserting breaks every tenant-path identifier, while keeping
// the trailing slash breaks only the one that has one - and those are two
// different bugs with two different ages.
func TestWellKnownURL(t *testing.T) {
	const suffix = "openid-credential-issuer"

	t.Run("host only", func(t *testing.T) {
		assert.Equal(t, "https://issuer.example.com/.well-known/"+suffix,
			WellKnownURL("https://issuer.example.com", suffix))
	})

	t.Run("host with a trailing slash", func(t *testing.T) {
		assert.Equal(t, "https://issuer.example.com/.well-known/"+suffix,
			WellKnownURL("https://issuer.example.com/", suffix))
	})

	t.Run("tenant path: the suffix is inserted, not appended", func(t *testing.T) {
		assert.Equal(t, "https://issuer.example.com/.well-known/"+suffix+"/tenant",
			WellKnownURL("https://issuer.example.com/tenant", suffix))
	})

	t.Run("tenant path with a trailing slash resolves to the same URL", func(t *testing.T) {
		// This row IS the 1.1 delta. Without the trim, these two
		// identifiers publish at different URLs and two conformant wallets
		// disagree about where one tenant's metadata lives.
		assert.Equal(t, WellKnownURL("https://issuer.example.com/tenant", suffix),
			WellKnownURL("https://issuer.example.com/tenant/", suffix))
	})

	t.Run("nested tenant path", func(t *testing.T) {
		assert.Equal(t, "https://issuer.example.com/.well-known/"+suffix+"/a/b",
			WellKnownURL("https://issuer.example.com/a/b", suffix))
	})

	t.Run("subdomain tenant is untouched", func(t *testing.T) {
		assert.Equal(t, "https://tenant.issuer.example.com/.well-known/"+suffix,
			WellKnownURL("https://tenant.issuer.example.com", suffix))
	})

	t.Run("any suffix, not just this one", func(t *testing.T) {
		assert.Equal(t, "https://issuer.example.com/.well-known/oauth-authorization-server/tenant",
			WellKnownURL("https://issuer.example.com/tenant", "oauth-authorization-server"))
	})

	t.Run("an identifier with no host falls back to appending", func(t *testing.T) {
		// Not correct, but it is what the caller would have done anyway,
		// and refusing here would surface a malformed configuration as a
		// nil URL far from where it was written.
		assert.Equal(t, "not-a-url/.well-known/"+suffix, WellKnownURL("not-a-url", suffix))
	})
}
