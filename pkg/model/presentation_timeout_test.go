package model

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/creasty/defaults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// GetPresentationTimeout must never hand a caller a zero duration. Callers
// turn it into a session expiry, and AuthorizationContext.ExpiresAt of 0
// means "never expires" - so a nil or unset config falling through as zero
// would remove the deadline instead of applying the default one.
func TestGetPresentationTimeoutNeverReturnsZero(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  *OpenID4VPConfig
		want time.Duration
	}{
		{"nil config", nil, DefaultPresentationTimeout},
		{"unset field", &OpenID4VPConfig{}, DefaultPresentationTimeout},
		{"negative", &OpenID4VPConfig{PresentationTimeout: -1}, DefaultPresentationTimeout},
		{"configured", &OpenID4VPConfig{PresentationTimeout: 45}, 45 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.cfg.GetPresentationTimeout()
			assert.NotZero(t, got)
			assert.Equal(t, tc.want, got)
		})
	}
}

// The nil fallback has to agree with the struct tag, or a config that omits
// the openid4vp section behaves differently from one that spells out the
// documented default.
func TestPresentationTimeoutFallbackMatchesTheStructTag(t *testing.T) {
	var cfg OpenID4VPConfig
	require.NoError(t, defaults.Set(&cfg))

	assert.Equal(t, DefaultPresentationTimeout, cfg.GetPresentationTimeout(),
		"DefaultPresentationTimeout and the `default:\"300\"` tag have drifted apart")
}

// A tripwire, not proof: it cannot tell whether a field is read, only that
// somebody has written down where. refresh_token_duration sat here for as
// long as it did because nothing forced that question to be asked - it was
// validate:"required", documented and defaulted, and the token endpoint
// implements no refresh_token grant to spend it (SUNET/vc#756).
//
// Adding a duration to OIDCOP fails this until the entry names its reader.
// The behaviour itself is pinned by the tests in internal/verifier.
func TestEveryOIDCOPDurationNamesItsReader(t *testing.T) {
	readers := map[string]string{
		"SessionDuration":     "internal/verifier/httpserver/service.go: userSessionMaxAge -> the verifier_user_session cookie MaxAge",
		"CodeDuration":        "internal/verifier/apiv1/handler_openid4vp.go: authCtx.CodeExpiresAt",
		"AccessTokenDuration": "internal/verifier/apiv1/handler_oidc.go: generateAccessToken",
		"IDTokenDuration":     "internal/verifier/apiv1/handler_oidc.go: generateIDToken",
	}

	typ := reflect.TypeOf(OIDCOP{})
	var found int
	for i := range typ.NumField() {
		name := typ.Field(i).Name
		if !strings.HasSuffix(name, "Duration") && !strings.HasSuffix(name, "Timeout") {
			continue
		}
		found++
		assert.Contains(t, readers, name,
			"OIDCOP.%s is a configurable duration with no reader recorded - wire it up, or remove it (SUNET/vc#756)", name)
	}

	// ... and the walk really did look at the fields, so the loop cannot
	// pass by finding none.
	assert.Equal(t, len(readers), found, "the reader list and OIDCOP have drifted apart")
}
