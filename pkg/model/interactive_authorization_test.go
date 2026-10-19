package model

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func enabledIA() *InteractiveAuthorization {
	on := true
	return &InteractiveAuthorization{Enable: &on}
}

// The endpoint is what advertises the mechanism, so a deployment that has
// not turned it on must produce no URL at all - an empty string is what
// suppresses both metadata members downstream.
func TestInteractiveAuthorization_ChallengeEndpoint(t *testing.T) {
	assert.Equal(t, "https://issuer.example.com/authorize-challenge",
		enabledIA().ChallengeEndpoint("https://issuer.example.com"))

	assert.Equal(t, "https://issuer.example.com/authorize-challenge",
		enabledIA().ChallengeEndpoint("https://issuer.example.com/"),
		"a trailing slash on the issuer identifier must not double the separator")

	assert.Empty(t, (&InteractiveAuthorization{}).ChallengeEndpoint("https://issuer.example.com"))
	assert.Empty(t, (*InteractiveAuthorization)(nil).ChallengeEndpoint("https://issuer.example.com"))
}

// require_interactive_authorization without the endpoint is forbidden, so
// Required is false unless the mechanism is also offered.
func TestInteractiveAuthorization_RequiredImpliesEnabled(t *testing.T) {
	on, off := true, false

	assert.True(t, (&InteractiveAuthorization{Enable: &on, RequireInteractiveAuthorization: &on}).Required())
	assert.False(t, (&InteractiveAuthorization{Enable: &off, RequireInteractiveAuthorization: &on}).Required(),
		"a server cannot require a mechanism it does not offer")
	assert.False(t, (&InteractiveAuthorization{Enable: &on}).Required())
}

// CS01_08: the 1.1 draft's normative sentence says the derived Origin and
// its own example in that sentence shows the endpoint URL. "origin"
// follows the words, "endpoint" exists so a counterparty that read it the
// other way is a config change rather than a rebuild.
func TestInteractiveAuthorization_PresentationAudience(t *testing.T) {
	for name, tc := range map[string]struct {
		scope  string
		prefix string
		want   string
	}{
		"the derived Origin, which the normative sentence asks for": {
			want: "ia:https://issuer.example.com",
		},
		"the endpoint URL its own example shows": {
			scope: "endpoint",
			want:  "ia:https://issuer.example.com/authorize-challenge",
		},
		"the change log's prefix": {
			prefix: "iae:",
			want:   "iae:https://issuer.example.com",
		},
	} {
		t.Run(name, func(t *testing.T) {
			ia := enabledIA()
			ia.SDJWTBindingScope = tc.scope
			ia.BindingPrefix = tc.prefix

			got, err := ia.PresentationAudience("https://issuer.example.com")
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	t.Run("a public URL that is not absolute is refused, not guessed at", func(t *testing.T) {
		_, err := enabledIA().PresentationAudience("issuer.example.com")
		require.Error(t, err)
	})

	// RFC 6454 §6.2. The wallet derives the audience from an origin it
	// canonicalises itself and compares as a plain string, so a public URL
	// written with an explicit default port or an uppercase host - both
	// valid configuration, neither ever emitted by a browser - would
	// otherwise produce an audience no wallet computes.
	t.Run("the origin is serialised the way a browser would", func(t *testing.T) {
		for name, tc := range map[string]struct{ publicURL, want string }{
			"an explicit default port is dropped": {
				publicURL: "https://issuer.example.com:443",
				want:      "ia:https://issuer.example.com",
			},
			"a non-default port is kept": {
				publicURL: "https://issuer.example.com:8443",
				want:      "ia:https://issuer.example.com:8443",
			},
			"the host is lowercased": {
				publicURL: "https://Issuer.Example.COM",
				want:      "ia:https://issuer.example.com",
			},
			"both at once": {
				publicURL: "HTTPS://Issuer.Example.COM:443",
				want:      "ia:https://issuer.example.com",
			},
		} {
			t.Run(name, func(t *testing.T) {
				got, err := enabledIA().PresentationAudience(tc.publicURL)
				require.NoError(t, err)
				assert.Equal(t, tc.want, got)
			})
		}
	})
}

// RFC 6454 §4: an Origin is scheme, host and port - never the path.
func TestInteractiveAuthorization_ChallengeEndpointOrigin(t *testing.T) {
	origin, err := enabledIA().ChallengeEndpointOrigin("https://issuer.example.com/issuer")
	require.NoError(t, err)
	assert.Equal(t, "https://issuer.example.com", origin)

	origin, err = enabledIA().ChallengeEndpointOrigin("https://issuer.example.com:8443")
	require.NoError(t, err)
	assert.Equal(t, "https://issuer.example.com:8443", origin, "a non-default port is part of the Origin")

	// expected_origins is compared against what the browser reports, which
	// never carries the default port and never carries case.
	origin, err = enabledIA().ChallengeEndpointOrigin("HTTPS://Issuer.Example.COM:443")
	require.NoError(t, err)
	assert.Equal(t, "https://issuer.example.com", origin)

	_, err = enabledIA().ChallengeEndpointOrigin("not a url at all")
	require.Error(t, err)
}

// Empty means every type the build implements: what this server can do is
// a property of the code, not of configuration.
func TestInteractiveAuthorization_Offers(t *testing.T) {
	assert.True(t, enabledIA().Offers(InteractionOpenID4VPPresentation))

	narrowed := enabledIA()
	narrowed.InteractionTypesSupported = []string{InteractionAuthViaWeb}
	assert.False(t, narrowed.Offers(InteractionOpenID4VPPresentation))
	assert.True(t, narrowed.Offers(InteractionAuthViaWeb))
}

func TestInteractiveAuthorization_InteractionType(t *testing.T) {
	assert.Equal(t, "urn:openid:dcp:ia:openid4vp_presentation",
		enabledIA().InteractionType(InteractionOpenID4VPPresentation))

	renamed := enabledIA()
	renamed.InteractionTypePrefix = "urn:openid:dcp:iae:"
	assert.Equal(t, "urn:openid:dcp:iae:openid4vp_presentation",
		renamed.InteractionType(InteractionOpenID4VPPresentation),
		"CS01_07: the namespace has to move if the working group renames it")
}

// The served document is what a wallet reads to discover the mechanism, so
// the endpoint appears exactly when it is offered - and the configured
// spellings reach the JSON, not just the Go field.
func TestInteractiveAuthorizationReachesTheServedMetadata(t *testing.T) {
	server := &OAuthServer{TokenEndpoint: "https://issuer.example.com/token"}

	t.Run("off", func(t *testing.T) {
		document := metadataJSON(t, server, &InteractiveAuthorization{})
		assert.NotContains(t, document, "authorization_challenge_endpoint")
		assert.NotContains(t, document, "require_interactive_authorization")
	})

	t.Run("on", func(t *testing.T) {
		on := true
		document := metadataJSON(t, server, &InteractiveAuthorization{
			Enable:                          &on,
			RequireInteractiveAuthorization: &on,
		})
		assert.Equal(t, "https://issuer.example.com/authorize-challenge",
			document["authorization_challenge_endpoint"])
		assert.Equal(t, true, document["require_interactive_authorization"])
	})

	t.Run("on, under the change log's names", func(t *testing.T) {
		on := true
		document := metadataJSON(t, server, &InteractiveAuthorization{
			Enable:                          &on,
			RequireInteractiveAuthorization: &on,
			MetadataEndpointParameter:       "interactive_authorization_endpoint",
			MetadataRequireParameter:        "require_interactive_authorization_request",
		})
		assert.Equal(t, "https://issuer.example.com/authorize-challenge",
			document["interactive_authorization_endpoint"])
		assert.Equal(t, true, document["require_interactive_authorization_request"])
		assert.NotContains(t, document, "authorization_challenge_endpoint",
			"the normative name must be gone, not published alongside the renamed one")
	})
}

func metadataJSON(t *testing.T, server *OAuthServer, ia *InteractiveAuthorization) map[string]any {
	t.Helper()

	raw, err := json.Marshal(server.GenerateMetadata(t.Context(), "https://issuer.example.com", false, nil, ia))
	require.NoError(t, err)

	document := map[string]any{}
	require.NoError(t, json.Unmarshal(raw, &document))
	return document
}

// The bound in AuthSessionTTLSeconds's validate tag is the one thing a Go
// struct tag cannot build from a constant, so this reads it back. Raising
// MaxAuthSessionTTLSeconds without the tag would leave config validation
// enforcing the old ceiling; lowering it without the tag would let a
// configuration through that the cache cannot hold.
func TestMaxAuthSessionTTLMatchesItsTag(t *testing.T) {
	field, ok := reflect.TypeOf(InteractiveAuthorization{}).FieldByName("AuthSessionTTLSeconds")
	require.True(t, ok)

	want := fmt.Sprintf("lte=%d", MaxAuthSessionTTLSeconds)
	assert.Contains(t, field.Tag.Get("validate"), want,
		"the validate tag must enforce MaxAuthSessionTTLSeconds")
}

// And the ceiling has to be long enough to be usable: an exchange is a
// user presenting a credential, not a machine round trip.
func TestDefaultAuthSessionTTLIsWithinTheCeiling(t *testing.T) {
	assert.LessOrEqual(t, int((&InteractiveAuthorization{}).AuthSessionTTL().Seconds()), MaxAuthSessionTTLSeconds)
	assert.GreaterOrEqual(t, MaxAuthSessionTTLSeconds, 300, "an exchange needs room for a person to answer")
}
