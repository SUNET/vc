package oauth2

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func iaMetadata() *AuthorizationServerMetadata {
	return &AuthorizationServerMetadata{
		Issuer:                          "https://issuer.example.com",
		AuthorizationEndpoint:           "https://issuer.example.com/authorize",
		TokenEndpoint:                   "https://issuer.example.com/token",
		ResponseTypesSupported:          []string{"code"},
		AuthorizationChallengeEndpoint:  "https://issuer.example.com/op/authorize-challenge",
		RequireInteractiveAuthorization: true,
	}
}

func members(t *testing.T, v any) map[string]json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)

	var got map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &got))
	return got
}

// The zero value is the specification: a deployment that configures
// nothing publishes the normative names.
func TestMetadataNamesDefaultToTheNormativeSpelling(t *testing.T) {
	got := members(t, iaMetadata())

	assert.Contains(t, got, "authorization_challenge_endpoint")
	assert.Contains(t, got, "require_interactive_authorization")
	assert.NotContains(t, got, "interactive_authorization_endpoint")
}

func TestMetadataNamesRenameBothMembers(t *testing.T) {
	renamed := iaMetadata().WithInteractiveAuthorizationNames(MetadataNames{
		AuthorizationChallengeEndpoint:  "interactive_authorization_endpoint",
		RequireInteractiveAuthorization: "require_interactive_authorization_request",
	})
	got := members(t, renamed)

	assert.Contains(t, got, "interactive_authorization_endpoint")
	assert.Contains(t, got, "require_interactive_authorization_request")
	assert.NotContains(t, got, "authorization_challenge_endpoint")
	assert.NotContains(t, got, "require_interactive_authorization")

	// Everything else is untouched - the rename must not be a rebuild.
	original := members(t, iaMetadata())
	assert.Equal(t, original["issuer"], got["issuer"])
	assert.Equal(t, original["token_endpoint"], got["token_endpoint"])
	assert.Equal(t, len(original), len(got), "renaming must not add or drop members")
}

// The document is both SERVED and SIGNED. If a rename reached one and not
// the other they would disagree, and every verifier checking the JWT
// against the served document would reject it. Carrying the names on the
// struct and applying them in MarshalJSON is what makes that impossible:
// both paths marshal the same value.
func TestRenameAppliesToEverySerialisation(t *testing.T) {
	renamed := iaMetadata().WithInteractiveAuthorizationNames(MetadataNames{
		AuthorizationChallengeEndpoint: "interactive_authorization_endpoint",
	})

	// By pointer, as the HTTP layer serialises it.
	byPointer := members(t, renamed)
	// By value, as a shallow copy made before signing would be.
	byValue := members(t, *renamed)
	// Nested, as it would be inside any enclosing document.
	nested := members(t, struct {
		M *AuthorizationServerMetadata `json:"m"`
	}{renamed})

	assert.Contains(t, byPointer, "interactive_authorization_endpoint")
	assert.Contains(t, byValue, "interactive_authorization_endpoint")

	var inner map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(nested["m"], &inner))
	assert.Contains(t, inner, "interactive_authorization_endpoint")
}

// Renaming only one of the two is a legitimate state, since the draft's
// two renames could be resolved separately.
func TestMetadataNamesRenameOneMember(t *testing.T) {
	renamed := iaMetadata().WithInteractiveAuthorizationNames(MetadataNames{
		RequireInteractiveAuthorization: "require_interactive_authorization_request",
	})
	got := members(t, renamed)

	assert.Contains(t, got, "authorization_challenge_endpoint")
	assert.Contains(t, got, "require_interactive_authorization_request")
	assert.NotContains(t, got, "require_interactive_authorization")
}

// A member that is absent stays absent: renaming must not conjure one.
func TestRenameDoesNotAddAbsentMembers(t *testing.T) {
	bare := &AuthorizationServerMetadata{
		Issuer:                 "https://issuer.example.com",
		AuthorizationEndpoint:  "https://issuer.example.com/authorize",
		TokenEndpoint:          "https://issuer.example.com/token",
		ResponseTypesSupported: []string{"code"},
	}
	got := members(t, bare.WithInteractiveAuthorizationNames(MetadataNames{
		AuthorizationChallengeEndpoint: "interactive_authorization_endpoint",
	}))

	assert.NotContains(t, got, "interactive_authorization_endpoint")
	assert.NotContains(t, got, "authorization_challenge_endpoint")
}

func TestWithInteractiveAuthorizationNamesDoesNotMutate(t *testing.T) {
	base := iaMetadata()
	_ = base.WithInteractiveAuthorizationNames(MetadataNames{
		AuthorizationChallengeEndpoint: "interactive_authorization_endpoint",
	})

	assert.Contains(t, members(t, base), "authorization_challenge_endpoint",
		"the original must still publish the normative names")
}

// A configured member name is free text written straight into the
// published document, so it has to be refused when it would displace
// something rather than quietly overwriting it.
func TestMetadataNameCollisionsAreRefused(t *testing.T) {
	metadata := validMetadata()
	metadata.AuthorizationChallengeEndpoint = "https://issuer.example.com/authorize-challenge"
	metadata.RequireInteractiveAuthorization = true

	t.Run("a name that is already a member of the document", func(t *testing.T) {
		// "issuer" is the one that does real damage: the endpoint URL would
		// replace the Credential Issuer Identifier, and every wallet
		// reading the document would be pointed somewhere else.
		_, err := json.Marshal(metadata.WithInteractiveAuthorizationNames(MetadataNames{
			AuthorizationChallengeEndpoint: "issuer",
		}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot be published as")
	})

	t.Run("both parameters configured to the same name", func(t *testing.T) {
		// Which one survives is map iteration order, so the served
		// document could differ between restarts - and stop matching the
		// signed_metadata built from the same value.
		_, err := json.Marshal(metadata.WithInteractiveAuthorizationNames(MetadataNames{
			AuthorizationChallengeEndpoint:  "ia_thing",
			RequireInteractiveAuthorization: "ia_thing",
		}))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot be published as")
	})

	t.Run("the change log's names, which collide with nothing", func(t *testing.T) {
		raw, err := json.Marshal(metadata.WithInteractiveAuthorizationNames(MetadataNames{
			AuthorizationChallengeEndpoint:  "interactive_authorization_endpoint",
			RequireInteractiveAuthorization: "require_interactive_authorization_request",
		}))
		require.NoError(t, err)

		document := map[string]any{}
		require.NoError(t, json.Unmarshal(raw, &document))
		assert.Contains(t, document, "interactive_authorization_endpoint")
		assert.Equal(t, "https://issuer.example.com", document["issuer"],
			"the document's own members are untouched")
	})
}

// The same rule, reachable where an operator can read the message.
func TestValidateMetadataNames(t *testing.T) {
	require.NoError(t, ValidateMetadataNames(MetadataNames{}),
		"the zero value is the specification's own names")

	require.NoError(t, ValidateMetadataNames(MetadataNames{
		AuthorizationChallengeEndpoint:  "interactive_authorization_endpoint",
		RequireInteractiveAuthorization: "require_interactive_authorization_request",
	}))

	err := ValidateMetadataNames(MetadataNames{AuthorizationChallengeEndpoint: "token_endpoint"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be published as")

	err = ValidateMetadataNames(MetadataNames{
		AuthorizationChallengeEndpoint:  "same",
		RequireInteractiveAuthorization: "same",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be published as")
}

// Every member this server publishes is refused as a target, which is now
// a consequence of the closed alternatives set rather than of the
// collision check - but it is the property that matters to an operator,
// so it is asserted on the behaviour rather than on the reason.
//
// The history is worth keeping: validating against a marshalled zero
// value accepted "jwks_uri", because almost every member is omitempty and
// so absent from a zero document, and the collision then surfaced at
// signing or serving instead of at startup.
// metadataMemberNames is every JSON member AuthorizationServerMetadata can
// emit, read off the struct tags rather than listed - a list would be a
// second description of the document that nothing keeps in step.
//
// Test-only: nothing in the package needs it since the permitted
// spellings became a closed set. It is here to express the invariant that
// makes that set safe.
func metadataMemberNames(t *testing.T) map[string]bool {
	t.Helper()

	typ := reflect.TypeOf(AuthorizationServerMetadata{})
	members := make(map[string]bool, typ.NumField())

	for i := range typ.NumField() {
		tag := typ.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		if name, _, _ := strings.Cut(tag, ","); name != "" {
			members[name] = true
		}
	}
	return members
}

func TestEveryPublishedMemberIsRefusedAsATarget(t *testing.T) {
	for _, member := range []string{
		"jwks_uri",
		"pushed_authorization_request_endpoint",
		"grant_types_supported",
		"code_challenge_methods_supported",
		"dpop_signing_alg_values_supported",
	} {
		t.Run(member, func(t *testing.T) {
			err := ValidateMetadataNames(MetadataNames{AuthorizationChallengeEndpoint: member})
			require.Error(t, err, "%s is a member this server publishes", member)
		})
	}

	// And it is derived from the struct, so a member added later is
	// covered without anyone remembering to list it.
	members := metadataMemberNames(t)
	assert.Contains(t, members, "issuer")
	assert.Contains(t, members, defaultChallengeEndpointName)
	assert.Greater(t, len(members), 10, "the member set should be the whole document")
}

// The round trip that makes the rename safe at all.
//
// The served document is parsed back into a FRESH AuthorizationServerMetadata
// on its way to being signed - internal/issuer/apiv1/sign_metadata.go does
// exactly this, deliberately, as a whitelist that drops members the struct
// does not know. A renamed member it could not read back therefore reached
// the served JSON and vanished from signed_metadata, and every verifier
// comparing the two would reject the JWT.
//
// So the test is not "MarshalJSON renames": it is "marshal, unmarshal into
// a new value the way the signer does, marshal again, and get the same
// document".
func TestRenamedMembersSurviveTheSigningRoundTrip(t *testing.T) {
	for name, names := range map[string]MetadataNames{
		"the normative spellings":     {},
		"the change log's spellings":  {AuthorizationChallengeEndpoint: changeLogChallengeEndpointName, RequireInteractiveAuthorization: changeLogRequireInteractiveName},
		"one renamed, one left alone": {AuthorizationChallengeEndpoint: changeLogChallengeEndpointName},
		"the other one renamed":       {RequireInteractiveAuthorization: changeLogRequireInteractiveName},
	} {
		t.Run(name, func(t *testing.T) {
			metadata := validMetadata()
			metadata.AuthorizationChallengeEndpoint = "https://issuer.example.com/authorize-challenge"
			metadata.RequireInteractiveAuthorization = true

			served, err := json.Marshal(metadata.WithInteractiveAuthorizationNames(names))
			require.NoError(t, err)

			// What the signer does: unmarshal into a fresh value of this
			// type, then marshal the claims it will put in the JWT.
			var reparsed AuthorizationServerMetadata
			require.NoError(t, json.Unmarshal(served, &reparsed))

			signed, err := json.Marshal(reparsed)
			require.NoError(t, err)

			assert.JSONEq(t, string(served), string(signed),
				"the signed claims must be the served document, member names and all")

			// And the values actually came back, rather than both sides
			// agreeing by both being empty.
			assert.Equal(t, "https://issuer.example.com/authorize-challenge", reparsed.AuthorizationChallengeEndpoint)
			assert.True(t, reparsed.RequireInteractiveAuthorization)
		})
	}
}

// The failure the round trip prevents, stated directly: a spelling this
// type cannot read back must not be configurable, because it would survive
// into the served document and be dropped on the way to the JWT.
func TestUnreadableSpellingsAreRefusedRatherThanSilentlyDropped(t *testing.T) {
	err := ValidateMetadataNames(MetadataNames{
		AuthorizationChallengeEndpoint: "ia_endpoint_we_invented",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read back")

	// Everything in the closed set is accepted, in every combination.
	for _, endpoint := range metadataNameAlternatives[defaultChallengeEndpointName] {
		for _, require_ := range metadataNameAlternatives[defaultRequireInteractiveName] {
			assert.NoError(t, ValidateMetadataNames(MetadataNames{
				AuthorizationChallengeEndpoint:  endpoint,
				RequireInteractiveAuthorization: require_,
			}), "%s + %s", endpoint, require_)
		}
	}
}

// The collision guard in validateRenames is unreachable while no
// alternative spelling is also a member of the document - which is what
// this asserts, so that adding an alternative that collides fails here
// rather than at the moment a document is marshalled.
func TestNoAlternativeSpellingCollidesWithARealMember(t *testing.T) {
	members := metadataMemberNames(t)

	for member, alternatives := range metadataNameAlternatives {
		for _, alternative := range alternatives {
			if alternative == member {
				continue // the member's own name, necessarily present
			}
			assert.NotContains(t, members, alternative,
				"%q is both an alternative spelling and a member this type emits", alternative)
		}
	}

}
