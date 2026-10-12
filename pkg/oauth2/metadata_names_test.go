package oauth2

import (
	"encoding/json"
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
		assert.Contains(t, err.Error(), "already a member")
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
		assert.Contains(t, err.Error(), "both configured to be published as")
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
	require.NoError(t, ValidateMetadataNames(MetadataNames{}, nil),
		"the zero value is the specification's own names")

	require.NoError(t, ValidateMetadataNames(MetadataNames{
		AuthorizationChallengeEndpoint:  "interactive_authorization_endpoint",
		RequireInteractiveAuthorization: "require_interactive_authorization_request",
	}, nil))

	err := ValidateMetadataNames(MetadataNames{AuthorizationChallengeEndpoint: "token_endpoint"}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already a member")

	err = ValidateMetadataNames(MetadataNames{
		AuthorizationChallengeEndpoint:  "same",
		RequireInteractiveAuthorization: "same",
	}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "both configured")
}
