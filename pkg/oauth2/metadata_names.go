package oauth2

import (
	"encoding/json"
	"fmt"
)

// MetadataNames overrides the JSON member names of the Interactive
// Authorization parameters.
//
// It exists because OpenID4VCI 1.1 is an editor's draft that contradicts
// itself about what they are called: its change log records a rename to
// interactive_authorization_endpoint and
// require_interactive_authorization_request, which its own normative text
// does not apply (openid/OpenID4VCI#811, WE BUILD CS-01 NOTE CS01_07). A
// deployment interoperating with a counterparty that read the change log
// has to be able to say so without a rebuild.
//
// Empty fields keep the normative names, so the zero value is the
// specification and a deployment that configures nothing is unaffected.
type MetadataNames struct {
	AuthorizationChallengeEndpoint  string
	RequireInteractiveAuthorization string
}

func (n MetadataNames) resolve() (endpoint, require string) {
	endpoint, require = n.AuthorizationChallengeEndpoint, n.RequireInteractiveAuthorization
	if endpoint == "" {
		endpoint = defaultChallengeEndpointName
	}
	if require == "" {
		require = defaultRequireInteractiveName
	}
	return endpoint, require
}

const (
	defaultChallengeEndpointName  = "authorization_challenge_endpoint"
	defaultRequireInteractiveName = "require_interactive_authorization"
)

// WithInteractiveAuthorizationNames returns a copy of m that serialises its
// Interactive Authorization members under the given names.
//
// Set once where the metadata is built. Everything that serialises this
// type afterwards picks the names up on its own, which is the property
// that matters: the document is BOTH served as JSON and signed into
// signed_metadata, and if a rename reached one and not the other the two
// would disagree and every verifier checking the JWT against the served
// document would reject it.
//
// That is why this is carried on the struct and applied by MarshalJSON
// rather than offered as a "marshal it this way" helper. A helper can be
// forgotten at one of two call sites; a marshaller cannot.
func (m *AuthorizationServerMetadata) WithInteractiveAuthorizationNames(names MetadataNames) *AuthorizationServerMetadata {
	if m == nil {
		return nil
	}
	variant := *m
	variant.iaNames = names
	return &variant
}

// MarshalJSON renames the Interactive Authorization members, and otherwise
// serialises exactly as the struct tags say.
//
// The rename is applied to the marshalled form rather than by building the
// document from a map, so the struct stays the single description of what
// this server publishes: a member cannot be lost by being forgotten in a
// second construction site.
func (m AuthorizationServerMetadata) MarshalJSON() ([]byte, error) {
	// An alias to borrow the struct tags without re-entering this method.
	type plain AuthorizationServerMetadata

	raw, err := json.Marshal(plain(m))
	if err != nil {
		return nil, fmt.Errorf("marshalling authorization server metadata: %w", err)
	}

	endpoint, require := m.iaNames.resolve()
	if endpoint == defaultChallengeEndpointName && require == defaultRequireInteractiveName {
		return raw, nil
	}

	// A map, not a string replacement: a member's VALUE could contain the
	// normative name - an endpoint URL ending in
	// /authorization_challenge_endpoint is unlikely but not forbidden -
	// and renaming inside a value would corrupt the document silently.
	var document map[string]json.RawMessage
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, fmt.Errorf("re-reading authorization server metadata to rename its members: %w", err)
	}

	renames := map[string]string{
		defaultChallengeEndpointName:  endpoint,
		defaultRequireInteractiveName: require,
	}

	// Refuse rather than rename over something.
	//
	// A configured name is free text. If it lands on a member this
	// document already has - "issuer" is the obvious way to do real damage -
	// the assignment below would silently replace a required value with an
	// endpoint URL. And if both names are configured the same, which of the
	// two survives is decided by map iteration order, so the served
	// document would differ between restarts and stop matching its own
	// signature.
	//
	// Neither is recoverable at this point, and MarshalJSON is the last
	// place that sees both names, so it reports instead of guessing.
	// (ValidateMetadataNames catches the same thing at config load, where
	// an operator can read the message.)
	if err := validateRenames(document, renames); err != nil {
		return nil, err
	}

	for from, to := range renames {
		if from == to {
			continue
		}
		if value, ok := document[from]; ok {
			delete(document, from)
			document[to] = value
		}
	}

	return json.Marshal(document)
}

// validateRenames refuses a rename that would collide with a member the
// document already carries, or with the other rename's target.
func validateRenames(document map[string]json.RawMessage, renames map[string]string) error {
	targets := map[string]string{}
	for from, to := range renames {
		if from == to {
			continue
		}
		if _, taken := document[to]; taken {
			return fmt.Errorf("authorization server metadata: cannot publish %q as %q, which is already a member of this document", from, to)
		}
		if other, clash := targets[to]; clash {
			return fmt.Errorf("authorization server metadata: %q and %q are both configured to be published as %q", other, from, to)
		}
		targets[to] = from
	}
	return nil
}

// ValidateMetadataNames reports whether these names can be published
// without displacing something.
//
// The same rule MarshalJSON enforces, reachable at configuration load so
// that a deployment is refused with a message an operator can act on
// rather than at the moment a wallet asks for the document. It is checked
// against a REAL metadata document - the names it must not collide with
// are the members this type emits, and listing them here by hand would be
// a second source of truth that drifts.
func ValidateMetadataNames(names MetadataNames, sample *AuthorizationServerMetadata) error {
	if sample == nil {
		sample = &AuthorizationServerMetadata{}
	}

	// Marshalled WITHOUT the names applied, which is the document the
	// renames are about to be applied to.
	plainDocument, err := json.Marshal(*sample.WithInteractiveAuthorizationNames(MetadataNames{}))
	if err != nil {
		return fmt.Errorf("marshalling metadata to check its member names: %w", err)
	}

	var document map[string]json.RawMessage
	if err := json.Unmarshal(plainDocument, &document); err != nil {
		return fmt.Errorf("re-reading metadata to check its member names: %w", err)
	}

	endpoint, require := names.resolve()
	return validateRenames(document, map[string]string{
		defaultChallengeEndpointName:  endpoint,
		defaultRequireInteractiveName: require,
	})
}
