package oauth2

import (
	"encoding/json"
	"fmt"
	"slices"
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

	// The spellings OpenID4VCI 1.1's change log records, which its own
	// normative text does not apply (openid/OpenID4VCI#811, CS01_07).
	changeLogChallengeEndpointName  = "interactive_authorization_endpoint"
	changeLogRequireInteractiveName = "require_interactive_authorization_request"
)

// metadataNameAlternatives is every spelling each member may be published
// under: the normative one, and the one the change log records.
//
// A CLOSED set, and that is a deliberate narrowing from "any configured
// string". The document is parsed back out of its own JSON at the signing
// boundary (internal/issuer/apiv1/sign_metadata.go unmarshals it into a
// fresh struct as a whitelist), so a member this type cannot RECOGNISE is
// dropped before the JWT is built - and signed_metadata would then be
// missing a member the served document has, which is precisely the
// disagreement carrying the names on the struct exists to prevent.
//
// Recognising a fixed set keeps that round trip intact, and costs nothing
// real: CS01_07 is about which of two spellings the working group settles
// on, not about renaming these to anything at all.
var metadataNameAlternatives = map[string][]string{
	defaultChallengeEndpointName:  {defaultChallengeEndpointName, changeLogChallengeEndpointName},
	defaultRequireInteractiveName: {defaultRequireInteractiveName, changeLogRequireInteractiveName},
}

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
	if err := validateRenames(renames); err != nil {
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

// validateRenames refuses a spelling this type cannot read back.
//
// That is the whole rule, and it is stronger than it looks: because the
// permitted spellings are a closed set that contains no member of this
// document, a permitted rename cannot displace an existing member and two
// permitted renames cannot target the same name. Earlier versions checked
// both of those at runtime; the checks were unreachable once the set
// closed, and unreachable code that reads as a safety net is worse than
// none. TestNoAlternativeSpellingCollidesWithARealMember asserts the
// property they were guarding, against the data rather than at runtime,
// so adding a colliding alternative fails there.
func validateRenames(renames map[string]string) error {
	for from, to := range renames {
		if from == to {
			continue
		}
		if !slices.Contains(metadataNameAlternatives[from], to) {
			return fmt.Errorf("authorization server metadata: %q cannot be published as %q; the spellings this server can read back are %v",
				from, to, metadataNameAlternatives[from])
		}
	}
	return nil
}

// ValidateMetadataNames reports whether these names can be published
// without displacing something.
//
// The same rule MarshalJSON enforces, reachable at configuration load so
// that a deployment is refused with a message an operator can act on
// rather than at the moment a wallet asks for the document.
//
// A spelling outside the closed set is refused, which also refuses every
// member this server publishes - "jwks_uri" included. An earlier version
// checked the configured name against a marshalled sample instead, and
// accepted exactly that: almost every member is omitempty, so a zero-value
// document contains none of them and the collision surfaced at signing or
// serving rather than at startup.
func ValidateMetadataNames(names MetadataNames) error {
	endpoint, require := names.resolve()
	return validateRenames(map[string]string{
		defaultChallengeEndpointName:  endpoint,
		defaultRequireInteractiveName: require,
	})
}

// UnmarshalJSON reads the Interactive Authorization members under either
// of their spellings and REMEMBERS which it saw, so that marshalling this
// document again reproduces it.
//
// That round trip is what makes the rename safe to apply at all. The
// served JSON is parsed back into a fresh value of this type on its way to
// being signed, as a whitelist that drops members the struct does not
// know; without this, a renamed member survived into the served document
// and vanished from signed_metadata, and every verifier comparing the two
// would reject the JWT.
func (m *AuthorizationServerMetadata) UnmarshalJSON(data []byte) error {
	// An alias to borrow the struct tags without re-entering this method.
	type plain AuthorizationServerMetadata

	var base plain
	if err := json.Unmarshal(data, &base); err != nil {
		return fmt.Errorf("reading authorization server metadata: %w", err)
	}
	*m = AuthorizationServerMetadata(base)

	var document map[string]json.RawMessage
	if err := json.Unmarshal(data, &document); err != nil {
		return fmt.Errorf("re-reading authorization server metadata for its member names: %w", err)
	}

	// The tagged members were filled by the alias above when the document
	// used the normative names; this picks up the other spelling.
	for _, name := range metadataNameAlternatives[defaultChallengeEndpointName] {
		if name == defaultChallengeEndpointName {
			continue
		}
		if raw, ok := document[name]; ok {
			if err := json.Unmarshal(raw, &m.AuthorizationChallengeEndpoint); err != nil {
				return fmt.Errorf("reading %s: %w", name, err)
			}
			m.iaNames.AuthorizationChallengeEndpoint = name
		}
	}

	for _, name := range metadataNameAlternatives[defaultRequireInteractiveName] {
		if name == defaultRequireInteractiveName {
			continue
		}
		if raw, ok := document[name]; ok {
			if err := json.Unmarshal(raw, &m.RequireInteractiveAuthorization); err != nil {
				return fmt.Errorf("reading %s: %w", name, err)
			}
			m.iaNames.RequireInteractiveAuthorization = name
		}
	}

	return nil
}
