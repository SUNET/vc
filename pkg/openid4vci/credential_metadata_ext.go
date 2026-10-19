package openid4vci

import (
	"encoding/json"
	"fmt"
	"slices"
)

// credentialMetadataKnownMembers are the members this type models. They
// are matched by EXACT name when splitting a document, which is the
// whole point of doing the split by hand.
//
// encoding/json matches struct field names CASE-INSENSITIVELY, so a
// decode that filled the struct and then collected "everything else"
// would bind `DISPLAY` to Display AND keep it as an extension - and
// re-encoding would emit both, with the extension silently overriding
// the modelled member. Selecting the known names exactly, before the
// struct decode, is what stops that.
var credentialMetadataKnownMembers = []string{"display", "claims"}

// MarshalJSON emits the modelled members and the extensions as one
// object.
//
// Extensions are written at the TOP level, beside display and claims,
// because that is where OpenID4VCI 1.1 puts an extension: a
// collision-resistant name holding an object. An extension that
// collides with a modelled member is refused rather than silently
// dropped or duplicated - a document that says `display` twice means
// different things to different readers, which for a member carrying a
// secret is not a formatting question.
func (c CredentialMetadata) MarshalJSON() ([]byte, error) {
	type plain CredentialMetadata // no methods, so no recursion
	encoded, err := json.Marshal(plain(c))
	if err != nil {
		return nil, err
	}
	if len(c.Extensions) == 0 {
		return encoded, nil
	}

	var members map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &members); err != nil {
		return nil, fmt.Errorf("credential_metadata: %w", err)
	}
	if members == nil {
		members = map[string]json.RawMessage{}
	}
	for name, value := range c.Extensions {
		if slices.Contains(credentialMetadataKnownMembers, name) {
			return nil, fmt.Errorf("credential_metadata: extension %q collides with a modelled member", name)
		}
		if name == "" {
			return nil, fmt.Errorf("credential_metadata: an extension member has no name")
		}
		members[name] = value
	}
	return json.Marshal(members)
}

// UnmarshalJSON fills the modelled members and keeps everything else.
//
// Kept rather than dropped because a relay or proxy MUST preserve
// members it does not understand: dropping one here would make this
// build a lossy hop for an extension it simply has not been taught.
func (c *CredentialMetadata) UnmarshalJSON(data []byte) error {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil {
		return fmt.Errorf("credential_metadata: %w", err)
	}

	// The modelled members, selected by exact name BEFORE the struct
	// decode - see credentialMetadataKnownMembers.
	known := map[string]json.RawMessage{}
	for _, name := range credentialMetadataKnownMembers {
		if value, ok := members[name]; ok {
			known[name] = value
			delete(members, name)
		}
	}
	knownJSON, err := json.Marshal(known)
	if err != nil {
		return fmt.Errorf("credential_metadata: %w", err)
	}
	type plain CredentialMetadata
	var decoded plain
	if err := json.Unmarshal(knownJSON, &decoded); err != nil {
		return fmt.Errorf("credential_metadata: %w", err)
	}

	*c = CredentialMetadata(decoded)
	if len(members) > 0 {
		c.Extensions = members
	}
	return nil
}
