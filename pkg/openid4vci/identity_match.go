package openid4vci

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"slices"

	"github.com/SUNET/vc/pkg/claimpath"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// IdentityMatch decides whether the Holder who presented a credential is
// the one an issuance was prepared for.
//
// It is supplied by the CALLER that prepared the issuance - typically a
// portal that has already authenticated the user and let them choose what
// is being issued - and not read from this server's configuration. Only
// that caller knows what "the same user" means for its own session: which
// claims identify the person, and what values it authenticated them
// under. Configuration can say "family_name must be one of these"; it
// cannot say "must be the person currently signed in to this session",
// which is the statement that matters.
//
// Every entry must pass. An empty rule is refused rather than treated as
// "anything matches": a caller that supplies no rule has not said the
// issuance is unbound, it has said nothing, and the difference between
// those two is the whole point of the mechanism.
//
// Omitting the rule is not the way to ask for an unbound issuance either -
// PrepareIssuance requires one, so an absent rule is refused as a missing
// field rather than honoured as a choice. An offer any wallet may complete
// is the pre-authorized grant, asked for by name.
type IdentityMatch struct {
	// Claims lists the claims of the presented credential, each with the
	// test it must pass.
	//
	// A path is a claims path pointer, or a dotted claim name read the way
	// the presented credential's format reads it - nested for SD-JWT VC,
	// "<namespace>.<element>" for mdoc - so a caller writes the same path
	// it would write anywhere else in this API. The earlier form, an
	// object from dotted claim names to tests, is read too.
	Claims ClaimMatches `json:"claims" bson:"claims" validate:"required,min=1"`
}

// ClaimMatch is one claim of the presented credential and the test it
// must pass.
type ClaimMatch struct {
	// Path is the claim.
	Path claimpath.Pointer
	ClaimTest
}

// ClaimMatches is the list of claim matches.
type ClaimMatches []ClaimMatch

// ClaimTest is how one claim is compared.
//
// An object rather than a bare value, so that a comparison added later -
// case-insensitive, date-normalising, a range - does not change the shape
// of a request a caller already sends.
type ClaimTest struct {
	// Equals is the exact value the claim must have. Where the claim is an
	// array, at least one element must equal it.
	//
	// Exact, and deliberately not case-folded or otherwise normalised:
	// folding a personal name is locale-dependent and gets it wrong for
	// someone. A caller comparing values that came from two different
	// authorities should expect to normalise before it gets here, or to
	// match on an identifier rather than a name - see the package
	// documentation on IdentityMatch for why that is usually the better
	// rule anyway.
	Equals string `json:"equals" bson:"equals"`
}

// Validate refuses a rule that cannot do its job.
//
// Called when the rule is accepted, not when it is evaluated: a caller
// that mistypes a comparator should be told at the moment it prepares the
// issuance, not when a Holder is standing there with a wallet open.
func (m *IdentityMatch) Validate() error {
	if m == nil || len(m.Claims) == 0 {
		return fmt.Errorf("identity match: no claims to match on; a rule that matches anything is refused - an issuance any wallet may complete is the pre-authorized grant, which is a different request")
	}

	for _, claim := range m.Claims {
		_, pending := claim.Path.Pending()
		switch {
		case claim.Path.IsZero():
			return fmt.Errorf("identity match: a claim path is empty")
		case !pending && !claim.Path.SelectsOne():
			return fmt.Errorf("identity match: claim %s selects every element of an array; a match compares one claim", claim.Path)
		case claim.Equals == "":
			return fmt.Errorf("identity match: claim %s has no comparison; the only one supported is \"equals\", and it may not be empty", claim.Path)
		}
	}
	return nil
}

// ClaimPaths returns the paths this rule tests, rendered for a log line or
// an error.
func (m *IdentityMatch) ClaimPaths() []string {
	if m == nil {
		return nil
	}
	paths := make([]string, 0, len(m.Claims))
	for _, claim := range m.Claims {
		paths = append(paths, claim.Path.String())
	}
	return paths
}

// claimMatchWire is a claim match on the wire: the path a claims path
// pointer array, or a dotted claim name.
type claimMatchWire struct {
	Path json.RawMessage `json:"path"`
	ClaimTest
}

// MarshalJSON writes the path as an array, or a dotted name as a string.
func (c ClaimMatch) MarshalJSON() ([]byte, error) {
	var path []byte
	var err error
	if dotted, pending := c.Path.Pending(); pending {
		path, err = json.Marshal(dotted)
	} else {
		path, err = json.Marshal(c.Path)
	}
	if err != nil {
		return nil, err
	}
	return json.Marshal(claimMatchWire{Path: path, ClaimTest: c.ClaimTest})
}

// UnmarshalJSON reads the path as an array, or a dotted name as a string.
func (c *ClaimMatch) UnmarshalJSON(data []byte) error {
	var wire claimMatchWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	var dotted string
	if err := json.Unmarshal(wire.Path, &dotted); err == nil {
		path, err := claimpath.Dotted(dotted)
		if err != nil {
			return err
		}
		*c = ClaimMatch{Path: path, ClaimTest: wire.ClaimTest}
		return nil
	}
	*c = ClaimMatch{ClaimTest: wire.ClaimTest}
	return json.Unmarshal(wire.Path, &c.Path)
}

// UnmarshalJSON reads the list, or the earlier object from dotted claim
// names to tests, in name order.
func (m *ClaimMatches) UnmarshalJSON(data []byte) error {
	if !bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")) {
		var list []ClaimMatch
		if err := json.Unmarshal(data, &list); err != nil {
			return fmt.Errorf("identity match: claims is a list of {path, equals} entries: %w", err)
		}
		*m = list
		return nil
	}
	var byName map[string]ClaimTest
	if err := json.Unmarshal(data, &byName); err != nil {
		return fmt.Errorf("identity match: %w", err)
	}
	matches, err := claimMatchesByName(byName)
	if err != nil {
		return err
	}
	*m = matches
	return nil
}

// claimMatchesByName reads the earlier form: tests by dotted claim name.
func claimMatchesByName(byName map[string]ClaimTest) (ClaimMatches, error) {
	matches := make(ClaimMatches, 0, len(byName))
	for _, name := range slices.Sorted(maps.Keys(byName)) {
		path, err := claimpath.Dotted(name)
		if err != nil {
			return nil, fmt.Errorf("identity match: %w", err)
		}
		matches = append(matches, ClaimMatch{Path: path, ClaimTest: byName[name]})
	}
	return matches, nil
}

// identityMatchBSON is the stored shape. Claim paths are values, not field
// names: MongoDB before 5.0 refuses "." in field names, and mdoc paths have it.
type identityMatchBSON struct {
	Claims []claimEntryBSON `bson:"claims"`
}

// claimEntryBSON stores the path as an array, or a dotted name as a
// string.
type claimEntryBSON struct {
	Path any       `bson:"path"`
	Test ClaimTest `bson:"test"`
}

// claimEntryRawBSON reads a stored entry.
type claimEntryRawBSON struct {
	Path bson.RawValue `bson:"path"`
	Test ClaimTest     `bson:"test"`
}

// MarshalBSON stores Claims as a list of {path, test} entries.
func (m IdentityMatch) MarshalBSON() ([]byte, error) {
	stored := identityMatchBSON{Claims: make([]claimEntryBSON, 0, len(m.Claims))}
	for _, claim := range m.Claims {
		var path any = claim.Path
		if dotted, pending := claim.Path.Pending(); pending {
			path = dotted
		}
		stored.Claims = append(stored.Claims, claimEntryBSON{Path: path, Test: claim.ClaimTest})
	}
	return bson.Marshal(stored)
}

// UnmarshalBSON reads the entry list, and the earlier map shape.
func (m *IdentityMatch) UnmarshalBSON(data []byte) error {
	var raw struct {
		Claims bson.RawValue `bson:"claims"`
	}
	if err := bson.Unmarshal(data, &raw); err != nil {
		return err
	}

	switch raw.Claims.Type {
	case bson.TypeArray:
		var entries []claimEntryRawBSON
		if err := raw.Claims.Unmarshal(&entries); err != nil {
			return err
		}
		return m.readEntries(entries)
	case bson.TypeEmbeddedDocument:
		var byName map[string]ClaimTest
		if err := raw.Claims.Unmarshal(&byName); err != nil {
			return err
		}
		matches, err := claimMatchesByName(byName)
		if err != nil {
			return err
		}
		m.Claims = matches
	}
	return nil
}

// readEntries reads stored entries: a path stored as an array, or as a
// dotted name.
func (m *IdentityMatch) readEntries(entries []claimEntryRawBSON) error {
	m.Claims = make(ClaimMatches, 0, len(entries))
	for _, entry := range entries {
		var path claimpath.Pointer
		if dotted, ok := entry.Path.StringValueOK(); ok {
			var err error
			if path, err = claimpath.Dotted(dotted); err != nil {
				return err
			}
		} else if err := path.UnmarshalBSONValue(byte(entry.Path.Type), entry.Path.Value); err != nil {
			return err
		}
		m.Claims = append(m.Claims, ClaimMatch{Path: path, ClaimTest: entry.Test})
	}
	return nil
}
