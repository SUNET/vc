package openid4vci

import (
	"fmt"
	"sort"
	"strings"

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
	// Claims maps a claim path on the presented credential to the test it
	// must pass.
	//
	// The path is interpreted the way the presented credential's format
	// interprets it - nested for SD-JWT VC, one literal namespace-
	// qualified key for mdoc - so a caller writes the same path it would
	// write anywhere else in this API.
	Claims map[string]ClaimTest `json:"claims" bson:"claims" validate:"required,min=1"`
}

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

	for _, path := range sortedClaimPaths(m.Claims) {
		if strings.TrimSpace(path) == "" {
			return fmt.Errorf("identity match: a claim path is empty")
		}
		if m.Claims[path].Equals == "" {
			return fmt.Errorf("identity match: claim %q has no comparison; the only one supported is \"equals\", and it may not be empty", path)
		}
	}
	return nil
}

// ClaimPaths returns the paths this rule tests, in a stable order.
//
// Sorted so that a log line or an error naming them reads the same way
// twice, which matters because the usual reason to look at one is that a
// match failed and two systems disagree about a person.
func (m *IdentityMatch) ClaimPaths() []string {
	if m == nil {
		return nil
	}
	return sortedClaimPaths(m.Claims)
}

// identityMatchBSON is the stored shape. Claim paths are values, not field
// names: MongoDB before 5.0 refuses "." in field names, and mdoc paths have it.
type identityMatchBSON struct {
	Claims []claimEntryBSON `bson:"claims"`
}

type claimEntryBSON struct {
	Path string    `bson:"path"`
	Test ClaimTest `bson:"test"`
}

// MarshalBSON stores Claims as a list of {path, test} entries.
func (m IdentityMatch) MarshalBSON() ([]byte, error) {
	stored := identityMatchBSON{Claims: make([]claimEntryBSON, 0, len(m.Claims))}
	for _, path := range sortedClaimPaths(m.Claims) {
		stored.Claims = append(stored.Claims, claimEntryBSON{Path: path, Test: m.Claims[path]})
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
		var entries []claimEntryBSON
		if err := raw.Claims.Unmarshal(&entries); err != nil {
			return err
		}
		m.Claims = make(map[string]ClaimTest, len(entries))
		for _, e := range entries {
			m.Claims[e.Path] = e.Test
		}
	case bson.TypeEmbeddedDocument:
		return raw.Claims.Unmarshal(&m.Claims)
	}
	return nil
}

func sortedClaimPaths(claims map[string]ClaimTest) []string {
	paths := make([]string, 0, len(claims))
	for path := range claims {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}
