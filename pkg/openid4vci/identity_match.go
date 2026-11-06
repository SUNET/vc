package openid4vci

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

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
	// test it must pass. A path is a claims path pointer (OpenID4VP 1.0
	// section 7) into the presented credential: [namespace, element] for
	// an mdoc.
	Claims []ClaimMatch `json:"claims" validate:"required,min=1"`
}

// ClaimMatch is one claim of the presented credential and the test it
// must pass.
type ClaimMatch struct {
	// Path is the claim.
	Path claimpath.Pointer `json:"path"`
	ClaimTest
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

// errNoClaims refuses a rule without claims.
var errNoClaims = errors.New("identity match: no claims to match on; a rule that matches anything is refused - an issuance any wallet may complete is the pre-authorized grant, which is a different request")

// Validate refuses a rule that cannot do its job.
//
// Called when the rule is accepted, not when it is evaluated: a caller
// that mistypes a comparator should be told at the moment it prepares the
// issuance, not when a Holder is standing there with a wallet open.
func (m *IdentityMatch) Validate() error {
	if m == nil || len(m.Claims) == 0 {
		return errNoClaims
	}

	for _, claim := range m.Claims {
		switch {
		case claim.Path.IsZero():
			return fmt.Errorf("identity match: a claim path is empty")
		case !claim.Path.SelectsOne():
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

// Store returns the rule as a session stores it. spell returns the dotted
// name a replica running the earlier release reads as a claim. When spell
// names every claim, the session holds those names, so such a replica
// reads the session during a rolling deploy. Otherwise it holds the
// pointers.
func (m *IdentityMatch) Store(spell func(claimpath.Pointer) (string, bool)) *StoredIdentityMatch {
	if m == nil {
		return nil
	}
	names := make([]storedClaim, 0, len(m.Claims))
	for _, claim := range m.Claims {
		name, ok := "", false
		if spell != nil {
			name, ok = spell(claim.Path)
		}
		if !ok {
			names = nil
			break
		}
		names = append(names, storedClaim{path: namedPath(name), test: claim.ClaimTest})
	}
	if names != nil {
		return &StoredIdentityMatch{claims: names}
	}
	pointers := make([]storedClaim, 0, len(m.Claims))
	for _, claim := range m.Claims {
		pointers = append(pointers, storedClaim{path: pointerPath{claim.Path}, test: claim.ClaimTest})
	}
	return &StoredIdentityMatch{claims: pointers}
}

// LegacyIdentityMatch is identity_match as the earlier release's
// /issuance/prepare request writes it: an object from dotted claim names
// to tests. A name reads in the shape of the credential presented against
// it, as legacyclaims.PresentedClaim reads it: nested for an SD-JWT VC, and
// one namespace-qualified mdoc element, where a name without a dot is an
// element of org.iso.18013.5.1.
type LegacyIdentityMatch struct {
	Claims map[string]ClaimTest `json:"claims" validate:"required,min=1"`
}

// Validate refuses an empty rule, an empty claim name and an empty
// comparison.
func (m *LegacyIdentityMatch) Validate() error {
	if m == nil || len(m.Claims) == 0 {
		return errNoClaims
	}
	for _, name := range slices.Sorted(maps.Keys(m.Claims)) {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("identity match: a claim path is empty")
		}
		if m.Claims[name].Equals == "" {
			return fmt.Errorf("identity match: claim %q has no comparison; the only one supported is \"equals\", and it may not be empty", name)
		}
	}
	return nil
}

// ClaimPaths returns the claim names in sorted order.
func (m *LegacyIdentityMatch) ClaimPaths() []string {
	if m == nil {
		return nil
	}
	return slices.Sorted(maps.Keys(m.Claims))
}

// Store returns the rule as a session stores it: the dotted names, which a
// replica running the earlier release also reads.
func (m *LegacyIdentityMatch) Store() *StoredIdentityMatch {
	return &StoredIdentityMatch{claims: namedClaims(m.Claims)}
}

// namedClaims returns the stored claims of an object from dotted claim
// names to tests, in name order.
func namedClaims(byName map[string]ClaimTest) []storedClaim {
	claims := make([]storedClaim, 0, len(byName))
	for _, name := range slices.Sorted(maps.Keys(byName)) {
		claims = append(claims, storedClaim{path: namedPath(name), test: byName[name]})
	}
	return claims
}

// StoredIdentityMatch is an identity match as a session holds it. A claim
// is a claims path pointer, or a dotted claim name, which sessions written
// by the earlier release hold. A dotted name reads in the shape of the
// credential presented against it.
type StoredIdentityMatch struct {
	claims []storedClaim
}

// storedClaim is one claim of a stored rule and its test.
type storedClaim struct {
	path storedPath
	test ClaimTest
}

// storedPath is the claim of a stored rule: a pointerPath or a namedPath.
type storedPath interface {
	// pointer returns the claim, reading a dotted name with read.
	pointer(read func(name string) (claimpath.Pointer, error)) (claimpath.Pointer, error)
	// value returns the value the path is stored as: the pointer, or the
	// dotted name.
	value() any
	// String renders the path for a log line.
	String() string
}

// pointerPath is a claim stored as a claims path pointer.
type pointerPath struct{ claimpath.Pointer }

func (p pointerPath) pointer(func(string) (claimpath.Pointer, error)) (claimpath.Pointer, error) {
	return p.Pointer, nil
}

func (p pointerPath) value() any { return p.Pointer }

// namedPath is a claim stored as the earlier release's dotted claim name.
type namedPath string

func (n namedPath) pointer(read func(string) (claimpath.Pointer, error)) (claimpath.Pointer, error) {
	p, err := read(string(n))
	if err != nil {
		return claimpath.Pointer{}, fmt.Errorf("identity match: claim %q: %w", string(n), err)
	}
	return p, nil
}

func (n namedPath) value() any { return string(n) }

func (n namedPath) String() string { return string(n) }

// Rule returns the rule, with each dotted claim name read by read: main's
// reading of the name in the shape of the presented credential.
func (m *StoredIdentityMatch) Rule(read func(name string) (claimpath.Pointer, error)) (*IdentityMatch, error) {
	if m == nil {
		return nil, nil
	}
	rule := &IdentityMatch{Claims: make([]ClaimMatch, 0, len(m.claims))}
	for _, claim := range m.claims {
		path, err := claim.path.pointer(read)
		if err != nil {
			return nil, err
		}
		rule.Claims = append(rule.Claims, ClaimMatch{Path: path, ClaimTest: claim.test})
	}
	return rule, nil
}

// ClaimPaths returns the claims this rule tests, rendered for a log line.
func (m *StoredIdentityMatch) ClaimPaths() []string {
	if m == nil {
		return nil
	}
	paths := make([]string, 0, len(m.claims))
	for _, claim := range m.claims {
		paths = append(paths, claim.path.String())
	}
	return paths
}

// identityMatchBSON is the stored shape. Claim paths are values, not field
// names: MongoDB before 5.0 refuses "." in field names, and mdoc paths have it.
type identityMatchBSON struct {
	Claims []claimEntryBSON `bson:"claims"`
}

// claimEntryBSON is a stored claim: its path is a dotted name or an array.
type claimEntryBSON struct {
	Path any       `bson:"path"`
	Test ClaimTest `bson:"test"`
}

// claimEntryRawBSON reads a stored claim.
type claimEntryRawBSON struct {
	Path bson.RawValue `bson:"path"`
	Test ClaimTest     `bson:"test"`
}

// MarshalBSON stores the claims as a list of {path, test} entries.
func (m StoredIdentityMatch) MarshalBSON() ([]byte, error) {
	stored := identityMatchBSON{Claims: make([]claimEntryBSON, 0, len(m.claims))}
	for _, claim := range m.claims {
		stored.Claims = append(stored.Claims, claimEntryBSON{Path: claim.path.value(), Test: claim.test})
	}
	return bson.Marshal(stored)
}

// UnmarshalBSON reads the entry list, with a path stored as a dotted name
// or as an array, and the earlier map from dotted names to tests.
func (m *StoredIdentityMatch) UnmarshalBSON(data []byte) error {
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
		m.claims = namedClaims(byName)
		return nil
	case bson.TypeNull, 0:
		m.claims = nil
		return nil
	}
	return fmt.Errorf("identity match: claims is stored as BSON type %s", raw.Claims.Type)
}

// readEntries reads stored entries.
func (m *StoredIdentityMatch) readEntries(entries []claimEntryRawBSON) error {
	m.claims = make([]storedClaim, 0, len(entries))
	for _, entry := range entries {
		if name, ok := entry.Path.StringValueOK(); ok {
			m.claims = append(m.claims, storedClaim{path: namedPath(name), test: entry.Test})
			continue
		}
		var path claimpath.Pointer
		if err := path.UnmarshalBSONValue(byte(entry.Path.Type), entry.Path.Value); err != nil {
			return err
		}
		if path.IsZero() || path.IsEmptyArray() {
			return errors.New("identity match: a stored claim has no path")
		}
		m.claims = append(m.claims, storedClaim{path: pointerPath{path}, test: entry.Test})
	}
	return nil
}

// identityMatchJSON is the JSON form of a stored rule whose claims are
// not all dotted names: a list of {path, test} entries.
type identityMatchJSON struct {
	Claims []claimEntryJSON `json:"claims"`
}

// claimEntryJSON is a stored claim: its path is a dotted name or an array.
type claimEntryJSON struct {
	Path any       `json:"path"`
	Test ClaimTest `json:"test"`
}

// MarshalJSON writes a rule of dotted names as the earlier release's
// object from names to tests, which a replica running that release
// reads. It writes any other rule as a list of {path, test} entries.
func (m StoredIdentityMatch) MarshalJSON() ([]byte, error) {
	byName := make(map[string]ClaimTest, len(m.claims))
	for _, claim := range m.claims {
		name, ok := claim.path.(namedPath)
		if !ok {
			byName = nil
			break
		}
		byName[string(name)] = claim.test
	}
	if byName != nil {
		return json.Marshal(struct {
			Claims map[string]ClaimTest `json:"claims"`
		}{byName})
	}
	stored := identityMatchJSON{Claims: make([]claimEntryJSON, 0, len(m.claims))}
	for _, claim := range m.claims {
		stored.Claims = append(stored.Claims, claimEntryJSON{Path: claim.path.value(), Test: claim.test})
	}
	return json.Marshal(stored)
}

// UnmarshalJSON reads the entry list, and the earlier release's object
// from dotted claim names to tests.
func (m *StoredIdentityMatch) UnmarshalJSON(data []byte) error {
	var raw struct {
		Claims json.RawMessage `json:"claims"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if bytes.HasPrefix(bytes.TrimSpace(raw.Claims), []byte("{")) {
		var byName map[string]ClaimTest
		if err := json.Unmarshal(raw.Claims, &byName); err != nil {
			return err
		}
		m.claims = namedClaims(byName)
		return nil
	}
	var entries []struct {
		Path json.RawMessage `json:"path"`
		Test ClaimTest       `json:"test"`
	}
	if err := json.Unmarshal(raw.Claims, &entries); err != nil {
		return err
	}
	m.claims = make([]storedClaim, 0, len(entries))
	for _, entry := range entries {
		var name string
		if err := json.Unmarshal(entry.Path, &name); err == nil {
			m.claims = append(m.claims, storedClaim{path: namedPath(name), test: entry.Test})
			continue
		}
		var path claimpath.Pointer
		if err := json.Unmarshal(entry.Path, &path); err != nil {
			return err
		}
		if path.IsZero() {
			return errors.New("identity match: a stored claim has no path")
		}
		m.claims = append(m.claims, storedClaim{path: pointerPath{path}, test: entry.Test})
	}
	return nil
}
