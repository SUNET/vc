package openid4vp

import "strings"

// DefaultNeverDisclose is the built-in never-disclose set.
//
// ssc and psc are the nym_auth seed commitments. They are ordinary
// selectively-disclosable attributes as far as the credential format is
// concerned - ISO 18013-5 commits to a digest for every element and
// leaves disclosure to the holder, and SD-JWT VC is no different - but
// they are meant to be consumed only as inputs to a zero-knowledge proof.
//
// Disclosed in the clear, either is a permanent, globally unique
// identifier for its holder: stable across re-issuance, identical across
// every credential of a batch, and retroactively linking every pseudonym
// that holder has ever produced. One disclosure to one verifier is not
// recoverable, which is why this is a code-level control and not a
// documented convention.
var DefaultNeverDisclose = []string{"ssc", "psc"}

// NeverDisclose is a set of claim names that must never be requested from
// a wallet, never used to satisfy a match, and never handed to a verifier
// or rendered to a user.
//
// A set of NAMES rather than full paths, matched against every segment of
// a claim path. A path-prefixed rule would have to enumerate each
// namespace and vct a claim can appear under, and the one that gets
// forgotten is the one that leaks; matching the leaf name costs the
// ability to permit "ssc" in some other credential where it means
// something harmless, which is a trade worth making for a list of this
// kind.
type NeverDisclose struct {
	names map[string]struct{}
}

// NewNeverDisclose builds the set. An empty or nil list yields a set that
// blocks nothing, which is what a deployment that deliberately cleared
// the configuration asked for.
func NewNeverDisclose(names []string) NeverDisclose {
	set := make(map[string]struct{}, len(names))
	for _, name := range names {
		if trimmed := strings.TrimSpace(name); trimmed != "" {
			set[trimmed] = struct{}{}
		}
	}
	return NeverDisclose{names: set}
}

// Blocks reports whether a claim path names something that must never be
// disclosed. Any segment matching is enough: a nested path reaches the
// same value as a top-level one.
//
// A nil segment is DCQL's "every element of this array" wildcard and
// names nothing, so it is skipped rather than treated as a match.
func (n NeverDisclose) Blocks(path []*string) bool {
	for _, segment := range path {
		if segment == nil {
			continue
		}
		if _, blocked := n.names[*segment]; blocked {
			return true
		}
	}
	return false
}

// BlocksName is Blocks for a single claim name.
func (n NeverDisclose) BlocksName(name string) bool {
	_, blocked := n.names[name]
	return blocked
}

// Empty reports whether this set blocks nothing.
func (n NeverDisclose) Empty() bool { return len(n.names) == 0 }

// FilterDCQL removes blocked claims from a query, in place.
//
// This is the "never ask" half. It runs on every query this server
// builds, whatever built it: a preset an operator wrote, a scope mapping,
// or the issuance-auth query. An operator who configures a preset asking
// for ssc gets a preset that does not ask for it, rather than a verifier
// that leaks on their behalf.
//
// A credential query left with no claims at all is left alone rather than
// dropped: an empty claims list in DCQL means "any claims", so removing
// the last entry would silently widen the request into asking for
// everything - the opposite of what this function is for. The credential
// query is dropped instead.
func (n NeverDisclose) FilterDCQL(query *DCQL) {
	if query == nil || n.Empty() {
		return
	}

	kept := make([]CredentialQuery, 0, len(query.Credentials))
	dropped := map[string]bool{}

	for _, credential := range query.Credentials {
		if len(credential.Claims) == 0 {
			kept = append(kept, credential)
			continue
		}

		claims := make([]ClaimQuery, 0, len(credential.Claims))
		for _, claim := range credential.Claims {
			if n.Blocks(claim.Path) {
				continue
			}
			claims = append(claims, claim)
		}

		if len(claims) == 0 {
			// Every claim this query asked for is blocked. Keeping it
			// with an empty list would ask for all of them.
			dropped[credential.ID] = true
			continue
		}

		credential.Claims = claims
		kept = append(kept, credential)
	}

	query.Credentials = kept
	if len(dropped) > 0 {
		query.CredentialSets = filterCredentialSets(query.CredentialSets, dropped)
	}
}

// filterCredentialSets removes options naming a credential query that is
// no longer there, and sets left with no options at all.
func filterCredentialSets(sets []CredentialSetQuery, dropped map[string]bool) []CredentialSetQuery {
	kept := make([]CredentialSetQuery, 0, len(sets))
	for _, set := range sets {
		options := make([][]string, 0, len(set.Options))
		for _, option := range set.Options {
			keep := true
			for _, id := range option {
				if dropped[id] {
					keep = false
					break
				}
			}
			if keep {
				options = append(options, option)
			}
		}
		if len(options) == 0 {
			continue
		}
		set.Options = options
		kept = append(kept, set)
	}
	return kept
}

// FilterClaims returns a copy of claims with every blocked entry removed,
// at any depth.
//
// This is the second half, and it is deliberately not the same mechanism
// as the first. Filtering the query stops this server asking; this stops
// anything blocked that arrives anyway - because a wallet volunteered it,
// because a query was built somewhere this list was not applied, or
// because a credential carries it as an ordinary disclosed claim - from
// being matched on, returned, or displayed.
//
// A copy rather than a mutation: the caller's map is often a verified
// credential's claims, and silently emptying it elsewhere would be a
// surprise.
func (n NeverDisclose) FilterClaims(claims map[string]any) map[string]any {
	if claims == nil {
		return nil
	}
	if n.Empty() {
		return claims
	}

	filtered := make(map[string]any, len(claims))
	for key, value := range claims {
		if n.BlocksName(key) {
			continue
		}
		// mdoc keeps namespace-qualified claims as one dotted key, so the
		// leaf has to be looked at there too.
		if idx := strings.LastIndex(key, "."); idx >= 0 && n.BlocksName(key[idx+1:]) {
			continue
		}
		if nested, ok := value.(map[string]any); ok {
			filtered[key] = n.FilterClaims(nested)
			continue
		}
		filtered[key] = value
	}
	return filtered
}

// FilterNamed removes blocked entries from any map keyed by claim name.
//
// A package function rather than a method because Go methods cannot take
// type parameters, and the display paths carry typed values - SVG
// template values, rendered claim structs - that would otherwise each
// need their own copy of this loop. Shallow by design: these maps are
// one level of claim names, not credential claim trees.
func FilterNamed[T any](n NeverDisclose, named map[string]T) map[string]T {
	if named == nil || n.Empty() {
		return named
	}

	filtered := make(map[string]T, len(named))
	for key, value := range named {
		if n.BlocksName(key) {
			continue
		}
		if idx := strings.LastIndex(key, "."); idx >= 0 && n.BlocksName(key[idx+1:]) {
			continue
		}
		filtered[key] = value
	}
	return filtered
}
