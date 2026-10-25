package model

import (
	"slices"

	"github.com/SUNET/vc/pkg/credential/primitives"
)

// UniqueEntry is an auxiliary_data entry whose commitment is unique per
// key.
type UniqueEntry struct {
	// Path is the claims path pointer of the entry.
	Path []string
	// Key lists the key parts. An empty key makes one commitment for the
	// entry.
	Key []KeyPart
}

// KeyPart is a claim of a unique entry's key.
type KeyPart struct {
	// Path is the claims path pointer of the claim.
	Path []string
	// Openings derive the claim from identifiers, one per source scope in
	// which the claim is a to_wallet entry with an hkdf opening.
	Openings []*primitives.HKDFOpeningArgs
}

// UniqueEntries returns the unique entries of the credential scope: one per
// entry and key that its source scopes configure.
func (ds *DataSources) UniqueEntries(scope string) []UniqueEntry {
	var entries []UniqueEntry
	for _, src := range ds.SourceScopes() {
		if src.Scope != scope {
			continue
		}
		for _, d := range src.Derivations {
			if d.HashCommitment != nil && d.HashCommitment.Unique != nil {
				entries = addUniqueEntry(entries, src.Derivations, d.HashCommitment)
			}
		}
	}
	return entries
}

// addUniqueEntry adds the unique entry hc configures, with the hkdf
// openings of its key parts in derivations.
func addUniqueEntry(entries []UniqueEntry, derivations []primitives.Derivation, hc *primitives.HashCommitmentArgs) []UniqueEntry {
	i := slices.IndexFunc(entries, func(e UniqueEntry) bool {
		return slices.Equal(e.Path, hc.Path) && slices.EqualFunc(e.Key, hc.Unique.Key, func(part KeyPart, path []string) bool {
			return slices.Equal(part.Path, path)
		})
	})
	if i < 0 {
		entry := UniqueEntry{Path: hc.Path, Key: make([]KeyPart, 0, len(hc.Unique.Key))}
		for _, path := range hc.Unique.Key {
			entry.Key = append(entry.Key, KeyPart{Path: path})
		}
		entries, i = append(entries, entry), len(entries)
	}
	for k, part := range entries[i].Key {
		if derived := primitives.HashCommitmentFor(derivations, part.Path); derived != nil && derived.Opening != nil && derived.Opening.HKDF != nil {
			entries[i].Key[k].Openings = append(entries[i].Key[k].Openings, derived.Opening.HKDF)
		}
	}
	return entries
}

// KeyPaths returns the paths of the key parts.
func (e UniqueEntry) KeyPaths() [][]string {
	paths := make([][]string, 0, len(e.Key))
	for _, part := range e.Key {
		paths = append(paths, part.Path)
	}
	return paths
}
