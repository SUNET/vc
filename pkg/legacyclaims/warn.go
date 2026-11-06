package legacyclaims

import (
	"fmt"
	"slices"

	"github.com/SUNET/vc/pkg/logger"
)

// String renders the rewrite as one line that names the file, the YAML
// location, the old spelling and the new one.
func (r Rewrite) String() string {
	if r.Note != "" {
		return fmt.Sprintf("%s:%d: %s: deprecated claim spelling %s; migrate_claim_paths leaves it as written: %s", r.File, r.Line, r.Path, r.Old, r.Note)
	}
	return fmt.Sprintf("%s:%d: %s: deprecated claim spelling %s; write %s, or run migrate_claim_paths", r.File, r.Line, r.Path, r.Old, r.New)
}

// Warn logs one deprecation warning per rewrite, in file and line order.
// Each message names its location, so log sampling keeps every one.
func Warn(log *logger.Log, rewrites []Rewrite) {
	sorted := slices.Clone(rewrites)
	slices.SortStableFunc(sorted, func(a, b Rewrite) int {
		if a.File != b.File {
			if a.File < b.File {
				return -1
			}
			return 1
		}
		return a.Line - b.Line
	})
	for _, r := range sorted {
		log.Warn(r.String(), "file", r.File, "path", r.Path, "line", r.Line, "old", r.Old, "new", r.New)
	}
}
