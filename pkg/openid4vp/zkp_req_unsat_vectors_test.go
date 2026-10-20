package openid4vp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// unsatVector is one shared conformance vector for the rulebook's
// "unsatisfiable request" rules: a well-formed query the evaluator must
// never offer.
type unsatVector struct {
	Description string          `json:"description"`
	Query       json.RawMessage `json:"query"`
	Expect      struct {
		Satisfiable bool   `json:"satisfiable"`
		Error       string `json:"error"`
	} `json:"expect"`
}

// The vendored zkp_req_unsat set was being hashed for the pinned digest
// and never executed. That is the whole of what the nym_auth profile is
// for - the rules a preset is judged against at startup - stated by the
// implementation every other party checks against, and it was sitting
// unused while the profile silently stopped short of three of them
// (source_format, ver, prf).
//
// Only the verdict is compared, not the reason: the vectors carry the
// matcher's stable reason codes and this profile reports prose aimed at
// whoever is editing the configuration. The verdict is the part that has
// to agree.
// deliberatelyStricter names the vectors where this profile refuses a
// request the matcher calls satisfiable, with the reason. A divergence
// has to be stated somewhere a reader will find it; a vector quietly
// skipped is indistinguishable from one that was never noticed.
var deliberatelyStricter = map[string]string{
	// The matcher is right about the rulebook: known-offender-matching-psc
	// is a defined configuration, and whether a system can serve it is
	// its registry entry's say. This profile judges PRESETS, for a
	// deployment whose circuits prove -ssc only, so it refuses the
	// configuration with an explanation while it cannot be served -
	// which is more use to an operator at startup than a preset that
	// loads and is declined by every wallet.
	"ok_psc_and_xsite_configs_are_rulebook_defined": "psc cannot be requested until a circuit proves it",
}

func TestNymAuthProfileAgreesWithTheUnsatisfiableVectors(t *testing.T) {
	dir := filepath.Join(vectorsDir, "zkp_req_unsat")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	ran := 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, name))
		require.NoError(t, err)

		var vector unsatVector
		require.NoError(t, json.Unmarshal(raw, &vector), name)

		var query CredentialQuery
		require.NoError(t, json.Unmarshal(vector.Query, &query), name)

		t.Run(strings.TrimSuffix(name, ".json"), func(t *testing.T) {
			err := ValidateProfile(ProfileNymAuth, query)
			if why, stricter := deliberatelyStricter[strings.TrimSuffix(name, ".json")]; stricter {
				assert.Errorf(t, err, "%s is listed as a deliberate divergence (%s), but the profile now accepts it; remove the entry", name, why)
				return
			}
			if vector.Expect.Satisfiable {
				assert.NoError(t, err, "%s: %s", name, vector.Description)
				return
			}
			assert.Errorf(t, err, "%s: %s (the matcher refuses this as %s)",
				name, vector.Description, vector.Expect.Error)
		})
		ran++
	}
	require.NotZero(t, ran, "no vectors were read")
}
