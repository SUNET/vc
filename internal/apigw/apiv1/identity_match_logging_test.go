package apiv1

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/openid4vci"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A failed identity match compares two identities, and both of them are
// personal data: the expected one came out of a portal session, the
// presented one out of somebody's credential. Writing either to the log
// puts names and national identifiers into log retention, log shipping and
// everything with read access to either - which is the exposure
// docs/SECURITY_HARDENING_PLAN.md's first phase exists to close.
//
// The claim path is what makes a failure diagnosable and is not itself
// personal data, so that is all this logs.
func TestMatchPresentedIdentity_DoesNotLogTheValues(t *testing.T) {
	dir := t.TempDir()
	log, err := logger.New("identitymatchtest", dir, true)
	require.NoError(t, err)

	c := &Client{log: log}

	match := &openid4vci.IdentityMatch{
		Claims: map[string]openid4vci.ClaimTest{
			"given_name":          {Equals: "Anna"},
			"personal_identifier": {Equals: "198001011234"},
		},
	}
	presented := map[string]any{
		"given_name":          "Bertil",
		"personal_identifier": "199912319876",
	}

	err = c.matchPresentedIdentity("dc+sd-jwt", presented, match)
	require.Error(t, err, "the presented identity is a different person")

	written, readErr := os.ReadFile(filepath.Join(dir, "identitymatchtest.log"))
	require.NoError(t, readErr)
	logged := string(written)

	require.Contains(t, logged, "identity match failed",
		"the failure must still be diagnosable from the log")

	for _, value := range []string{"Anna", "Bertil", "198001011234", "199912319876"} {
		assert.NotContains(t, logged, value,
			"an identity value must never reach the log")
	}

	// And not through the error handed back to the wallet either: telling
	// the Holder which identity the issuance was prepared for turns a
	// failed match into an oracle for the portal session's contents.
	for _, value := range []string{"Anna", "Bertil", "198001011234", "199912319876"} {
		assert.NotContains(t, err.Error(), value)
	}
}
