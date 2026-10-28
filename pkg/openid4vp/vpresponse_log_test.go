package openid4vp_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/openid4vp"
)

// A presented credential is the most sensitive thing that crosses this
// service, and it was going into the log whole - at DEBUG from the
// verification path, and at ERROR when no query matched, which did not
// even need debug logging enabled.
//
// Asserted on what is written, because the failure is in the rendering.
func TestAVPTokenIsNeverLoggedWhole(t *testing.T) {
	const presentation = "eyJhbGciOiJFUzI1NiJ9.SD-JWT-PRESENTATION~disclosure~disclosure"

	response := &openid4vp.VPResponse{
		State:   "state-1",
		VPToken: map[string][]string{"pid_1_8": {presentation}},
	}

	dir := t.TempDir()
	log, err := logger.New("probe", dir, false)
	require.NoError(t, err)

	// Both shapes: the summary a caller passes, and the whole struct.
	log.Debug("VP Response received", "vp_token", response.VPTokenSummary())
	log.Debug("whole", "response", response)

	out, err := os.ReadFile(filepath.Join(dir, "probe.log"))
	require.NoError(t, err)

	assert.NotContains(t, string(out), presentation, "the presented credential reached the log")
	assert.NotContains(t, string(out), "SD-JWT-PRESENTATION")

	// What a reader still gets: which query answered, and how big.
	assert.Contains(t, string(out), "pid_1_8", "the query id is what the line is for")
	assert.Contains(t, string(out), "state-1")
}

// The summary answers the questions the logs around it were asking.
func TestVPTokenSummaryDescribesTheShape(t *testing.T) {
	response := &openid4vp.VPResponse{VPToken: map[string][]string{
		"pid_1_8":  {"abc", "defgh"},
		"nym_auth": {},
	}}

	summary := response.VPTokenSummary()
	assert.Equal(t, []int{3, 5}, summary["pid_1_8"], "one length per presentation, in order")
	assert.Empty(t, summary["nym_auth"], "a query that answered with nothing is distinguishable from one that did not answer")

	assert.Nil(t, (&openid4vp.VPResponse{}).VPTokenSummary(), "no token, nothing to describe")
	assert.Nil(t, (*openid4vp.VPResponse)(nil).VPTokenSummary(), "a nil response must not panic a log call")
}
