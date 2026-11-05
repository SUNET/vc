package model

import (
	"testing"
	"time"

	"github.com/creasty/defaults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The default is asymmetric, and deliberately so: the issuer SIGNS, and a
// signature over terms whose context never loaded is not a degraded
// service. A verifier loses one credential type and should keep serving the
// others.
func TestPolicyForDefaultsByService(t *testing.T) {
	var jc JSONLDContexts

	assert.Equal(t, JSONLDContextRequired, jc.PolicyFor("issuer"))
	assert.Equal(t, JSONLDContextBestEffort, jc.PolicyFor("verifier"))
}

// A nil receiver is the shape a service with no common stanza has, and it
// must answer rather than panic.
func TestPolicyForOnANilStanza(t *testing.T) {
	var jc *JSONLDContexts

	assert.Equal(t, JSONLDContextRequired, jc.PolicyFor("issuer"))
	assert.Equal(t, JSONLDContextBestEffort, jc.PolicyFor("verifier"))
}

// Precedence runs per-service, then global, then the built-in default.
// Without the first of those a deployment could only choose one policy for
// both services, which is the thing that made the old behaviour wrong.
func TestPolicyForPrecedence(t *testing.T) {
	jc := JSONLDContexts{StartupPolicy: JSONLDContextLazy}
	assert.Equal(t, JSONLDContextLazy, jc.PolicyFor("issuer"),
		"the global setting overrides the built-in default")

	jc.StartupPolicyPerService = map[string]JSONLDContextPolicy{"issuer": JSONLDContextRequired}
	assert.Equal(t, JSONLDContextRequired, jc.PolicyFor("issuer"),
		"the per-service setting overrides the global one")
	assert.Equal(t, JSONLDContextLazy, jc.PolicyFor("verifier"),
		"and leaves the other service on the global one")

	// An empty value in the map is not a choice; it falls through.
	jc.StartupPolicyPerService["verifier"] = ""
	assert.Equal(t, JSONLDContextLazy, jc.PolicyFor("verifier"))
}

// The defaults a deployment gets without writing the stanza at all. They
// matter because they are what every existing config file will now run
// with.
func TestJSONLDContextDefaults(t *testing.T) {
	var jc JSONLDContexts
	require.NoError(t, defaults.Set(&jc))

	assert.Equal(t, 12*time.Hour, jc.RefreshInterval)
	assert.Equal(t, time.Second, jc.Retry.InitialInterval)
	assert.Equal(t, 5*time.Minute, jc.Retry.MaxInterval)
	assert.InDelta(t, 2.0, jc.Retry.Multiplier, 0.0001)
	assert.Equal(t, 3, jc.Retry.BootAttempts)

	assert.Empty(t, jc.StartupPolicy,
		"unset, so PolicyFor can still tell the issuer and the verifier apart")
}
