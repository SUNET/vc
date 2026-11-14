package apiv1

import (
	"context"
	"strings"
	"testing"

	"github.com/SUNET/vc/internal/gen/status/apiv1_status"
	"github.com/SUNET/vc/pkg/status"
	"github.com/SUNET/vc/pkg/vc20/credential"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A verifier that started under the best_effort policy is RUNNING and
// cannot canonicalize a presentation of any credential type whose context
// has not loaded. Without this probe it reports healthy and a load balancer
// sends it work it will fail - which is the only thing that makes starting
// at all, rather than crash-looping, defensible.
func TestJSONLDContextProbeIsRegistered(t *testing.T) {
	const unresolvable = "https://ctx.invalid/verifier-readiness.jsonld"

	pinner := credential.NewPinner(credential.NewCachingDocumentLoader(), credential.PinnerOptions{
		Policy: credential.PolicyBestEffort,
	})
	require.NoError(t, pinner.Pin(context.Background(), []credential.PinGroup{{
		Name:        "common.credential_metadata.diploma",
		Field:       "credential_contexts",
		URLs:        []string{unresolvable},
		Consequence: "so presentations of this credential type cannot be verified",
	}}))
	require.Error(t, pinner.HealthProbe(context.Background()), "precondition: the pinner must be unhealthy")

	credential.SetGlobalPinner(pinner)
	t.Cleanup(func() {
		pinner.Stop()
		credential.SetGlobalPinner(nil)
	})

	aggregator := status.New("verifier")
	registerJSONLDContextProbe(aggregator)
	reply := aggregator.Reply(context.Background())

	probe := findProbe(t, reply, "verifier.jsonld_contexts")
	assert.Equal(t, status.StatusFail, probe.GetStatus())
	assert.Contains(t, probe.GetMessage(), unresolvable,
		"an operator reading /health has to learn which context is missing")
	assert.Contains(t, reply.GetData().GetStatus(), "STATUS_FAIL",
		"one unready component must make the service unready")
}

// With nothing resolving contexts there is no pinner, and registering
// nothing must not disturb the rest of the reply.
func TestJSONLDContextProbeIsAbsentWithoutAPinner(t *testing.T) {
	credential.SetGlobalPinner(nil)

	aggregator := status.New("verifier")
	registerJSONLDContextProbe(aggregator)
	reply := aggregator.Reply(context.Background())

	for _, probe := range reply.GetData().GetProbes() {
		assert.NotEqual(t, "verifier.jsonld_contexts", probe.GetName())
	}
}

func findProbe(t *testing.T, reply *apiv1_status.StatusReply, name string) *apiv1_status.StatusProbe {
	t.Helper()
	var have []string
	for _, probe := range reply.GetData().GetProbes() {
		if probe.GetName() == name {
			return probe
		}
		have = append(have, probe.GetName())
	}
	t.Fatalf("no probe named %q (have %s)", name, strings.Join(have, ", "))
	return nil
}
