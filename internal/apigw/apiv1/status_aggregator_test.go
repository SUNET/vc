package apiv1

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/SUNET/vc/internal/gen/registry/apiv1_registry"
	apiv1_status "github.com/SUNET/vc/internal/gen/status/apiv1_status"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// healthyRegistry answers Status successfully; everything else panics so an
// unexpected call is visible rather than a zero value that reads as success.
type healthyRegistry struct {
	apiv1_registry.RegistryServiceClient
}

func (healthyRegistry) Status(context.Context, *apiv1_status.StatusRequest, ...grpc.CallOption) (*apiv1_status.StatusReply, error) {
	// A healthy downstream contributes ITS OWN probe list, not one named
	// after the downstream, so the reply has to carry something nameable.
	return &apiv1_status.StatusReply{Data: &apiv1_status.StatusReply_Data{
		ServiceName: "registry",
		Status:      "STATUS_OK",
		Probes: []*apiv1_status.StatusProbe{
			{Name: "registry-db", Healthy: true, Message: "OK"},
		},
	}}, nil
}

// unreachableRegistry is a configured registry that cannot be reached, which
// must be REPORTED - the point of registering conditionally is that absent
// and passing are different answers.
type unreachableRegistry struct {
	apiv1_registry.RegistryServiceClient
}

func (unreachableRegistry) Status(context.Context, *apiv1_status.StatusRequest, ...grpc.CallOption) (*apiv1_status.StatusReply, error) {
	return nil, errors.New("connection refused")
}

func probeNames(reply *apiv1_status.StatusReply) []string {
	if reply == nil || reply.Data == nil {
		return nil
	}
	names := make([]string, 0, len(reply.Data.Probes))
	for _, p := range reply.Data.Probes {
		names = append(names, p.Name)
	}
	return names
}

// hasRegistryProbe reports whether anything registry-related made it into
// the report. Probe names are prefixed with the aggregate's service name
// ("apigw.registry"), and a healthy downstream contributes its own probes
// under that prefix too ("apigw.registry-db"), so both shapes count.
func hasRegistryProbe(reply *apiv1_status.StatusReply) bool {
	for _, n := range probeNames(reply) {
		if strings.HasPrefix(n, "apigw.registry") {
			return true
		}
	}
	return false
}

// TestStatusAggregator_NoRegistryIsNotProbed: making the local registry
// optional is pointless if the readiness report then fails forever. The
// probe used to be registered unconditionally and answered a nil client
// with "registry client not initialized", which fails the whole aggregate -
// so an external-status-service deployment, the configuration this change
// exists to support, could never become ready.
func TestStatusAggregator_NoRegistryIsNotProbed(t *testing.T) {
	c := &Client{} // no registry client configured

	reply := c.buildStatusAggregator().Reply(t.Context())
	require.NotNil(t, reply)
	require.False(t, hasRegistryProbe(reply),
		"no registry is configured, so it must not appear in the readiness report: %v", probeNames(reply))
}

// TestStatusAggregator_ConfiguredRegistryIsStillProbed is the other half:
// absent from the report and passing are different answers, and a registry
// that IS configured must still be reported on.
func TestStatusAggregator_ConfiguredRegistryIsStillProbed(t *testing.T) {
	c := &Client{registryClient: healthyRegistry{}}

	reply := c.buildStatusAggregator().Reply(t.Context())
	require.NotNil(t, reply)
	require.Contains(t, probeNames(reply), "apigw.registry-db",
		"a configured, healthy registry must contribute its probes")
}

// TestStatusAggregator_ConfiguredButUnreachableRegistryFails: absent from the
// report and passing are different answers. Skipping the probe inside the
// fetcher, rather than deciding registration up front, would have reported a
// registry that was configured and down as healthy.
func TestStatusAggregator_ConfiguredButUnreachableRegistryFails(t *testing.T) {
	c := &Client{registryClient: unreachableRegistry{}}

	reply := c.buildStatusAggregator().Reply(t.Context())
	require.NotNil(t, reply)
	require.True(t, hasRegistryProbe(reply),
		"a configured registry that is down must still be reported: %v", probeNames(reply))

	var registryProbe *apiv1_status.StatusProbe
	for _, p := range reply.Data.Probes {
		if p.Name == "apigw.registry" {
			registryProbe = p
		}
	}
	require.NotNil(t, registryProbe)
	require.False(t, registryProbe.Healthy)
	require.Contains(t, registryProbe.Message, "connection refused")
}
