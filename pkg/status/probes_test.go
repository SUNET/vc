package status

import (
	"fmt"
	"strings"
	"testing"

	"github.com/SUNET/vc/internal/gen/status/apiv1_status"
	"github.com/stretchr/testify/assert"
)

func TestProbes_Check(t *testing.T) {
	tts := []struct {
		name            string
		probes          Probes
		serviceName     string
		expectNumProbes int
		expectProbeSt   []string // per-probe status strings, in order
		expectRollup    string   // Data.Status
	}{
		{
			name:            "nil probes - rollup OK, no probes",
			probes:          nil,
			serviceName:     "test-service",
			expectNumProbes: 0,
			expectProbeSt:   nil,
			expectRollup:    fmt.Sprintf(ServiceStatusOK, "test-service"),
		},
		{
			name: "all healthy - rollup OK",
			probes: Probes{
				{Name: "db", Healthy: true, Message: "connected"},
				{Name: "cache", Healthy: true, Message: "ok"},
			},
			serviceName:     "my-svc",
			expectNumProbes: 2,
			expectProbeSt:   []string{StatusOK, StatusOK},
			expectRollup:    fmt.Sprintf(ServiceStatusOK, "my-svc"),
		},
		{
			name: "one unhealthy - rollup FAIL",
			probes: Probes{
				{Name: "db", Healthy: true, Message: "connected"},
				{Name: "cache", Healthy: false, Message: "timeout"},
			},
			serviceName:     "svc",
			expectNumProbes: 2,
			expectProbeSt:   []string{StatusOK, StatusFail},
			expectRollup:    fmt.Sprintf(ServiceStatusFail, "svc"),
		},
		{
			name: "all unhealthy - rollup FAIL",
			probes: Probes{
				{Name: "db", Healthy: false, Message: "down"},
				{Name: "cache", Healthy: false, Message: "down"},
			},
			serviceName:     "svc",
			expectNumProbes: 2,
			expectProbeSt:   []string{StatusFail, StatusFail},
			expectRollup:    fmt.Sprintf(ServiceStatusFail, "svc"),
		},
		{
			name:            "empty slice - rollup OK, no probes",
			probes:          Probes{},
			serviceName:     "svc",
			expectNumProbes: 0,
			expectProbeSt:   nil,
			expectRollup:    fmt.Sprintf(ServiceStatusOK, "svc"),
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			reply := tt.probes.Check(tt.serviceName)

			assert.Equal(t, tt.serviceName, reply.Data.ServiceName)
			assert.Equal(t, tt.expectRollup, reply.Data.Status)
			assert.Len(t, reply.Data.Probes, tt.expectNumProbes)
			for i, want := range tt.expectProbeSt {
				p := reply.Data.Probes[i]
				assert.Equal(t, want, p.Status, "probe %s", p.Name)
				assert.True(t, strings.HasPrefix(p.Name, tt.serviceName+"."), "probe %s should be prefixed with %s.", p.Name, tt.serviceName)
			}
		})
	}
}

func TestProbes_Check_DoesNotDoublePrefix(t *testing.T) {
	// A downstream probe forwarded through an aggregator already carries
	// its own "<svc>." prefix and must be left untouched.
	probes := Probes{
		{Name: "issuer.signer", Healthy: true},
		{Name: "registry.mongo", Healthy: false, Message: "down"},
	}
	reply := probes.Check("apigw")

	assert.Equal(t, "issuer.signer", reply.Data.Probes[0].Name)
	assert.Equal(t, "registry.mongo", reply.Data.Probes[1].Name)
}

func TestProbes_Check_BuildVariablesPopulated(t *testing.T) {
	probes := Probes{}
	reply := probes.Check("svc")

	bv := reply.Data.BuildVariables
	assert.NotNil(t, bv)
	assert.Equal(t, BuildVariableGitCommit, bv.GitCommit)
	assert.Equal(t, BuildVariableGitBranch, bv.GitBranch)
	assert.Equal(t, BuildVariableTimestamp, bv.Timestamp)
	assert.Equal(t, BuildVariableGoVersion, bv.GoVersion)
	assert.Equal(t, BuildVariableGoArch, bv.GoArch)
	assert.Equal(t, BuildVersion, bv.Version)
}

func TestProbes_Check_ProbesPreserveOrder(t *testing.T) {
	probes := Probes{
		{Name: "first", Healthy: true},
		{Name: "second", Healthy: false},
		{Name: "third", Healthy: true},
	}
	reply := probes.Check("svc")

	assert.Len(t, reply.Data.Probes, 3)
	assert.Equal(t, "svc.first", reply.Data.Probes[0].Name)
	assert.Equal(t, "svc.second", reply.Data.Probes[1].Name)
	assert.Equal(t, "svc.third", reply.Data.Probes[2].Name)
}

func TestProbes_Check_ProbeFieldsCopied(t *testing.T) {
	probe := &apiv1_status.StatusProbe{
		Name:    "db",
		Healthy: true,
		Message: "all good",
	}
	probes := Probes{probe}
	reply := probes.Check("svc")

	assert.Equal(t, "svc.db", reply.Data.Probes[0].Name)
	assert.Equal(t, probe.Healthy, reply.Data.Probes[0].Healthy)
	assert.Equal(t, probe.Message, reply.Data.Probes[0].Message)
}
