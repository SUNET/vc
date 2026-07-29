package model

import (
	"fmt"
	"testing"

	"github.com/SUNET/vc/internal/gen/status/apiv1_status"
	"github.com/stretchr/testify/assert"
)

func TestProbes_Check(t *testing.T) {
	tts := []struct {
		name            string
		probes          Probes
		serviceName     string
		expectStatus    string
		expectNumProbes int
	}{
		{
			name:            "nil probes returns FAIL",
			probes:          nil,
			serviceName:     "test-service",
			expectStatus:    fmt.Sprintf(StatusFail, "test-service"),
			expectNumProbes: 0,
		},
		{
			name: "all healthy returns OK",
			probes: Probes{
				{Name: "db", Healthy: true, Message: "connected"},
				{Name: "cache", Healthy: true, Message: "ok"},
			},
			serviceName:     "my-svc",
			expectStatus:    fmt.Sprintf(StatusOK, "my-svc"),
			expectNumProbes: 2,
		},
		{
			name: "one unhealthy returns FAIL",
			probes: Probes{
				{Name: "db", Healthy: true, Message: "connected"},
				{Name: "cache", Healthy: false, Message: "timeout"},
			},
			serviceName:     "svc",
			expectStatus:    fmt.Sprintf(StatusFail, "svc"),
			expectNumProbes: 2,
		},
		{
			name: "all unhealthy returns FAIL",
			probes: Probes{
				{Name: "db", Healthy: false, Message: "down"},
				{Name: "cache", Healthy: false, Message: "down"},
			},
			serviceName:     "svc",
			expectStatus:    fmt.Sprintf(StatusFail, "svc"),
			expectNumProbes: 2,
		},
		{
			name:            "empty slice returns OK",
			probes:          Probes{},
			serviceName:     "svc",
			expectStatus:    fmt.Sprintf(StatusOK, "svc"),
			expectNumProbes: 0,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			reply := tt.probes.Check(tt.serviceName)

			assert.Equal(t, tt.serviceName, reply.Data.ServiceName)
			assert.Equal(t, tt.expectStatus, reply.Data.Status)
			assert.Len(t, reply.Data.Probes, tt.expectNumProbes)
		})
	}
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
	assert.Equal(t, "first", reply.Data.Probes[0].Name)
	assert.Equal(t, "second", reply.Data.Probes[1].Name)
	assert.Equal(t, "third", reply.Data.Probes[2].Name)
}

func TestProbes_Check_ProbeFieldsCopied(t *testing.T) {
	probe := &apiv1_status.StatusProbe{
		Name:    "db",
		Healthy: true,
		Message: "all good",
	}
	probes := Probes{probe}
	reply := probes.Check("svc")

	assert.Equal(t, probe.Name, reply.Data.Probes[0].Name)
	assert.Equal(t, probe.Healthy, reply.Data.Probes[0].Healthy)
	assert.Equal(t, probe.Message, reply.Data.Probes[0].Message)
}
