package model

import (
	"fmt"
	"log"
	"time"

	"github.com/SUNET/vc/internal/gen/status/apiv1_status"
)

var (
	// StatusOK status ok
	StatusOK = "STATUS_OK_%s"
	// StatusFail status fail
	StatusFail = "STATUS_FAIL_%s"
)

// Health contains status for each service
type Health struct {
	ServiceName string   `json:"service_name,omitempty"`
	Probes      []*Probe `json:"probes,omitempty"`
	Status      string   `json:"status,omitempty"`
}

// Probe type
type Probe struct {
	Name          string    `json:"name,omitempty"`
	Healthy       bool      `json:"healthy,omitempty"`
	Message       string    `json:"message,omitempty"`
	LastCheckedTS time.Time `json:"timestamp"`
}

// ProbeStore contains the previous probe result and the next time to check
type ProbeStore struct {
	NextCheck      time.Time
	PreviousResult *Probe
}

// Probes contains probes
type Probes []*apiv1_status.StatusProbe

var (
	// BuildVariableGitCommit contains ldflags -X variable git commit hash
	BuildVariableGitCommit string = "undef"

	// BuildVariableTimestamp contains ldsflags -X variable build time
	BuildVariableTimestamp string = "undef"

	// BuildVariableGoVersion contains ldsflags -X variable go build version
	BuildVariableGoVersion string = "undef"

	// BuildVariableGoArch contains ldsflags -X variable go arch build
	BuildVariableGoArch string = "undef"

	// BuildVariableGitBranch contains ldsflags -X variable git branch
	BuildVariableGitBranch string = "undef"

	// BuildVersion contains ldsflags -X variable build version
	BuildVersion string = "undef"
)

// Check checks the status of each status, return the first that does not pass.
func (probes Probes) Check(serviceName string) *apiv1_status.StatusReply {
	health := &apiv1_status.StatusReply{
		Data: &apiv1_status.StatusReply_Data{
			ServiceName: serviceName,
			BuildVariables: &apiv1_status.BuildVariables{
				GitCommit: BuildVariableGitCommit,
				GitBranch: BuildVariableGitBranch,
				Timestamp: BuildVariableTimestamp,
				GoVersion: BuildVariableGoVersion,
				GoArch:    BuildVariableGoArch,
				Version:   BuildVersion,
			},
			Probes: []*apiv1_status.StatusProbe{},
			Status: fmt.Sprintf(StatusOK, serviceName),
		},
	}

	if probes == nil {
		log.Println("probe is nil")
		health.Data.Status = fmt.Sprintf(StatusFail, serviceName)
		return health
	}

	for _, probe := range probes {
		if !probe.Healthy {
			health.Data.Status = fmt.Sprintf(StatusFail, serviceName)
		}
		health.Data.Probes = append(health.Data.Probes, probe)
	}

	return health
}
