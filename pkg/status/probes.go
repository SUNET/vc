package status

import (
	"fmt"
	"strings"

	"github.com/SUNET/vc/internal/gen/status/apiv1_status"
)

const (
	// StatusOK marks an individual probe as healthy.
	StatusOK = "OK"
	// StatusFail marks an individual probe as unhealthy.
	StatusFail = "FAIL"

	// ServiceStatusOK / ServiceStatusFail are the top-level rollup format,
	// e.g. "STATUS_OK_apigw" / "STATUS_FAIL_apigw".
	ServiceStatusOK   = "STATUS_OK_%s"
	ServiceStatusFail = "STATUS_FAIL_%s"
)

// Probes is a mutable slice of proto StatusProbe pointers. See Check for the
// mutation contract.
type Probes []*apiv1_status.StatusProbe

// Build-time variables populated via `-ldflags "-X 'github.com/SUNET/vc/pkg/status.<Name>=<value>'"`
// and exposed in every StatusReply for operator visibility.
var (
	BuildVariableGitCommit string = "undef"
	BuildVariableTimestamp string = "undef"
	BuildVariableGoVersion string = "undef"
	BuildVariableGoArch    string = "undef"
	BuildVariableGitBranch string = "undef"
	BuildVersion           string = "undef"
)

// Check builds a StatusReply from the collected probes. Each probe carries
// its own status ("OK" / "FAIL"), and Data.Status carries a service-level
// rollup ("STATUS_OK_<svc>" / "STATUS_FAIL_<svc>") — FAIL when any probe is
// unhealthy. Locally-produced probes are prefixed with "<svc>." (so operators
// see "apigw.db" etc.); probes forwarded from a downstream service already
// carry their own "<svc>." prefix and are left untouched.
//
// Note: mutates each probe's Name and Status in place, so callers should
// pass freshly-built probes rather than sharing them across Check calls.
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
			Status: fmt.Sprintf(ServiceStatusOK, serviceName),
		},
	}

	for _, probe := range probes {
		if probe == nil {
			continue
		}
		if !strings.Contains(probe.Name, ".") {
			probe.Name = serviceName + "." + probe.Name
		}
		if probe.Healthy {
			probe.Status = StatusOK
		} else {
			probe.Status = StatusFail
			health.Data.Status = fmt.Sprintf(ServiceStatusFail, serviceName)
		}
		health.Data.Probes = append(health.Data.Probes, probe)
	}

	return health
}
