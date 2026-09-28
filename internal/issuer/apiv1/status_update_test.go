package apiv1

import (
	"context"
	"testing"

	"github.com/SUNET/vc/internal/gen/registry/apiv1_registry"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// recordingRegistry captures TokenStatusListUpdateStatus calls. Everything
// else is left to the embedded nil interface so an unexpected call panics
// rather than quietly returning a zero value.
type recordingRegistry struct {
	apiv1_registry.RegistryServiceClient
	updates []*apiv1_registry.TokenStatusListUpdateStatusRequest
}

func (r *recordingRegistry) TokenStatusListUpdateStatus(_ context.Context, in *apiv1_registry.TokenStatusListUpdateStatusRequest, _ ...grpc.CallOption) (*apiv1_registry.TokenStatusListUpdateStatusReply, error) {
	r.updates = append(r.updates, in)
	return &apiv1_registry.TokenStatusListUpdateStatusReply{}, nil
}

func statusUpdateClient(t *testing.T, registry apiv1_registry.RegistryServiceClient) *Client {
	t.Helper()
	log := logger.NewSimple("test")
	tracer, err := trace.NewForTesting(t.Context(), "status-update", log)
	require.NoError(t, err)
	return &Client{
		cfg:            &model.Cfg{},
		log:            log,
		tracer:         tracer,
		registryClient: registry,
	}
}

func TestSetCredentialStatus_RegistryBackend(t *testing.T) {
	rec := &recordingRegistry{}
	c := statusUpdateClient(t, rec)

	require.NoError(t, c.SetCredentialStatus(t.Context(), &SetCredentialStatusRequest{
		Backend:       StatusBackendRegistry,
		StatusListURI: "https://registry.example.com/statuslists/4",
		Section:       4,
		Index:         9,
		Status:        1,
	}))

	require.Len(t, rec.updates, 1)
	require.Equal(t, int64(4), rec.updates[0].Section)
	require.Equal(t, int64(9), rec.updates[0].Index)
	require.Equal(t, uint32(1), rec.updates[0].Status)
}

// TestSetCredentialStatus_NeverCrossesBackends is the point of recording the
// backend at issuance. An entry from an external status service has no
// section and reports 0; routing it to the registry would write status 0/9
// of the registry's own list - flipping an unrelated credential and leaving
// the intended one valid, with no error.
func TestSetCredentialStatus_NeverCrossesBackends(t *testing.T) {
	rec := &recordingRegistry{}
	c := statusUpdateClient(t, rec) // registry configured, status service not

	err := c.SetCredentialStatus(t.Context(), &SetCredentialStatusRequest{
		Backend:       StatusBackendStatusService,
		StatusListURI: "https://status.example.com/statuslists/abc",
		Index:         9,
		Status:        1,
	})

	require.Error(t, err, "an entry from an unconfigured backend must be refused, not rerouted")
	require.Contains(t, err.Error(), "no status service configured")
	require.Empty(t, rec.updates, "the registry must not be written to on behalf of another backend")
}

func TestSetCredentialStatus_RegistryBackendWithoutARegistry(t *testing.T) {
	c := statusUpdateClient(t, nil)

	err := c.SetCredentialStatus(t.Context(), &SetCredentialStatusRequest{
		Backend:       StatusBackendRegistry,
		StatusListURI: "https://registry.example.com/statuslists/4",
		Section:       4,
		Index:         9,
		Status:        1,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "no registry client configured")
}

func TestSetCredentialStatus_RejectsAnUnknownOrMissingBackend(t *testing.T) {
	rec := &recordingRegistry{}
	c := statusUpdateClient(t, rec)

	for name, backend := range map[string]string{
		"unknown": "some_future_backend",
		"empty":   "",
	} {
		t.Run(name, func(t *testing.T) {
			err := c.SetCredentialStatus(t.Context(), &SetCredentialStatusRequest{
				Backend:       backend,
				StatusListURI: "https://registry.example.com/statuslists/4",
				Section:       4,
				Index:         9,
				Status:        1,
			})
			require.Error(t, err)
			require.Empty(t, rec.updates)
		})
	}
}

func TestSetCredentialStatus_RequiresAListURI(t *testing.T) {
	rec := &recordingRegistry{}
	c := statusUpdateClient(t, rec)

	err := c.SetCredentialStatus(t.Context(), &SetCredentialStatusRequest{
		Backend: StatusBackendRegistry,
		Section: 4,
		Index:   9,
		Status:  1,
	})
	require.Error(t, err, "section and index alone do not identify an entry")
	require.Empty(t, rec.updates)
}
