package apiv1

import (
	"context"
	"errors"
	"testing"

	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/tokenstatuslist"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// failingAfterFirst mints one credential and then fails, which is the shape
// that leaked: the first call ALLOCATED a status entry, the second failed, and
// the function returned before anything recorded or released the first.
type failingAfterFirst struct {
	apiv1_issuer.IssuerServiceClient
	made     int
	released []*apiv1_issuer.SetCredentialStatusRequest
}

func (f *failingAfterFirst) MakeSDJWT(_ context.Context, _ *apiv1_issuer.MakeSDJWTRequest, _ ...grpc.CallOption) (*apiv1_issuer.MakeSDJWTReply, error) {
	f.made++
	if f.made > 1 {
		return nil, errors.New("issuer unavailable")
	}
	return &apiv1_issuer.MakeSDJWTReply{
		Credentials:            []*apiv1_issuer.Credential{{Credential: "the.first.credential"}},
		TokenStatusListSection: 7,
		TokenStatusListIndex:   42,
		TokenStatusListUri:     "https://status.example.org/list/7",
		TokenStatusListBackend: "status_service",
	}, nil
}

func (f *failingAfterFirst) SetCredentialStatus(_ context.Context, in *apiv1_issuer.SetCredentialStatusRequest, _ ...grpc.CallOption) (*apiv1_issuer.SetCredentialStatusReply, error) {
	f.released = append(f.released, in)
	return &apiv1_issuer.SetCredentialStatusReply{}, nil
}

// TestMidLoopFailureReleasesEarlierAllocations: one credential request can mint
// several credentials, one per holder key. A later one failing used to return
// straight out, so the earlier allocations were never recorded and never
// released - the slot stayed VALID on the status list with nothing able to
// find it, and every retry leaked another.
func TestMidLoopFailureReleasesEarlierAllocations(t *testing.T) {
	issuer := &failingAfterFirst{}
	log := logger.NewSimple("test")
	tracer, err := trace.NewForTesting(t.Context(), "leak", log)
	require.NoError(t, err)
	client := &Client{
		cfg: &model.Cfg{Common: &model.Common{CredentialMetadata: map[string]*model.CredentialMetadata{
			"pid": {Format: "dc+sd-jwt"},
		}}},
		log:          log,
		tracer:       tracer,
		issuerClient: issuer,
	}

	twoKeys := []*apiv1_issuer.Jwk{{Kty: "EC"}, {Kty: "EC"}}

	_, err = client.issueSDJWT(t.Context(), "pid", []byte(`{}`), twoKeys, "identifier", "source")
	require.Error(t, err, "the second credential could not be minted")

	require.Len(t, issuer.released, 1,
		"the first credential's status entry is released, not left VALID and unreferenced")
	released := issuer.released[0]
	require.Equal(t, "https://status.example.org/list/7", released.StatusListUri)
	require.Equal(t, int64(7), released.Section)
	require.Equal(t, int64(42), released.Index)
	require.Equal(t, "status_service", released.Backend)
	require.Equal(t, uint32(tokenstatuslist.StatusInvalid), released.Status,
		"released means marked INVALID, so the slot cannot be handed out as live")
}
