package grpcserver

import (
	"context"
	"testing"

	"github.com/SUNET/vc/internal/gen/registry/apiv1_registry"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/require"
)

// recordingIssuer captures UpdateStatus calls. An update that should have
// been refused shows up here as a call that happened.
type recordingIssuer struct {
	updates [][3]int64
}

func (r *recordingIssuer) AddStatus(_ context.Context, _ uint8) (int64, int64, error) {
	panic("not used by these tests")
}

func (r *recordingIssuer) UpdateStatus(_ context.Context, section, index int64, status uint8) error {
	r.updates = append(r.updates, [3]int64{section, index, int64(status)})
	return nil
}

func ownershipService(t *testing.T) (*Service, *recordingIssuer) {
	t.Helper()
	issuer := &recordingIssuer{}
	return &Service{
		log:                   logger.NewSimple("test"),
		tokenStatusListIssuer: issuer,
		cfg: &model.Cfg{
			Registry: &model.Registry{
				PublicURL: "https://registry.example.com",
			},
		},
	}, issuer
}

// TestUpdateStatus_CanonicalURIIsAccepted pins the happy path, so the two
// refusals below cannot pass merely because this endpoint refuses
// everything.
func TestUpdateStatus_CanonicalURIIsAccepted(t *testing.T) {
	s, issuer := ownershipService(t)

	_, err := s.TokenStatusListUpdateStatus(t.Context(), &apiv1_registry.TokenStatusListUpdateStatusRequest{
		Section:       4,
		Index:         5,
		Status:        1,
		StatusListURI: "https://registry.example.com/statuslists/4",
	})
	require.NoError(t, err)
	require.Equal(t, [][3]int64{{4, 5, 1}}, issuer.updates)
}

// TestUpdateStatus_ForeignURIIsRefused: (section, index) are coordinates
// into whatever list this registry serves at those numbers right now, not
// an identity. A mapping recorded against some other list - stale,
// migrated, or made up by the caller - addressed an unrelated credential's
// entry and flipped it, while the credential the caller meant to revoke
// stayed valid. Both halves of that are silent.
func TestUpdateStatus_ForeignURIIsRefused(t *testing.T) {
	s, issuer := ownershipService(t)

	_, err := s.TokenStatusListUpdateStatus(t.Context(), &apiv1_registry.TokenStatusListUpdateStatusRequest{
		Section:       4,
		Index:         5,
		Status:        1,
		StatusListURI: "https://other-registry.example.net/statuslists/4",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "https://registry.example.com/statuslists/4",
		"the error must name the list this registry actually serves, so the mismatch is diagnosable")
	require.Empty(t, issuer.updates, "nothing may be written when the caller names a list this registry does not serve")
}

// TestUpdateStatus_WrongSectionForTheURIIsRefused: the subtler shape of the
// same bug. The URI is one this registry does serve - just not at the
// section the caller asked to write. Routing by section alone would update
// list 7's entry while the credential names list 4.
func TestUpdateStatus_WrongSectionForTheURIIsRefused(t *testing.T) {
	s, issuer := ownershipService(t)

	_, err := s.TokenStatusListUpdateStatus(t.Context(), &apiv1_registry.TokenStatusListUpdateStatusRequest{
		Section:       7,
		Index:         5,
		Status:        1,
		StatusListURI: "https://registry.example.com/statuslists/4",
	})
	require.Error(t, err)
	require.Empty(t, issuer.updates)
}

// TestUpdateStatus_MissingURIIsRefused: "the caller did not say" and "the
// caller named this list" are different claims and only the second can be
// checked. Waving the empty one through would restore the unverified
// routing this field exists to close, for any caller that omits it.
func TestUpdateStatus_MissingURIIsRefused(t *testing.T) {
	s, issuer := ownershipService(t)

	_, err := s.TokenStatusListUpdateStatus(t.Context(), &apiv1_registry.TokenStatusListUpdateStatusRequest{
		Section: 4,
		Index:   5,
		Status:  1,
	})
	require.Error(t, err)
	require.Empty(t, issuer.updates)
}
