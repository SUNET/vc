package grpcserver

import (
	"testing"

	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"

	"github.com/stretchr/testify/require"
)

// The apigw refuses an issuance reply that does not SAY whether an entry
// was allocated, because a registry's first allocation is legitimately
// section 0, index 0 and so is "nothing was allocated". These pin what the
// issuer says.
func TestStatusAllocation(t *testing.T) {
	t.Run("an allocation with its list URI is ALLOCATED", func(t *testing.T) {
		got, err := statusAllocation(true, "https://registry.example.com/statuslists/4")
		require.NoError(t, err)
		require.Equal(t, apiv1_issuer.StatusAllocation_STATUS_ALLOCATION_ALLOCATED, got)
	})

	// Degraded mode: the allocator was asked, could not allocate, and the
	// issuance continues deliberately without a status entry. This is the
	// case that must NOT come out as UNSPECIFIED - the apigw reads that as
	// an issuer too old to have the field and fails the issuance.
	t.Run("no allocation and no URI is NONE", func(t *testing.T) {
		got, err := statusAllocation(false, "")
		require.NoError(t, err)
		require.Equal(t, apiv1_issuer.StatusAllocation_STATUS_ALLOCATION_NONE, got)
	})

	// The verdict and the URI are two statements about one fact. They
	// agree today because allocateOrDegrade and allocateOptionalStatus hand
	// the slot back when an allocation arrives without a URI - an invariant
	// in another file. If that ever stops holding, this is where it shows.
	t.Run("allocated with no URI is refused", func(t *testing.T) {
		_, err := statusAllocation(true, "")
		require.Error(t, err, "an entry nothing can record or revoke must not be reported as allocated")
	})

	t.Run("not allocated but carrying a URI is refused", func(t *testing.T) {
		_, err := statusAllocation(false, "https://registry.example.com/statuslists/4")
		require.Error(t, err, "an entry that exists must not be reported as never allocated")
	})
}
