package apiv1

import (
	"math"
	"testing"

	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/revocation"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMdocStatusClaim(t *testing.T) {
	t.Run("no status", func(t *testing.T) {
		for _, st := range []*mdoc.MSOStatus{nil, {}} {
			got, err := mdocStatusClaim(st)
			require.NoError(t, err)
			assert.Nil(t, got)
		}
	})

	t.Run("shaped for the revocation registry", func(t *testing.T) {
		got, err := mdocStatusClaim(&mdoc.MSOStatus{StatusList: &mdoc.MSOStatusList{URI: "https://r.example/statuslists/1", Idx: 42}})
		require.NoError(t, err)

		// The registry reads this exact shape for SD-JWT; mdoc must not need its own path.
		ref := revocation.ExtractStatusListReference(map[string]any{"status": got})
		require.NotNil(t, ref)
		assert.Equal(t, "https://r.example/statuslists/1", ref.URI)
		assert.Equal(t, int64(42), ref.Index)
	})

	t.Run("overflowing index is an error", func(t *testing.T) {
		_, err := mdocStatusClaim(&mdoc.MSOStatus{StatusList: &mdoc.MSOStatusList{URI: "https://r.example/1", Idx: math.MaxInt64 + 1}})
		require.Error(t, err)
	})
}
