//go:build zknative

package verifier

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// longfellowVectorsPath is the copy staged by `make zk-native-lib`,
// which only exists in a zknative build - hence the tag.
const longfellowVectorsPath = "../../../third_party/zk-cred-longfellow/test-vectors/nymauth/challenge-vectors.json"

// The two repositories ship this file and must agree about it.
//
// testdata/SOURCE says either repository is a valid source. That is a
// claim nothing was checking: the vendored copy comes from vega, and
// Longfellow's was simply staged beside it and never compared. They
// are in fact DIFFERENT today - Longfellow v0.1.2 carries the
// pre-redirect version - and nothing noticed, which is the part worth
// fixing rather than the difference itself.
//
// What is checked is what the invariant actually is: the arrays BOTH
// files carry must be identical. A library that changed a transcript
// shape under the vendored file would show up here, in the data,
// rather than only in the derivation cross-checks beside this.
//
// derive_redirect and rejects_redirect are deliberately exempt while
// Longfellow has not mirrored them. That exemption is asserted, not
// assumed: when Longfellow does mirror them this test fails and says
// to tighten it, instead of silently continuing to ignore two arrays.
func TestVendoredVectorsAgreeWithLongfellow(t *testing.T) {
	raw, err := os.ReadFile(longfellowVectorsPath)
	require.NoError(t, err, "run `make zk-native-lib` first")

	var longfellow, vendored map[string]any
	require.NoError(t, json.Unmarshal(raw, &longfellow))

	raw, err = os.ReadFile(filepath.Join("testdata", "challenge-vectors.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &vendored))

	// Everything both files carry.
	for _, key := range []string{"version", "min_nonce_chars", "derive", "digest", "rejects"} {
		t.Run(key, func(t *testing.T) {
			require.Contains(t, longfellow, key, "Longfellow's copy is missing %q entirely", key)
			require.Contains(t, vendored, key)
			assert.Equal(t, longfellow[key], vendored[key],
				"the two repositories disagree about %q; they are the same shared file and a difference here "+
					"means the verifier and one of the provers are binding presentations to different values", key)
		})
	}

	// The known, temporary asymmetry - asserted so that it cannot
	// quietly become permanent.
	for _, key := range []string{"derive_redirect", "rejects_redirect"} {
		require.Contains(t, vendored, key, "the vendored copy must carry %q", key)
		assert.NotContains(t, longfellow, key,
			"Longfellow now carries %q: mirror is complete, so replace this exemption with a full "+
				"equality check and re-vendor from whichever repository is canonical", key)
	}
}
