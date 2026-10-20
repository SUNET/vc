//go:build zknative

package verifier

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// longfellowVectorsPath is the copy staged by `make zk-native-lib`,
// which only exists in a zknative build - hence the tag.
const longfellowVectorsPath = "../../../third_party/zk-cred-longfellow/test-vectors/nymauth/challenge-vectors.json"

// The two repositories ship this file and must agree about it, BYTE
// FOR BYTE.
//
// testdata/SOURCE says either repository is a valid source. That was
// a claim nothing checked: the vendored copy comes from vega, and
// Longfellow's was staged beside it and never compared. They did in
// fact differ for a while - Longfellow carried the pre-redirect
// version - and this test allowed that gap explicitly while asserting
// it would expire. zk-cred-longfellow#14 closed it, so the exemption
// is gone and the comparison is now total.
//
// Total rather than per-array because that is what the claim in
// SOURCE actually says, and because a difference anywhere in this
// file means the verifier and one of the provers are binding
// presentations to different values.
func TestVendoredVectorsAgreeWithLongfellow(t *testing.T) {
	staged, err := os.ReadFile(longfellowVectorsPath)
	require.NoError(t, err, "run `make zk-native-lib` first")

	vendored, err := os.ReadFile(filepath.Join("testdata", "challenge-vectors.json"))
	require.NoError(t, err)

	assert.Equal(t, hex.EncodeToString(hashOf(vendored)), hex.EncodeToString(hashOf(staged)),
		"zk-cred-longfellow and the vendored copy disagree about challenge-vectors.json; "+
			"they are the same shared file, and a difference means this verifier and one of the "+
			"provers bind presentations to different values. Re-vendor from whichever is canonical.")

	// Spelled out as well as compared, so a failure says WHICH bytes
	// rather than only that two digests differ.
	assert.Equal(t, string(vendored), string(staged))
}

func hashOf(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}
