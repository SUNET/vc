package openid4vp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// vectorsDir is the vendored conformance set; SOURCE records where
// from and at which commit.
const vectorsDir = "testdata/zkp_req"

// vectorSetDigest pins it, computed the way the matcher's
// scripts/vectors_digest.sh computes it: the sha256 of the sha256sum
// manifest of every *.json under the four directories, LC_ALL=C
// sorted, README.md excluded.
//
// These vectors are what tells us this verifier, the Rust matcher and
// the two SDKs agree about what a zkp_req presentation is. A local
// edit - or a stale copy after the upstream file moves - turns that
// cross-implementation check into a self-consistency check that
// passes while the implementations disagree.
const vectorSetDigest = "9f482d7a3fb87cb1381d0dfb7a2fc396b6cd3c1eba07c5d76f44e47142b751ac"

type responseVector struct {
	Description    string          `json:"description"`
	Query          json.RawMessage `json:"query"`
	ClientMetadata json.RawMessage `json:"client_metadata"`
	VPToken        json.RawMessage `json:"vp_token"`
	VPTokenText    *string         `json:"vp_token_text"`
	Expect         struct {
		Valid bool   `json:"valid"`
		Error string `json:"error"`
	} `json:"expect"`
}

// requestFromVector builds the verifier-side request a vector's
// response is checked against.
func requestFromVector(t *testing.T, v responseVector) ZkpReqRequest {
	t.Helper()

	var query struct {
		ID       string    `json:"id"`
		Multiple bool      `json:"multiple"`
		Req      []ReqItem `json:"_req"`
		Meta     struct {
			SourceFormat string `json:"source_format"`
		} `json:"meta"`
	}
	require.NoError(t, json.Unmarshal(v.Query, &query))

	request := ZkpReqRequest{
		QueryID:      query.ID,
		Items:        query.Req,
		Multiple:     query.Multiple,
		SourceFormat: query.Meta.SourceFormat,
	}
	if len(v.ClientMetadata) > 0 {
		var metadata struct {
			VPFormatsSupported struct {
				ZkpReq struct {
					SystemIDValues []string `json:"system_id_values"`
				} `json:"zkp_req"`
			} `json:"vp_formats_supported"`
		}
		require.NoError(t, json.Unmarshal(v.ClientMetadata, &metadata))
		request.OfferedSystemIDs = metadata.VPFormatsSupported.ZkpReq.SystemIDValues
	}
	return request
}

// The whole vendored response set, one subtest per file.
func TestZkpReqResponseVectors(t *testing.T) {
	dir := filepath.Join(vectorsDir, "zkp_req_response")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	ran := 0
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		name := entry.Name()
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(dir, name))
			require.NoError(t, err)

			var vector responseVector
			require.NoError(t, json.Unmarshal(raw, &vector))

			// Exactly one of vp_token / vp_token_text: the text form
			// carries inputs a parsed object cannot hold.
			var vpToken []byte
			switch {
			case vector.VPTokenText != nil:
				require.Empty(t, vector.VPToken, "%s: both vp_token and vp_token_text", name)
				vpToken = []byte(*vector.VPTokenText)
			default:
				require.NotEmpty(t, vector.VPToken, "%s: neither vp_token nor vp_token_text", name)
				vpToken = vector.VPToken
			}

			got, err := ValidateZkpReqResponse(vpToken, requestFromVector(t, vector))
			if vector.Expect.Error == "" {
				require.NoError(t, err, "%s: %s", name, vector.Description)
				assert.NotEmpty(t, got)
				return
			}
			var refusal *ZkpReqResponseError
			require.ErrorAs(t, err, &refusal, "%s: %s", name, vector.Description)
			assert.Equal(t, vector.Expect.Error, refusal.Reason,
				"%s: %s (detail: %s)", name, vector.Description, refusal.Detail)
		})
		ran++
	}
	require.NotZero(t, ran, "no vectors were read")
}

// The vendored copy must be the one the other implementations use.
func TestZkpReqVectorsAreTheVendoredSet(t *testing.T) {
	var manifest strings.Builder
	var names []string
	for _, set := range []string{"zkp_req", "zkp_req_response", "zkp_req_unsat", "proof_time"} {
		entries, err := os.ReadDir(filepath.Join(vectorsDir, set))
		require.NoError(t, err)
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".json") {
				names = append(names, filepath.Join(set, entry.Name()))
			}
		}
	}
	sort.Strings(names)
	require.NotEmpty(t, names)

	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(vectorsDir, name))
		require.NoError(t, err)
		fmt.Fprintf(&manifest, "%x  %s\n", sha256.Sum256(raw), name)
	}
	sum := sha256.Sum256([]byte(manifest.String()))
	assert.Equal(t, vectorSetDigest, hex.EncodeToString(sum[:]),
		"the vendored vectors differ from the pinned set; re-vendor and re-pin rather than edit, "+
			"or this stops checking agreement with the other implementations")
}
