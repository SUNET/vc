package openid4vp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// responseVectorsSHA256 pins the vendored conformance set.
//
// These vectors are what tells us this verifier, the Rust matcher and
// the two SDKs agree about what a circuit_zk presentation is. A local
// edit - or a stale copy after the upstream file moves - turns that
// cross-implementation check into a self-consistency check that passes
// while the implementations disagree.
//
// Re-vendor and re-pin; never edit. See testdata/circuit_zk_response/SOURCE.
const responseVectorsSHA256 = "25222766bc0aa0bb0f1308c54d1da2558ba14cf77a062c92f5b46e9edfe5296b"

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
func requestFromVector(t *testing.T, v responseVector) CircuitZkRequest {
	t.Helper()

	var query struct {
		ID       string    `json:"id"`
		Multiple bool      `json:"multiple"`
		Req      []ReqItem `json:"req"`
	}
	require.NoError(t, json.Unmarshal(v.Query, &query))

	request := CircuitZkRequest{QueryID: query.ID, Items: query.Req, Multiple: query.Multiple}

	if len(v.ClientMetadata) > 0 {
		var metadata struct {
			VPFormatsSupported struct {
				CircuitZk struct {
					CircuitIDValues          []string `json:"circuit_id_values"`
					CircuitProofSystemValues []string `json:"circuit_proof_system_values"`
				} `json:"circuit_zk"`
			} `json:"vp_formats_supported"`
		}
		require.NoError(t, json.Unmarshal(v.ClientMetadata, &metadata))
		request.OfferedCircuitIDs = metadata.VPFormatsSupported.CircuitZk.CircuitIDValues
		request.OfferedProofSystems = metadata.VPFormatsSupported.CircuitZk.CircuitProofSystemValues
	}
	return request
}

// The whole vendored conformance set, one subtest per file.
func TestCircuitZkResponseVectors(t *testing.T) {
	dir := filepath.Join("testdata", "circuit_zk_response")
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

			got, err := ValidateCircuitZkResponse(vpToken, requestFromVector(t, vector))

			if vector.Expect.Valid {
				require.NoErrorf(t, err, "%s: %s", name, vector.Description)
				assert.NotEmpty(t, got, "an accepted response carries presentations")
				return
			}

			require.Errorf(t, err, "%s: %s", name, vector.Description)
			var refusal *CircuitZkResponseError
			require.ErrorAs(t, err, &refusal)
			assert.Equalf(t, vector.Expect.Error, refusal.Reason,
				"%s: %s\nrefused with %q", name, vector.Description, refusal.Error())
		})
		ran++
	}

	// The set is big enough that a path typo producing zero subtests
	// would otherwise look like a pass.
	assert.GreaterOrEqual(t, ran, 40, "the vendored conformance set should be the whole set")
}

// The vendored copy must be the one every other implementation uses.
func TestCircuitZkResponseVectorsAreTheVendoredSet(t *testing.T) {
	dir := filepath.Join("testdata", "circuit_zk_response")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)

	// Over the files' contents AND their names, so a vector that is
	// deleted or renamed moves the digest too.
	digest := sha256.New()
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		require.NoError(t, err)
		digest.Write([]byte(name))
		digest.Write(raw)
	}
	assert.Equal(t, responseVectorsSHA256, hex.EncodeToString(digest.Sum(nil)),
		"the vendored vectors differ from the pinned set; re-vendor and re-pin rather than edit, "+
			"or this stops checking agreement with the other implementations")
}
