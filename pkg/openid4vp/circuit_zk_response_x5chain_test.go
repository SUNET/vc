package openid4vp

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The vendored conformance vectors cover which x5chain values are
// refused and with which code. What they cannot cover is what this
// package does with an accepted one, or the two rules that need raw
// text a JSON file cannot hold. That is what is here.

// x5chainRequest is the request these cases are checked against: one
// handle, one offered circuit and proof system, so that nothing but
// the chain can be what a case refuses on.
func x5chainRequest() CircuitZkRequest {
	return CircuitZkRequest{
		QueryID: "nym_attestation",
		Items: []ReqItem{{
			ID:     "age_check",
			Return: "age-range-123",
			Params: map[string]any{"ge": "2008-10-10", "le": "2013-10-09"},
		}},
		OfferedCircuitIDs:   []string{"urn:circuits:longfellow:nym_auth:v1"},
		OfferedProofSystems: []string{"longfellow-libzk-v1"},
	}
}

// x5chainToken builds a vp_token whose single presentation carries
// x5chainMember verbatim - as raw JSON text, so that a case can state
// a member no Go value could express.
func x5chainToken(x5chainMember string) []byte {
	proof := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("p", 48)))
	return []byte(fmt.Sprintf(`{"nym_attestation":[{
	  "circuit_id":"urn:circuits:longfellow:nym_auth:v1",
	  "proof_system":"longfellow-libzk-v1",
	  "proof":%q,
	  %s,
	  "results":{"age-range-123":{"satisfied":true}}}]}`, proof, x5chainMember))
}

// derOfSize is a stand-in certificate of a stated decoded size. This
// package bounds and decodes; it does not parse X.509, and a case
// about the bytes should not depend on a parser that runs later.
func derOfSize(n int) string {
	return base64.StdEncoding.EncodeToString([]byte(strings.Repeat("c", n)))
}

// An accepted chain reaches the caller whole, in order and decoded -
// the verifier takes Q from the LEAF, so the order is not cosmetic.
func TestCircuitZkX5ChainIsCarriedThrough(t *testing.T) {
	leaf, root := derOfSize(600), derOfSize(700)
	token := x5chainToken(fmt.Sprintf(`"x5chain":[%q,%q]`, leaf, root))

	got, err := ValidateCircuitZkResponse(token, x5chainRequest())
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Len(t, got[0].X5Chain, 2)
	assert.Equal(t, []byte(strings.Repeat("c", 600)), got[0].X5Chain[0], "leaf first")
	assert.Equal(t, []byte(strings.Repeat("c", 700)), got[0].X5Chain[1])
}

// A repeated x5chain is a repeated member, refused on the RAW TEXT
// before anything decodes it. A decoder would silently keep one of
// the two chains, and which one would be the wallet's choice - so
// this cannot be expressed as a vector's parsed vp_token, and is not
// one.
func TestCircuitZkX5ChainRepeatedMember(t *testing.T) {
	member := fmt.Sprintf(`"x5chain":[%q],"x5chain":[%q]`, derOfSize(600), derOfSize(700))

	_, err := ValidateCircuitZkResponse(x5chainToken(member), x5chainRequest())
	var refusal *CircuitZkResponseError
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, ReasonDuplicateMember, refusal.Reason)
}

// Adding x5chain to the member set must not open it: a neighbouring
// unknown member is still refused.
func TestCircuitZkX5ChainDoesNotOpenTheMemberSet(t *testing.T) {
	member := fmt.Sprintf(`"x5chain":[%q],"x5bag":[]`, derOfSize(600))

	_, err := ValidateCircuitZkResponse(x5chainToken(member), x5chainRequest())
	var refusal *CircuitZkResponseError
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, ReasonPresentationUnknownMember, refusal.Reason)
}

// A JSON null is not an array. It decodes into a nil slice without
// error, which would otherwise read as an empty chain and be reported
// as the wrong refusal.
func TestCircuitZkX5ChainNullIsNotAnArray(t *testing.T) {
	_, err := ValidateCircuitZkResponse(x5chainToken(`"x5chain":null`), x5chainRequest())
	var refusal *CircuitZkResponseError
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, ReasonX5ChainNotArray, refusal.Reason, "detail: %s", refusal.Detail)
}

// The limit is on the DECODED bytes. A certificate that is under it
// only because it was never decoded does not pass, and one exactly at
// it does: 4096 bytes of DER is 5464 characters of base64.
func TestCircuitZkX5ChainLimitIsOnDecodedBytes(t *testing.T) {
	atTheLimit := derOfSize(MaxX5ChainCertificateBytes)
	require.Len(t, atTheLimit, 5464)

	got, err := ValidateCircuitZkResponse(
		x5chainToken(fmt.Sprintf(`"x5chain":[%q]`, atTheLimit)), x5chainRequest())
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Len(t, got[0].X5Chain[0], MaxX5ChainCertificateBytes)
}

// Every vendored vector that is meant to be valid carries an x5chain.
// The member is required, so a valid vector without one would mean
// the vendored set and this implementation disagree about that -
// which is exactly what the conformance set exists to catch, and
// would otherwise show up only as a confusing failure elsewhere.
func TestCircuitZkValidVectorsAllCarryX5Chain(t *testing.T) {
	dir := filepath.Join("testdata", "circuit_zk_response")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	checked := 0
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "ok_") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		require.NoError(t, err)
		assert.Contains(t, string(raw), `"x5chain"`, "%s is a valid vector with no x5chain", entry.Name())
		checked++
	}
	require.NotZero(t, checked, "no valid vectors were read")
}
