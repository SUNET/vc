package openid4vp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A repeated key is judged by WHERE it is, and the two places have
// different codes.
//
// These cases are not in the vendored conformance set; they are the
// ways a scanner can get the scoping wrong, which is a property of
// this implementation rather than of the wire format. Both were real
// here before this test existed.
func TestDuplicateScopingByPosition(t *testing.T) {
	const query = `{
	  "id": "%s", "format": "circuit_zk",
	  "req": [{"id": "age_check", "return": "age-1", "params": {"ge": "2008-10-10", "le": "2013-10-09"}}]
	}`
	_ = query

	request := CircuitZkRequest{
		QueryID:             "nym_attestation",
		Items:               []ReqItem{{ID: CircuitZkFunctionAgeCheck, Return: "age-1"}},
		OfferedCircuitIDs:   []string{"urn:c"},
		OfferedProofSystems: []string{"longfellow-libzk-v1"},
	}

	presentation := func(queryID, results string) string {
		return `{"` + queryID + `":[{"circuit_id":"urn:c","proof_system":"longfellow-libzk-v1",` +
			`"proof":"AQID","x5chain":["Y2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2Nj"],"results":` + results + `}]}`
	}

	t.Run("a repeat inside a result VALUE is a duplicate member", func(t *testing.T) {
		// The handle does not repeat; the member inside its value
		// does. Reporting duplicate_handle here would name the wrong
		// thing, and would do it before the handle checks that must
		// come first.
		_, err := ValidateCircuitZkResponse(
			[]byte(presentation("nym_attestation", `{"age-1":{"satisfied":true,"satisfied":true}}`)), request)
		require.Error(t, err)

		var refusal *CircuitZkResponseError
		require.ErrorAs(t, err, &refusal)
		assert.Equal(t, ReasonDuplicateMember, refusal.Reason)
	})

	t.Run("a repeated handle is a duplicate handle", func(t *testing.T) {
		_, err := ValidateCircuitZkResponse(
			[]byte(presentation("nym_attestation", `{"age-1":{"satisfied":true},"age-1":{"satisfied":true}}`)), request)
		require.Error(t, err)

		var refusal *CircuitZkResponseError
		require.ErrorAs(t, err, &refusal)
		assert.Equal(t, ReasonDuplicateHandle, refusal.Reason)
	})

	t.Run("an unexpected handle wins over a repeated result member", func(t *testing.T) {
		// Handles are checked before values, so a response wrong in
		// both places is reported the same way by every
		// implementation.
		_, err := ValidateCircuitZkResponse(
			[]byte(presentation("nym_attestation",
				`{"age-1":{"satisfied":true},"nobody-asked":{"satisfied":true,"satisfied":true}}`)), request)
		require.Error(t, err)

		var refusal *CircuitZkResponseError
		require.ErrorAs(t, err, &refusal)
		assert.Equal(t, ReasonResultHandleUnexpected, refusal.Reason)
	})

	// A credential query id may legitimately BE "results". Skipping
	// the scan by the key's spelling let a presentation under that id
	// escape it entirely, so two "proof" members were accepted and
	// the decoder kept the last.
	t.Run("a credential query named results is still scanned", func(t *testing.T) {
		resultsRequest := request
		resultsRequest.QueryID = "results"

		raw := `{"results":[{"circuit_id":"urn:c","proof_system":"longfellow-libzk-v1",` +
			`"proof":"AQID","proof":"BAUG","x5chain":["Y2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2Nj"],"results":{"age-1":{"satisfied":true}}}]}`

		_, err := ValidateCircuitZkResponse([]byte(raw), resultsRequest)
		require.Error(t, err)

		var refusal *CircuitZkResponseError
		require.ErrorAs(t, err, &refusal)
		assert.Equal(t, ReasonDuplicateMember, refusal.Reason)
	})

	t.Run("and a valid presentation under that id still passes", func(t *testing.T) {
		resultsRequest := request
		resultsRequest.QueryID = "results"

		got, err := ValidateCircuitZkResponse([]byte(presentation("results", `{"age-1":{"satisfied":true}}`)), resultsRequest)
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, []string{"age-1"}, got[0].Satisfied)
	})
}
