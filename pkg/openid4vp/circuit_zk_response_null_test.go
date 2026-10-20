package openid4vp

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// JSON null is a TYPE ERROR wherever it appears, never an absent or
// an empty value.
//
// The vendored vectors now cover these same twelve positions, so this
// is deliberate duplication. It stays because it says the one thing a
// vector cannot: WHICH wrong answer each position would give without
// the check. That is Go-specific - its decoder treats null as "leave
// the target alone" and returns no error, so a member is refused as
// whatever its zero value happens to look like - and a reader who
// does not know that trap will read the refusal as redundant and
// remove it. The "instead" column is the argument for keeping it.
func TestCircuitZkNullIsAlwaysATypeError(t *testing.T) {
	request := CircuitZkRequest{
		QueryID: "nym_attestation",
		Items: []ReqItem{{
			ID:     CircuitZkFunctionAgeCheck,
			Return: "age-1",
		}},
		OfferedCircuitIDs:   []string{"urn:c"},
		OfferedProofSystems: []string{"longfellow-libzk-v1"},
	}
	pseudonymRequest := CircuitZkRequest{
		QueryID:             "nym_attestation",
		Items:               []ReqItem{{ID: CircuitZkFunctionPseudonym, Return: "nym-1"}},
		OfferedCircuitIDs:   []string{"urn:c"},
		OfferedProofSystems: []string{"longfellow-libzk-v1"},
	}

	leaf := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("c", 48)))
	// A presentation with one member replaced by the given JSON text.
	presentation := func(member, value string) string {
		parts := map[string]string{
			"circuit_id":   `"urn:c"`,
			"proof_system": `"longfellow-libzk-v1"`,
			"proof":        `"AQID"`,
			"x5chain":      fmt.Sprintf(`[%q]`, leaf),
			"results":      `{"age-1":{"satisfied":true}}`,
		}
		parts[member] = value
		return fmt.Sprintf(`{"nym_attestation":[{"circuit_id":%s,"proof_system":%s,"proof":%s,"x5chain":%s,"results":%s}]}`,
			parts["circuit_id"], parts["proof_system"], parts["proof"], parts["x5chain"], parts["results"])
	}

	for _, tc := range []struct {
		name     string
		token    string
		request  CircuitZkRequest
		reason   string
		insteady string
	}{{
		name:     "the whole vp_token",
		token:    `null`,
		reason:   ReasonResponseNotParseable,
		insteady: "an empty envelope, reported as a missing query id",
	}, {
		name:     "the presentations array",
		token:    `{"nym_attestation":null}`,
		reason:   ReasonPresentationsNotArray,
		insteady: "an empty array, reported as presentations_empty",
	}, {
		name:     "one presentation",
		token:    `{"nym_attestation":[null]}`,
		reason:   ReasonPresentationNotObject,
		insteady: "an empty object, reported as a missing member",
	}, {
		name:     "circuit_id",
		token:    presentation("circuit_id", "null"),
		reason:   ReasonPresentationMemberWrongType,
		insteady: `the empty string, reported as circuit_id_not_offered`,
	}, {
		name:     "proof_system",
		token:    presentation("proof_system", "null"),
		reason:   ReasonPresentationMemberWrongType,
		insteady: `the empty string, reported as proof_system_not_offered`,
	}, {
		name:     "proof",
		token:    presentation("proof", "null"),
		reason:   ReasonPresentationMemberWrongType,
		insteady: `the empty string, reported as proof_empty`,
	}, {
		name:     "x5chain",
		token:    presentation("x5chain", "null"),
		reason:   ReasonX5ChainNotArray,
		insteady: "an empty chain, reported as x5chain_empty",
	}, {
		name:     "an x5chain element",
		token:    presentation("x5chain", fmt.Sprintf(`[%q,null]`, leaf)),
		reason:   ReasonX5ChainElementNotString,
		insteady: "an empty certificate, reported as x5chain_element_empty",
	}, {
		name:     "results",
		token:    presentation("results", "null"),
		reason:   ReasonPresentationMemberWrongType,
		insteady: "an empty results object, reported as a missing handle",
	}, {
		name:     "one result value",
		token:    presentation("results", `{"age-1":null}`),
		reason:   ReasonResultNotObject,
		insteady: "an empty result object, reported as a missing member",
	}, {
		name:     "a boolean result member",
		token:    presentation("results", `{"age-1":{"satisfied":null}}`),
		reason:   ReasonResultMemberWrongType,
		insteady: "false, reported as result_not_satisfied",
	}, {
		name:     "a string result member",
		token:    strings.Replace(presentation("results", `{"nym-1":{"pseudonym":null}}`), `"age-1"`, `"nym-1"`, 1),
		request:  pseudonymRequest,
		reason:   ReasonResultMemberWrongType,
		insteady: "the empty string, reported as pseudonym_wrong_length",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			req := request
			if tc.request.QueryID != "" {
				req = tc.request
			}
			_, err := ValidateCircuitZkResponse([]byte(tc.token), req)
			var refusal *CircuitZkResponseError
			require.ErrorAs(t, err, &refusal)
			assert.Equal(t, tc.reason, refusal.Reason,
				"null here must be a type error; without the check it reads as %s. detail: %s",
				tc.insteady, refusal.Detail)
		})
	}
}
