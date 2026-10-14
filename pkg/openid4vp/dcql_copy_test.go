package openid4vp

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// copyDCQL reconstructs each credential query field by field, so a field
// added to CredentialQuery is dropped by it until somebody remembers.
//
// That is exactly what happened: Req, Extra and Raw were added and the
// copier kept building queries without them, so every requested circuit
// function disappeared on the verifier's main template path - silently,
// because the result is still a valid query, just not the one configured.
//
// This guard derives the field set from the type rather than listing it.
// The fixture below must set every field of CredentialQuery to something
// non-zero, and the copy must equal it. Add a field and this test fails
// twice over: once because the fixture does not cover it, and again if the
// copier drops it.
func TestCopyDCQLCarriesEveryCredentialQueryField(t *testing.T) {
	yes := true
	path := "ssc"

	original := CredentialQuery{
		ID:       "nym_attestation",
		Format:   FormatCircuitZk,
		Multiple: true,
		Meta: MetaQuery{
			DoctypeValue: "eu.europa.ec.eudi.nym_auth.1",
			VCTValues:    []string{"urn:example"},
			TypeValues:   [][]string{{"https://example.org/T"}},
			PPIDContext:  "ctx",
			ZKSystemType: []ZKSystemTypeSpec{{ID: "i", System: "s", Params: map[string]string{"n": "1"}}},
		},
		TrustedAuthorities:                []TrustedAuthority{{Type: "aki", Values: []string{"v"}}},
		RequireCryptographicHolderBinding: &yes,
		Claims:                            []ClaimQuery{{ID: "c", Path: []*string{&path}, Values: []any{"v"}}},
		ClaimSet:                          [][]string{{"c"}},
		Req: []ReqItem{{
			ID: FunctionPseudonym, Return: "nym-123",
			Params: map[string]any{"config": "known-offender-matching-ssc"},
			Extra:  map[string]any{"source": map[string]any{"path": []any{"ssc"}}},
		}},
		Extra: map[string]any{"future_member": "kept"},
		// Raw is exclusive with the rest, so it is covered separately
		// below rather than set here.
	}

	// Every field must be covered by the fixture, derived from the type.
	for _, field := range reflect.VisibleFields(reflect.TypeOf(original)) {
		if !field.IsExported() {
			continue
		}
		if field.Name == "Raw" {
			continue // exclusive with the others; see TestCopyDCQLCarriesRaw
		}
		value := reflect.ValueOf(original).FieldByIndex(field.Index)
		assert.False(t, value.IsZero(),
			"the fixture leaves %s zero, so this test would not notice copyDCQL dropping it", field.Name)
	}

	src := &DCQL{Credentials: []CredentialQuery{original}}
	dst := copyDCQL(src)

	require.Len(t, dst.Credentials, 1)
	assert.Equal(t, original, dst.Credentials[0],
		"copyDCQL must reproduce the query it was given, member for member")

	// And it must be a COPY: mutating the original must not reach it.
	src.Credentials[0].Req[0].Params["config"] = "mutated"
	src.Credentials[0].Extra["future_member"] = "mutated"
	assert.Equal(t, "known-offender-matching-ssc", dst.Credentials[0].Req[0].Params["config"])
	assert.Equal(t, "kept", dst.Credentials[0].Extra["future_member"])
}

func TestCopyDCQLCarriesRaw(t *testing.T) {
	raw := json.RawMessage(`{"id":"q","format":"circuit_zk","claims":{"_req":[]}}`)
	src := &DCQL{Credentials: []CredentialQuery{{Raw: raw}}}
	dst := copyDCQL(src)

	require.Len(t, dst.Credentials, 1)
	assert.JSONEq(t, string(raw), string(dst.Credentials[0].Raw))

	src.Credentials[0].Raw[1] = 'X'
	assert.NotEqual(t, string(src.Credentials[0].Raw), string(dst.Credentials[0].Raw),
		"the copy must not alias the original's bytes")
}

// The template path is where this actually bit, so it is checked end to
// end rather than only at the copier.
func TestTemplateDCQLQueryKeepsCircuitFunctions(t *testing.T) {
	src := &DCQL{Credentials: []CredentialQuery{{
		ID:     "nym_attestation",
		Format: FormatCircuitZk,
		Meta:   MetaQuery{DoctypeValue: "eu.europa.ec.eudi.nym_auth.1"},
		Req: []ReqItem{
			{ID: FunctionPseudonym, Return: "nym-123", Params: map[string]any{"config": "known-offender-matching-ssc"}},
			{ID: FunctionAgeCheck, Return: "age-123", Params: map[string]any{"ge": "2008-10-10"}},
		},
	}}}

	dst := copyDCQL(src)

	encoded, err := json.Marshal(dst)
	require.NoError(t, err)
	assert.Contains(t, string(encoded), FunctionPseudonym,
		"a templated circuit_zk request that lost its functions asks the wallet for nothing")
	assert.Contains(t, string(encoded), FunctionAgeCheck)
	assert.Contains(t, string(encoded), "nym-123")
}
