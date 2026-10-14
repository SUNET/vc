package openid4vp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	yamlv2 "gopkg.in/yaml.v2"
)

// The extension bags have to work from YAML, because that is where an
// operator actually configures them.
//
// Extra is tagged yaml:"-", so without MarshalYAML/UnmarshalYAML its
// members are read and silently dropped - an escape hatch that exists in
// the documentation and not in the product. Both
// .verifier.preferred_vp_formats and the presentation request templates
// (pkg/configuration, openid4vp.DCQL) are loaded from YAML.
func TestExtraSurvivesYAML(t *testing.T) {
	t.Run("the envelope form an operator is most likely to need", func(t *testing.T) {
		const in = `
fn_id: circuit_zk_longfellow
input: eyJhIjoxfQ==
`
		var format CircuitZkFormat
		require.NoError(t, yamlv2.Unmarshal([]byte(in), &format))
		require.NotNil(t, format.Extra, "the envelope members must not be dropped")
		assert.Equal(t, "circuit_zk_longfellow", format.Extra["fn_id"])
		assert.Equal(t, "eyJhIjoxfQ==", format.Extra["input"])

		// And out again, so a config read in is a request sent out.
		encoded, err := json.Marshal(format)
		require.NoError(t, err)
		assert.JSONEq(t, `{"fn_id":"circuit_zk_longfellow","input":"eyJhIjoxfQ=="}`, string(encoded))
	})

	t.Run("the plain arrays, alongside an unknown member", func(t *testing.T) {
		const in = `
circuit_proof_system_values: ["longfellow-libzk-v1"]
circuit_id_values: ["urn:circuits:longfellow:nym_auth:v1"]
future_member: kept
`
		var format CircuitZkFormat
		require.NoError(t, yamlv2.Unmarshal([]byte(in), &format))
		assert.Equal(t, []string{"longfellow-libzk-v1"}, format.CircuitProofSystemValues)
		assert.Equal(t, []string{"urn:circuits:longfellow:nym_auth:v1"}, format.CircuitIDValues)
		assert.Equal(t, "kept", format.Extra["future_member"])
	})

	t.Run("a req item", func(t *testing.T) {
		const in = `
id: pseudonym-v1-sha256
return: nym-123
params:
  config: known-offender-matching-ssc
  verifier_id_type: x509_san_dns
source:
  path: [ssc]
`
		var item ReqItem
		require.NoError(t, yamlv2.Unmarshal([]byte(in), &item))
		assert.Equal(t, FunctionPseudonym, item.ID)
		assert.Equal(t, "nym-123", item.Return)
		assert.Equal(t, "known-offender-matching-ssc", item.Params["config"])
		require.NotNil(t, item.Extra, "a member outside the model must survive")
		assert.Contains(t, item.Extra, "source")
	})

	t.Run("a whole credential query, as a presentation request template carries it", func(t *testing.T) {
		const in = `
id: nym_attestation
format: circuit_zk
meta:
  doctype_value: eu.europa.ec.eudi.nym_auth.1
req:
  - id: pseudonym-v1-sha256
    return: nym-123
    params:
      config: known-offender-matching-ssc
  - id: age_check
    return: age-123
    params:
      ge: "2008-10-10"
      le: "2013-10-09"
future_member: kept
`
		var query CredentialQuery
		require.NoError(t, yamlv2.Unmarshal([]byte(in), &query))

		assert.Equal(t, FormatCircuitZk, query.Format)
		assert.Equal(t, "eu.europa.ec.eudi.nym_auth.1", query.Meta.DoctypeValue)
		require.Len(t, query.Req, 2, "the functions must survive the YAML decode")
		assert.Equal(t, FunctionPseudonym, query.Req[0].ID)
		assert.Equal(t, "age_check", query.Req[1].ID)
		assert.Equal(t, "2008-10-10", query.Req[1].Params["ge"])
		assert.Equal(t, "kept", query.Extra["future_member"])

		// The request that leaves is the request that was configured.
		encoded, err := json.Marshal(query)
		require.NoError(t, err)
		assert.JSONEq(t, `{
			"id":"nym_attestation","format":"circuit_zk",
			"meta":{"doctype_value":"eu.europa.ec.eudi.nym_auth.1"},
			"req":[
			  {"id":"pseudonym-v1-sha256","return":"nym-123","params":{"config":"known-offender-matching-ssc"}},
			  {"id":"age_check","return":"age-123","params":{"ge":"2008-10-10","le":"2013-10-09"}}
			],
			"future_member":"kept"}`, string(encoded))
	})
}

// YAML and JSON must agree about what is modelled and what is an
// extension, or a request behaves differently depending on which side of
// the configuration it was written on.
func TestYAMLAndJSONAgreeOnWhatIsModelled(t *testing.T) {
	const yamlIn = `
id: nym_attestation
format: circuit_zk
meta:
  doctype_value: d
req:
  - id: age_check
    return: h
    params: {ge: "2008-10-10"}
unknown_member: x
`
	const jsonIn = `{"id":"nym_attestation","format":"circuit_zk","meta":{"doctype_value":"d"},
		"req":[{"id":"age_check","return":"h","params":{"ge":"2008-10-10"}}],"unknown_member":"x"}`

	var fromYAML, fromJSON CredentialQuery
	require.NoError(t, yamlv2.Unmarshal([]byte(yamlIn), &fromYAML))
	require.NoError(t, json.Unmarshal([]byte(jsonIn), &fromJSON))

	yamlEncoded, err := json.Marshal(fromYAML)
	require.NoError(t, err)
	jsonEncoded, err := json.Marshal(fromJSON)
	require.NoError(t, err)
	assert.JSONEq(t, string(jsonEncoded), string(yamlEncoded),
		"the same request written in YAML and in JSON must go out the same")
}

// YAML applies the same rule as JSON: an extension may not supply a
// member the type models.
func TestYAMLExtraCannotSupplyAModelledMember(t *testing.T) {
	for _, tc := range []struct {
		name string
		do   func() ([]byte, error)
	}{
		// The empty cases are the ones that matter: a check against the
		// populated map would pass them, which is how the JSON side was
		// wrong before review and how this side was wrong an hour later.
		{"circuit metadata, field EMPTY", func() ([]byte, error) {
			return yamlv2.Marshal(CircuitZkFormat{Extra: map[string]any{"circuit_id_values": []string{"x"}}})
		}},
		{"circuit metadata, field set", func() ([]byte, error) {
			return yamlv2.Marshal(CircuitZkFormat{CircuitIDValues: []string{"a"}, Extra: map[string]any{"circuit_id_values": []string{"x"}}})
		}},
		{"req item, params EMPTY", func() ([]byte, error) {
			return yamlv2.Marshal(ReqItem{ID: "f", Return: "h", Extra: map[string]any{"params": "x"}})
		}},
		{"credential query, req EMPTY", func() ([]byte, error) {
			return yamlv2.Marshal(CredentialQuery{ID: "q", Format: FormatCircuitZk, Extra: map[string]any{"req": "x"}})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.do()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "a member this type models")
		})
	}
}
