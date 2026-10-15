package openid4vp

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

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

// A wrong type in YAML must not be silently replaced by a zero value.
//
// The first implementation here assigned through a comma-ok assertion, so
// `id: 7` became "" - the serialiser repairing a request it promised to
// pass through, and losing the operator's value in the process. Known
// members go through a methodless alias now, so yaml.v2 handles the type
// exactly as it does for every other configuration struct in this
// repository: a scalar is coerced to the field's type, and a structural
// mismatch is an error.
//
// Coercion rather than refusal is deliberate. Diverging from yaml.v2 here
// would make this one struct behave unlike the rest of the configuration
// surface, which is a worse surprise than "7" where 7 was written.
func TestYAMLWrongTypesAreNotSilentlyEmptied(t *testing.T) {
	t.Run("a scalar is coerced, not emptied", func(t *testing.T) {
		var item ReqItem
		require.NoError(t, yamlv2.Unmarshal([]byte("id: 7\nreturn: h\n"), &item))
		assert.Equal(t, "7", item.ID, "the configured value must survive in some form, not become empty")
		assert.NotEmpty(t, item.ID)
	})

	for _, tc := range []struct{ name, in string }{
		{"params that are a list", "id: age_check\nreturn: h\nparams: [1, 2]\n"},
		{"params that are a scalar", "id: age_check\nreturn: h\nparams: 7\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var item ReqItem
			require.Error(t, yamlv2.Unmarshal([]byte(tc.in), &item),
				"a structural mismatch is an error, as it is everywhere else in the configuration")
		})
	}

	t.Run("a circuit list that is not a list", func(t *testing.T) {
		var format CircuitZkFormat
		require.Error(t, yamlv2.Unmarshal([]byte("circuit_id_values: {a: b}\n"), &format))
	})
}

// yaml.v2 materialises every nested mapping as map[any]any. Carrying that
// into Extra and out through JSON depends on what encoding/json does with
// a non-string key, which has changed between releases: it currently
// coerces an integer key and drops a sequence key SILENTLY. Neither is an
// acceptable way to read a verifier's own configuration.
func TestNestedYAMLExtraIsNormalisedAndNonStringKeysRefused(t *testing.T) {
	t.Run("nested mappings survive", func(t *testing.T) {
		const in = `
id: age_check
return: h
source:
  path: [birth_date]
  nested:
    deep: 1
`
		var item ReqItem
		require.NoError(t, yamlv2.Unmarshal([]byte(in), &item))
		encoded, err := json.Marshal(item)
		require.NoError(t, err)
		assert.JSONEq(t, `{"id":"age_check","return":"h","source":{"path":["birth_date"],"nested":{"deep":1}}}`, string(encoded))
	})

	t.Run("a non-string key is refused rather than coerced or dropped", func(t *testing.T) {
		var item ReqItem
		err := yamlv2.Unmarshal([]byte("id: age_check\nreturn: h\nsource:\n  2: two\n"), &item)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a string key")
	})
}

// The whole point of the alias decode: an ordinary, pre-existing
// presentation template with nested meta still loads.
func TestOrdinaryTemplatesStillLoad(t *testing.T) {
	const in = `
id: pid
format: dc+sd-jwt
meta:
  vct_values: ["urn:eudi:pid:1"]
claims:
  - path: [family_name]
`
	var query CredentialQuery
	require.NoError(t, yamlv2.Unmarshal([]byte(in), &query))
	assert.Equal(t, FormatSDJWTVC, query.Format)
	assert.Equal(t, []string{"urn:eudi:pid:1"}, query.Meta.VCTValues)
	require.Len(t, query.Claims, 1)
	assert.Nil(t, query.Extra, "nothing here is an extension")
}

// A valid nested params tree must come through the normalisation walk
// unchanged.
//
// This direction is the one the walk could break: it rebuilds every
// mapping it touches, and params is an INPUT TO A PROOF - the pseudonym a
// wallet computes depends on it byte for byte. The behaviour the walk
// CHANGES is in TestReqItemParamsRefusesNonStringKeys; on this toolchain
// encoding/json already handles a nested map[any]any whose keys are all
// strings, so this case would pass without the walk too.
func TestReqItemParamsSurviveNormalisationUnchanged(t *testing.T) {
	const in = `
id: pseudonym-v1-sha256
return: nym-123
params:
  config: known-offender-matching-ssc
  nested:
    inner: value
    deeper:
      - key: in-a-sequence
`
	var item ReqItem
	require.NoError(t, yamlv2.Unmarshal([]byte(in), &item))

	// The point is that this encodes at all, and keeps every member.
	encoded, err := json.Marshal(item)
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"id": "pseudonym-v1-sha256",
		"return": "nym-123",
		"params": {
			"config": "known-offender-matching-ssc",
			"nested": {"inner": "value", "deeper": [{"key": "in-a-sequence"}]}
		}
	}`, string(encoded))
}

// A key with no JSON spelling is refused rather than coerced to its
// rendering or dropped, for the same reason: silently changing a proof
// input is worse than refusing to load the configuration.
func TestReqItemParamsRefusesNonStringKeys(t *testing.T) {
	for _, tc := range []struct{ name, in, wantErr string }{
		// An integer key reaches the walk: yaml.v2 is happy to put it in a
		// map[any]any, and JSON would then quietly render it as "7".
		{"an integer key", "id: f\nreturn: h\nparams:\n  nested:\n    7: seven\n", "not a string key"},
		// A sequence key never gets that far - yaml.v2 refuses it on its
		// own. Asserted anyway, and on the OUTCOME rather than the
		// wording: this is the case JSON drops in silence, and which of
		// the two layers catches it is not the point.
		{"a sequence key", "id: f\nreturn: h\nparams:\n  nested:\n    [a, b]: pair\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var item ReqItem
			err := yamlv2.Unmarshal([]byte(tc.in), &item)
			require.Error(t, err)
			if tc.wantErr != "" {
				assert.Contains(t, err.Error(), tc.wantErr)
			}
		})
	}
}

// verifier.preferred_vp_formats loads into VPFormatsSupported from YAML,
// so that is the path a format identifier postdating this build actually
// arrives by. With JSON methods alone the extension bag was dropped
// exactly where an operator would use it.
func TestVPFormatsSupportedCarriesUnknownFormatsThroughYAML(t *testing.T) {
	const in = `
mso_mdoc: {}
circuit_zk:
  circuit_proof_system_values: [longfellow-libzk-v1]
some_future_format:
  alg_values: [ES256]
`
	var formats VPFormatsSupported
	require.NoError(t, yamlv2.Unmarshal([]byte(in), &formats))

	require.NotNil(t, formats.MsoMdoc)
	require.NotNil(t, formats.CircuitZk)
	assert.Equal(t, []string{"longfellow-libzk-v1"}, formats.CircuitZk.CircuitProofSystemValues)
	require.Contains(t, formats.Extra, "some_future_format")

	// And out to the wallet unchanged - client_metadata is JSON.
	encoded, err := json.Marshal(formats)
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"mso_mdoc": {},
		"circuit_zk": {"circuit_proof_system_values": ["longfellow-libzk-v1"]},
		"some_future_format": {"alg_values": ["ES256"]}
	}`, string(encoded))

	// And back to YAML, so a config that round-trips keeps it.
	reencoded, err := yamlv2.Marshal(formats)
	require.NoError(t, err)
	var again VPFormatsSupported
	require.NoError(t, yamlv2.Unmarshal(reencoded, &again))
	assert.Equal(t, formats.Extra, again.Extra)
}

// A req param is an input to a proof, and yaml.v2 resolves a non-integer
// scalar to a float64 before anything here can look at it - so the
// configured precision is gone upstream of every check, and the check
// downstream sees a value that is perfectly stable because the damage
// already happened.
//
// Integers survive yaml.v2 intact. It is the decimals that do not, which
// is why this pins both.
func TestReqItemParamsKeepTheConfiguredDigits(t *testing.T) {
	for _, tc := range []struct{ name, in, want, wantLiteral string }{
		{
			name:        "a decimal yaml.v2 would round",
			in:          "id: f\nreturn: h\nparams:\n  p: 1.00000000000000001\n",
			want:        `{"id":"f","return":"h","params":{"p":1.00000000000000001}}`,
			wantLiteral: "1.00000000000000001",
		},
		{
			name:        "an ordinary decimal",
			in:          "id: f\nreturn: h\nparams:\n  p: 0.1\n",
			want:        `{"id":"f","return":"h","params":{"p":0.1}}`,
			wantLiteral: "0.1",
		},
		{
			name:        "a large integer, which survived already",
			in:          "id: f\nreturn: h\nparams:\n  p: 9007199254740993\n",
			want:        `{"id":"f","return":"h","params":{"p":9007199254740993}}`,
			wantLiteral: "9007199254740993",
		},
		{
			name:        "nested inside a mapping",
			in:          "id: f\nreturn: h\nparams:\n  outer:\n    p: 1.00000000000000001\n",
			want:        `{"id":"f","return":"h","params":{"outer":{"p":1.00000000000000001}}}`,
			wantLiteral: "1.00000000000000001",
		},
		{
			name:        "and inside a sequence",
			in:          "id: f\nreturn: h\nparams:\n  list:\n    - 1.00000000000000001\n",
			want:        `{"id":"f","return":"h","params":{"list":[1.00000000000000001]}}`,
			wantLiteral: "[1.00000000000000001]",
		},
		{
			name:        "a string stays a string",
			in:          "id: f\nreturn: h\nparams:\n  p: \"1.00000000000000001\"\n",
			want:        `{"id":"f","return":"h","params":{"p":"1.00000000000000001"}}`,
			wantLiteral: `"1.00000000000000001"`,
		},
		{
			name:        "and a bool is untouched",
			in:          "id: f\nreturn: h\nparams:\n  p: true\n",
			want:        `{"id":"f","return":"h","params":{"p":true}}`,
			wantLiteral: "true",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var item ReqItem
			require.NoError(t, yamlv2.Unmarshal([]byte(tc.in), &item))
			encoded, err := json.Marshal(item)
			require.NoError(t, err)
			assert.JSONEq(t, tc.want, string(encoded))

			// JSONEq parses both sides as float64, so it cannot see the
			// digits it was given - it passes on a rounded value. The
			// literal has to be checked as text.
			assert.Contains(t, string(encoded), tc.wantLiteral,
				"the configured digits have to reach the wire, not a float64's rendering of them")
		})
	}
}

// A spelling YAML allows and JSON does not keeps the resolved value:
// inventing a JSON spelling for it would be a worse answer than the
// rounding.
func TestReqItemParamsFallBackForNonJSONSpellings(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"hexadecimal", "id: f\nreturn: h\nparams:\n  p: 0x10\n", `{"id":"f","return":"h","params":{"p":16}}`},
		{"octal", "id: f\nreturn: h\nparams:\n  p: 0o17\n", `{"id":"f","return":"h","params":{"p":15}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var item ReqItem
			require.NoError(t, yamlv2.Unmarshal([]byte(tc.in), &item))
			encoded, err := json.Marshal(item)
			require.NoError(t, err)
			assert.JSONEq(t, tc.want, string(encoded))
		})
	}
}

// Writing the configuration back out must not change a proof input
// either. The YAML marshal path bridges through JSON, so an
// exactly-preserved param arrives as a json.Number - and yaml.v2 encodes
// one through Int64 and then Float64, which rounds an integer beyond
// int64 and a decimal with more digits than a float64 holds.
//
// Every other path keeps these exact, so the honest answer here is to
// stop rather than to round quietly or to repair.
func TestYAMLRefusesToWriteANumberItWouldChange(t *testing.T) {
	for _, tc := range []struct {
		name, literal string
		ok            bool
	}{
		{"a small integer", "7", true},
		{"the largest int64", "9223372036854775807", true},
		{"an integer beyond int64", "123456789012345678901234567890", false},
		{"an ordinary decimal", "0.1", true},
		{"a decimal beyond float64 precision", "1.00000000000000001", false},
		{"a large integer inside float64's exact range", "9007199254740993", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			query := CredentialQuery{
				ID: "q", Format: FormatCircuitZk,
				Req: []ReqItem{{ID: "f", Return: "h", Params: map[string]any{"p": json.Number(tc.literal)}}},
			}
			encoded, err := yamlv2.Marshal(query)
			if !tc.ok {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "without changing it")
				assert.Contains(t, err.Error(), tc.literal, "the error has to name the value an operator must fix")
				return
			}
			require.NoError(t, err)
			assert.Contains(t, string(encoded), tc.literal,
				"an accepted number has to come back out as the digits that went in")
		})
	}
}

// Nested, and named by path so an operator can find it.
func TestYAMLNumberRefusalNamesThePath(t *testing.T) {
	query := CredentialQuery{
		ID: "q", Format: FormatCircuitZk,
		Req: []ReqItem{{ID: "f", Return: "h", Params: map[string]any{
			"outer": map[string]any{"inner": json.Number("1.00000000000000001")},
		}}},
	}
	_, err := yamlv2.Marshal(query)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "outer.inner")
}

// Two YAML scalars that have no JSON number to become, each failing in a
// different and quiet way before this refused them.
func TestReqItemParamsRefuseScalarsWithNoJSONNumber(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{
			// yaml.v2 resolves an overflowing literal to a STRING, and
			// nothing in what it hands back says whether the operator
			// wrote 1e400 or "1e400". A proof input quietly changing type
			// is invisible downstream: a string always looks stable.
			name: "a literal too large for yaml.v2 to hold",
			in:   "id: f\nreturn: h\nparams:\n  p: 1e400\n",
			want: "cannot tell",
		},
		{
			// These reach json.Marshal, which refuses them - so the whole
			// request object becomes unencodable at SEND time, far from
			// the configuration that caused it.
			name: "infinity",
			in:   "id: f\nreturn: h\nparams:\n  p: .inf\n",
			want: "no JSON spelling",
		},
		{
			name: "negative infinity",
			in:   "id: f\nreturn: h\nparams:\n  p: -.inf\n",
			want: "no JSON spelling",
		},
		{
			name: "not a number",
			in:   "id: f\nreturn: h\nparams:\n  p: .nan\n",
			want: "no JSON spelling",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var item ReqItem
			err := yamlv2.Unmarshal([]byte(tc.in), &item)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// And the neighbours that must keep working, so the refusal above is not
// quietly a ban on exponents or on strings.
func TestReqItemParamsKeepWhatIsRepresentable(t *testing.T) {
	for _, tc := range []struct{ name, in, wantJSON string }{
		{"an underflowing literal, which yaml.v2 does resolve", "id: f\nreturn: h\nparams:\n  p: 1e-400\n", `{"p":1e-400}`},
		{"an ordinary exponent", "id: f\nreturn: h\nparams:\n  p: 1e10\n", `{"p":1e10}`},
		{"a string that is not a number spelling", "id: f\nreturn: h\nparams:\n  p: \"inf\"\n", `{"p":"inf"}`},
		{"an ordinary string", "id: f\nreturn: h\nparams:\n  p: x509_san_dns\n", `{"p":"x509_san_dns"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var item ReqItem
			require.NoError(t, yamlv2.Unmarshal([]byte(tc.in), &item))
			encoded, err := json.Marshal(item.Params)
			require.NoError(t, err)
			assert.JSONEq(t, tc.wantJSON, string(encoded))
		})
	}
}

// Raw is tagged yaml:"-", so the YAML bridge emitted only the modelled
// shadow - a DIFFERENT query, missing whatever made the bytes raw, and
// missing it silently. A presentation template written back out lost the
// one member it existed to carry.
//
// Both directions, because emitting a shape this type then refuses to
// read back would be the same defect wearing the other face.
func TestRawSurvivesTheYAMLRoundTrip(t *testing.T) {
	const configured = `{"id":"q","format":"circuit_zk","meta":{"doctype_value":"d"},"claims":{"_req":[{"fn_id":"age_check","id":"h"}]}}`

	query, err := NewRawCredentialQuery(json.RawMessage(configured))
	require.NoError(t, err)

	out, err := yamlv2.Marshal(query)
	require.NoError(t, err)
	assert.Contains(t, string(out), "_req", "the member that made this raw has to be in the output")

	var reloaded CredentialQuery
	require.NoError(t, yamlv2.Unmarshal(out, &reloaded),
		"a query this type just wrote must load; refusing to would be a repair by other means")
	require.NotNil(t, reloaded.Raw, "and it is still the shape the typed model cannot hold")

	// And what reaches the wallet is what was configured.
	encoded, err := json.Marshal(reloaded)
	require.NoError(t, err)
	assert.JSONEq(t, configured, string(encoded))

	// The shadow comes back too, so the response path can still match it.
	assert.Equal(t, "q", reloaded.ID)
	assert.Equal(t, FormatCircuitZk, reloaded.Format)
	assert.Equal(t, "d", reloaded.Meta.DoctypeValue)
}

// A number the YAML writer cannot reproduce is refused rather than
// rounded, on the raw path as on the typed one.
func TestRawYAMLRefusesANumberItWouldChange(t *testing.T) {
	query, err := NewRawCredentialQuery(json.RawMessage(
		`{"id":"q","format":"circuit_zk","claims":{"_req":[]},"req":[{"params":{"p":123456789012345678901234567890}}]}`))
	require.NoError(t, err)

	_, err = yamlv2.Marshal(query)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "without changing it")
}

// The laundering guard applies on this path too: a member of the right
// kind that the model rejects is an invalid query, not an unmodelled one,
// and must not become raw just because it arrived as YAML.
func TestYAMLDoesNotLaunderInvalidModelledMembers(t *testing.T) {
	const in = "id: q\nformat: dc+sd-jwt\nmeta:\n  vct_values: [urn:x]\nclaims:\n  - path: []\n"
	var query CredentialQuery
	require.Error(t, yamlv2.Unmarshal([]byte(in), &query),
		"an empty claim path is refused by the model, and YAML is not a way around that")
}

// The extension bag needs the lexeme-preserving decode as much as params
// does - more so, since the shapes it exists for are the ones a newer
// rulebook defines and this build does not understand. Preserving params
// and rounding these would be a distinction with no basis.
func TestExtensionMembersKeepTheConfiguredDigits(t *testing.T) {
	for _, tc := range []struct{ name, in, wantLiteral string }{
		{
			name:        "an unknown member of a req item",
			in:          "id: f\nreturn: h\nfuture: 1.00000000000000001\n",
			wantLiteral: "1.00000000000000001",
		},
		{
			name:        "nested inside an unknown member",
			in:          "id: f\nreturn: h\nfuture:\n  inner: 1.00000000000000001\n",
			wantLiteral: "1.00000000000000001",
		},
		{
			name:        "and in a sequence under one",
			in:          "id: f\nreturn: h\nfuture:\n  - 1.00000000000000001\n",
			wantLiteral: "[1.00000000000000001]",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var item ReqItem
			require.NoError(t, yamlv2.Unmarshal([]byte(tc.in), &item))
			encoded, err := json.Marshal(item)
			require.NoError(t, err)
			assert.Contains(t, string(encoded), tc.wantLiteral,
				"an extension member is a proof input too; a float64's rendering is not what was configured")
		})
	}
}

// And the refusals reach it, rather than being swallowed as "not a
// mapping" the way a structural mismatch rightly is.
func TestExtensionMembersRefuseUnrepresentableScalars(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"an overflowing literal", "id: f\nreturn: h\nfuture: 1e400\n", "cannot tell"},
		{"infinity", "id: f\nreturn: h\nfuture: .inf\n", "no JSON spelling"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var item ReqItem
			err := yamlv2.Unmarshal([]byte(tc.in), &item)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

// An operator configures the negative requests this verifier exists to
// send, so a TEMPLATE has to be able to express them. The typed decode
// turns them into zero values and re-emits something else: req: [] is
// dropped by omitempty, an item with no id comes back carrying one, a
// null param disappears.
//
// Checked on shape rather than value - see jsonShapeEquivalent - so
// yaml.v2's scalar coercion, which is this repository's settled policy,
// is not mistaken for loss.
func TestTemplatesCanExpressTheNegativeShapes(t *testing.T) {
	for _, tc := range []struct {
		name, in, wantJSON string
	}{
		{
			name:     "an empty req array",
			in:       "id: q\nformat: circuit_zk\nmeta:\n  doctype_value: d\nreq: []\n",
			wantJSON: `{"id":"q","format":"circuit_zk","meta":{"doctype_value":"d"},"req":[]}`,
		},
		{
			name:     "an item with no id",
			in:       "id: q\nformat: circuit_zk\nmeta:\n  doctype_value: d\nreq:\n  - return: h\n",
			wantJSON: `{"id":"q","format":"circuit_zk","meta":{"doctype_value":"d"},"req":[{"return":"h"}]}`,
		},
		{
			name:     "an item with no return",
			in:       "id: q\nformat: circuit_zk\nmeta:\n  doctype_value: d\nreq:\n  - id: age_check\n",
			wantJSON: `{"id":"q","format":"circuit_zk","meta":{"doctype_value":"d"},"req":[{"id":"age_check"}]}`,
		},
		{
			name:     "a null params",
			in:       "id: q\nformat: circuit_zk\nmeta:\n  doctype_value: d\nreq:\n  - id: f\n    return: h\n    params: null\n",
			wantJSON: `{"id":"q","format":"circuit_zk","meta":{"doctype_value":"d"},"req":[{"id":"f","return":"h","params":null}]}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var query CredentialQuery
			require.NoError(t, yamlv2.Unmarshal([]byte(tc.in), &query))

			encoded, err := json.Marshal(query)
			require.NoError(t, err)
			assert.JSONEq(t, tc.wantJSON, string(encoded),
				"a template has to send what it says, including the shapes a typed model cannot hold")
		})
	}
}

// And the coercion policy survives: a scalar of the wrong type is still
// coerced by yaml.v2 exactly as it is everywhere else in this
// repository's configuration, rather than being treated as loss and
// pushed down the raw path.
func TestScalarCoercionIsNotMistakenForLoss(t *testing.T) {
	const in = "id: q\nformat: circuit_zk\nmeta:\n  doctype_value: d\nreq:\n  - id: 7\n    return: h\n"
	var query CredentialQuery
	require.NoError(t, yamlv2.Unmarshal([]byte(in), &query))

	assert.Nil(t, query.Raw, "coercion is this repository's policy, not a shape the model cannot hold")
	require.Len(t, query.Req, 1)
	assert.Equal(t, "7", query.Req[0].ID, "coerced, as every other configuration struct here coerces")
}

// An ordinary template is unaffected: it must still decode typed, or the
// distinction stops meaning anything.
func TestOrdinaryTemplatesStayTyped(t *testing.T) {
	const in = "id: q\nformat: circuit_zk\nmeta:\n  doctype_value: d\nreq:\n  - id: pseudonym-v1-sha256\n    return: nym-1\n    params:\n      config: known-offender-matching-ssc\n"
	var query CredentialQuery
	require.NoError(t, yamlv2.Unmarshal([]byte(in), &query))
	assert.Nil(t, query.Raw)
	require.Len(t, query.Req, 1)
	assert.Equal(t, FunctionPseudonym, query.Req[0].ID)
}

// age_check takes full-dates, and a full-date is exactly what YAML has a
// native type for - so an unquoted `ge: 2008-10-10` is both the most
// natural way to write the rulebook's central input and the one most at
// risk of arriving as something else.
//
// It reaches the wire as the string it was written as. On yaml.v2 that is
// the library's own doing: it sets a timestamp-resolved scalar as a
// string when the destination is an interface, deliberately and for
// backward compatibility. That is also why this test is here rather than
// taken on trust - the same source marks the behaviour "TODO(v3) Drop
// this", so it is someone else's compatibility promise, not ours.
func TestUnquotedFullDatesReachTheWireUnchanged(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{
			name: "the rulebook's own age_check range, unquoted",
			in:   "id: age_check\nreturn: age-1\nparams:\n  ge: 2008-10-10\n  le: 2013-10-09\n",
			want: `{"id":"age_check","return":"age-1","params":{"ge":"2008-10-10","le":"2013-10-09"}}`,
		},
		{
			name: "and quoted, which must come out the same",
			in:   "id: age_check\nreturn: age-1\nparams:\n  ge: \"2008-10-10\"\n  le: \"2013-10-09\"\n",
			want: `{"id":"age_check","return":"age-1","params":{"ge":"2008-10-10","le":"2013-10-09"}}`,
		},
		{
			name: "a full timestamp, likewise untouched",
			in:   "id: age_check\nreturn: age-1\nparams:\n  ge: 2008-10-10T00:00:00Z\n",
			want: `{"id":"age_check","return":"age-1","params":{"ge":"2008-10-10T00:00:00Z"}}`,
		},
		{
			name: "a date nested under an unknown member",
			in:   "id: age_check\nreturn: age-1\nfuture:\n  ge: 2008-10-10\n",
			want: `{"id":"age_check","return":"age-1","future":{"ge":"2008-10-10"}}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var item ReqItem
			require.NoError(t, yamlv2.Unmarshal([]byte(tc.in), &item))
			encoded, err := json.Marshal(item)
			require.NoError(t, err)
			// want pins it exactly, which is the point: a bare date that
			// had become an RFC 3339 timestamp would fail here, and the
			// matcher would reject such a value as not a full-date.
			assert.JSONEq(t, tc.want, string(encoded))
		})
	}
}

// The time.Time arm of yamlValue cannot be reached through yaml.v2: that
// library sets a timestamp-resolved scalar as a string when the
// destination is an interface, deliberately, with "TODO(v3) Drop this"
// beside it. So the arm is exercised directly rather than left as code no
// test can reach - it exists for the day that TODO is acted on, and the
// cost of being wrong then is the rulebook's central input silently
// becoming a value the matcher rejects.
func TestYAMLValueRecoversALexemeFromATimestamp(t *testing.T) {
	when, err := time.Parse(time.DateOnly, "2008-10-10")
	require.NoError(t, err)

	// Stands in for a library that resolves a full-date to a time.Time:
	// an interface target gets the time, a string target gets the lexeme,
	// which is what yaml.v2 itself does for every other scalar.
	unmarshal := func(into any) error {
		switch target := into.(type) {
		case *any:
			*target = when
			return nil
		case *string:
			*target = "2008-10-10"
			return nil
		}
		return fmt.Errorf("unexpected target %T", into)
	}

	var value yamlValue
	require.NoError(t, value.UnmarshalYAML(unmarshal))
	assert.Equal(t, "2008-10-10", value.value,
		"a full-date must survive as the full-date it was written as, not as an RFC 3339 timestamp")

	// And the shape that would have gone out without it.
	encoded, err := json.Marshal(when)
	require.NoError(t, err)
	assert.Equal(t, `"2008-10-10T00:00:00Z"`, string(encoded),
		"which is what a time.Time encodes as, and what the matcher rejects as not a full-date")
}

// The number check walked only any-valued containers, so a TYPED one -
// map[string]json.Number, []json.Number - was skipped entirely and
// yaml.v2 rounded what was inside it with nothing said.
//
// CredentialQuery.MarshalYAML happened to be safe, because it bridges
// through JSON before the check runs. ReqItem.MarshalYAML builds its map
// directly and was not - so this goes through ReqItem, which is the
// caller that was actually broken, and through CredentialQuery, which
// must stay safe for a better reason than luck.
func TestTypedContainersDoNotHideANumberYAMLWouldRound(t *testing.T) {
	const unrepresentable = "1.00000000000000001"

	for _, tc := range []struct {
		name    string
		params  map[string]any
		refused bool
	}{
		{"a typed map", map[string]any{"nested": map[string]json.Number{"p": unrepresentable}}, true},
		{"a typed slice", map[string]any{"list": []json.Number{unrepresentable}}, true},
		{"a typed map nested in a typed slice", map[string]any{
			"list": []map[string]json.Number{{"p": unrepresentable}},
		}, true},
		// Representable, so it passes - the walk descends typed
		// containers rather than refusing them on sight.
		{"a typed map of representable numbers", map[string]any{"nested": map[string]float64{"p": 1.5}}, false},
		{"and a typed map of strings", map[string]any{"nested": map[string]string{"p": unrepresentable}}, false},
		{"the any-valued form, which was already caught", map[string]any{
			"nested": map[string]any{"p": json.Number(unrepresentable)},
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			item := ReqItem{ID: "f", Return: "h", Params: tc.params}
			_, err := yamlv2.Marshal(item)
			if !tc.refused {
				require.NoError(t, err)
				return
			}
			require.Error(t, err, "a proof input YAML would round must be refused wherever it is nested")
			assert.Contains(t, err.Error(), "without changing it")
		})
	}

	// And through the whole query, which normalises on its own account.
	query := CredentialQuery{ID: "q", Format: FormatCircuitZk, Req: []ReqItem{{
		ID: "f", Return: "h",
		Params: map[string]any{"nested": map[string]json.Number{"p": unrepresentable}},
	}}}
	_, err := yamlv2.Marshal(query)
	require.Error(t, err)
}

// A duplicate member has no YAML representation that keeps both.
//
// The raw YAML path decodes the bytes to a tree, which collapses them to
// the last value - so writing the configuration back out would emit a
// different request, and the whole reason such a query is carried raw is
// that it must not change. Refused rather than quietly reduced.
func TestYAMLRefusesARawQueryWithDuplicateMembers(t *testing.T) {
	// Not a constraint member - those are refused outright now - but one
	// the model still carries raw.
	const in = `{"id":"first","id":"last","format":"circuit_zk","meta":{"doctype_value":"d"}}`

	query, err := NewRawCredentialQuery(json.RawMessage(in))
	require.NoError(t, err, "this is a request a verifier may legitimately send")

	_, err = yamlv2.Marshal(query)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "more than once")

	// And the JSON path still carries it, which is the point of the
	// refusal being narrow: only YAML cannot say this.
	encoded, err := json.Marshal(query)
	require.NoError(t, err)
	assert.Equal(t, in, string(encoded))
}

// An EMPTY constraint list is a filter that nothing matches; an ABSENT
// one is no filter at all. The matcher's contract distinguishes them, so
// this serialisation has to.
//
// omitempty could not: an explicit {"circuit_id_values": []} became {},
// and the wallet saw an unfiltered request where the operator had asked
// for one that matches nothing. omitzero omits only nil.
//
// Both encodings, because they reach the distinction by different means -
// JSON through the struct tag, YAML through MarshalYAML's own != nil
// test - and a fix to one would not have fixed the other.
func TestCircuitZkFormatKeepsEmptyApartFromAbsent(t *testing.T) {
	for _, tc := range []struct {
		name     string
		format   CircuitZkFormat
		wantJSON string
		wantYAML string
	}{
		{
			name:     "absent",
			format:   CircuitZkFormat{},
			wantJSON: `{}`,
			wantYAML: "{}\n",
		},
		{
			name:     "empty, which matches nothing",
			format:   CircuitZkFormat{CircuitIDValues: []string{}, CircuitProofSystemValues: []string{}},
			wantJSON: `{"circuit_proof_system_values":[],"circuit_id_values":[]}`,
			wantYAML: "circuit_id_values: []\ncircuit_proof_system_values: []\n",
		},
		{
			name:     "one empty and one absent",
			format:   CircuitZkFormat{CircuitIDValues: []string{}},
			wantJSON: `{"circuit_id_values":[]}`,
			wantYAML: "circuit_id_values: []\n",
		},
		{
			name:     "populated",
			format:   CircuitZkFormat{CircuitIDValues: []string{"urn:x"}},
			wantJSON: `{"circuit_id_values":["urn:x"]}`,
			wantYAML: "circuit_id_values:\n- urn:x\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := json.Marshal(tc.format)
			require.NoError(t, err)
			assert.Equal(t, tc.wantJSON, string(encoded))

			asYAML, err := yamlv2.Marshal(tc.format)
			require.NoError(t, err)
			assert.Equal(t, tc.wantYAML, string(asYAML))

			// And back: the distinction has to survive a round trip, not
			// just the encode. A decode that turned [] into nil would
			// lose the constraint one step later.
			var backJSON CircuitZkFormat
			require.NoError(t, json.Unmarshal(encoded, &backJSON))
			assert.Equal(t, tc.format.CircuitIDValues == nil, backJSON.CircuitIDValues == nil,
				"nil-ness of circuit_id_values must survive JSON")
			assert.Equal(t, len(tc.format.CircuitIDValues), len(backJSON.CircuitIDValues))

			var backYAML CircuitZkFormat
			require.NoError(t, yamlv2.Unmarshal(asYAML, &backYAML))
			assert.Equal(t, tc.format.CircuitIDValues == nil, backYAML.CircuitIDValues == nil,
				"nil-ness of circuit_id_values must survive YAML")
			assert.Equal(t, len(tc.format.CircuitIDValues), len(backYAML.CircuitIDValues))
		})
	}
}

// The YAML routes to Raw need the same guard as the JSON ones.
//
// A template is as capable of naming a constraint twice, or in the wrong
// case, as a JSON request is - and a configuration is the MORE likely
// place for a typo, because nobody runs a JSON schema over it first.
// Checking only the JSON paths left the whole of this open: a template
// with a case-aliased constraint reaches Raw through the
// shape-equivalence fallback, not the decode-failure one.
//
// Checked on the NORMALISED bytes, which is what gets emitted and what a
// wallet reads.
func TestYAMLRawPathIsNotAWayPastTheConstraintChecks(t *testing.T) {
	for _, tc := range []struct{ name, template, want string }{
		{
			name:     "a case-aliased constraint inside meta",
			template: "id: q\nformat: dc+sd-jwt\nmeta:\n  VCT_VALUES: [urn:x]\n",
			want:     "differs only in case",
		},
		{
			name:     "a case-aliased meta itself",
			template: "id: q\nformat: dc+sd-jwt\nMETA:\n  vct_values: [urn:x]\n",
			want:     "differs only in case",
		},
		{
			name:     "a case-aliased doctype_value",
			template: "id: q\nformat: mso_mdoc\nmeta:\n  DocType_Value: org.iso.18013.5.1.mDL\n",
			want:     "differs only in case",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var q CredentialQuery
			err := yamlv2.Unmarshal([]byte(tc.template), &q)
			require.Error(t, err, "this template must not be readable; it decoded to %#v", q)
			assert.Contains(t, err.Error(), tc.want)
		})
	}

	// And an ordinary template still reads, with its constraint intact -
	// the guard refuses aliases, not YAML.
	var ok CredentialQuery
	require.NoError(t, yamlv2.Unmarshal([]byte("id: q\nformat: dc+sd-jwt\nmeta:\n  vct_values: [urn:x]\n"), &ok))
	assert.Equal(t, []string{"urn:x"}, ok.Meta.VCTValues)
}

// An extension bag that cannot be read is an error, not an empty bag.
//
// yamlExtra decodes the node a second time to collect members the typed
// model does not know. A structural fault the typed decode IGNORES - a
// sequence used as a map key under an unknown member - makes that second
// decode fail, and the failure used to be swallowed: the whole bag was
// discarded, valid siblings and all, with no error. A metadata block
// carrying fn_id, input and one malformed sibling loaded with NO
// extensions, silently, and the verifier sent different metadata than
// the operator had configured.
func TestYAMLExtensionsAreNotDiscardedOnADecodeError(t *testing.T) {
	// The precondition: these siblings really are collected when nothing
	// else is wrong, so the assertion below is about the error and not
	// about a bag that was always empty.
	var ok CircuitZkFormat
	require.NoError(t, yamlv2.Unmarshal([]byte("fn_id: circuit_zk_longfellow\ninput: abc\n"), &ok))
	require.Len(t, ok.Extra, 2)

	var broken CircuitZkFormat
	err := yamlv2.Unmarshal([]byte(
		"fn_id: circuit_zk_longfellow\ninput: abc\nfuture:\n  ? [a, b]\n  : pair\n"), &broken)
	require.Error(t, err, "the extensions could not be read, so this must not look like success")
	assert.Contains(t, err.Error(), "circuit_zk client metadata")
	assert.Empty(t, broken.Extra,
		"and nothing half-read is kept; the caller gets the error, not a partial bag")
}
