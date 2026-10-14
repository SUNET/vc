package openid4vp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const vectorDir = "testdata/circuit_zk"

// vector is one shared conformance case. Only the parts this package is
// answerable for are decoded - the planner's expected output is the
// matcher's business, not ours.
type vector struct {
	Description       string          `json:"description"`
	Query             json.RawMessage `json:"query"`
	QueryText         *string         `json:"query_text"`
	ClientMetadata    json.RawMessage `json:"client_metadata"`
	ClientMetadataTxt *string         `json:"client_metadata_text"`
}

func loadVectors(t *testing.T) map[string]vector {
	t.Helper()
	entries, err := os.ReadDir(vectorDir)
	require.NoError(t, err)

	out := map[string]vector{}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(vectorDir, filepath.Clean(name)))
		require.NoError(t, err)
		var v vector
		require.NoError(t, json.Unmarshal(raw, &v), "%s", name)
		out[name] = v
	}
	require.NotEmpty(t, out, "no vectors found; the vendored set is the whole point of this file")
	return out
}

// Every vector's credential query must be emittable, byte for byte.
//
// This is the conformance that matters for a REQUEST builder. The planner
// vectors describe what a wallet must accept, so a query we cannot
// reproduce exactly is a query we cannot send - including the shapes this
// build does not model, which is most of the point: the rulebook's WIP
// claims._req form, members whose type a later generation changed, and
// unknown members at every level.
//
// Two routes, and the test records which each vector took. A shape the
// typed model understands round-trips through it; anything else goes
// through Raw. A vector that needs neither would be a shape this verifier
// could not produce at all.
func TestEveryVectorQueryCanBeEmitted(t *testing.T) {
	typed, raw := 0, 0

	for name, v := range loadVectors(t) {
		if v.Query == nil {
			continue // query_text cases are deliberately unparseable
		}
		t.Run(name, func(t *testing.T) {
			var query CredentialQuery
			if err := json.Unmarshal(v.Query, &query); err == nil {
				encoded, marshalErr := json.Marshal(query)
				require.NoError(t, marshalErr)
				if sameJSON(t, v.Query, encoded) {
					typed++
					return
				}
				// Decoded but did not survive re-encoding. Raw is the
				// escape hatch for that too, but say so rather than
				// letting it pass quietly as if the model had handled it.
				t.Logf("%s: the typed model decodes this but does not reproduce it; Raw carries it\n  vector: %s\n  typed:  %s",
					v.Description, v.Query, encoded)
			}

			encoded, err := json.Marshal(CredentialQuery{Raw: v.Query})
			require.NoError(t, err)
			assert.True(t, sameJSON(t, v.Query, encoded),
				"%s: neither the typed model nor Raw can emit this\n  vector: %s\n  ours:   %s",
				v.Description, v.Query, encoded)
			raw++
		})
	}

	t.Logf("emitted through the typed model: %d, through Raw: %d", typed, raw)
	assert.Positive(t, typed, "no vector went through the typed model; it is not modelling anything")
}

// Every shape a wallet must ACCEPT, the typed model must produce - with
// one named exception.
//
// Without this, the previous test would still pass if the model stopped
// understanding the normative shape entirely: everything would quietly
// fall through to Raw and the count assertion would not notice. This is
// the guard that says which shapes we model rather than merely transmit.
func TestTheModelProducesEveryAcceptedShape(t *testing.T) {
	// The rulebook's WIP example puts an object at "claims", where DCQL
	// has an array. The issue says this verifier emits the normative req
	// form, so the shape is reachable through Raw and deliberately not
	// modelled. If that changes, this list is where it changes.
	rawOnly := map[string]string{
		"ok_example_envelope.json": "claims is an object in the rulebook's WIP example",
	}

	for name, v := range loadVectors(t) {
		if v.Query == nil || !strings.HasPrefix(name, "ok_") {
			continue
		}
		t.Run(name, func(t *testing.T) {
			var query CredentialQuery
			err := json.Unmarshal(v.Query, &query)
			if err == nil {
				encoded, marshalErr := json.Marshal(query)
				require.NoError(t, marshalErr)
				if sameJSON(t, v.Query, encoded) {
					assert.NotContains(t, rawOnly, name,
						"this is listed as raw-only but the model handles it; remove the entry")
					return
				}
			}
			why, expected := rawOnly[name]
			require.True(t, expected,
				"%s\nthe typed model cannot reproduce a shape wallets accept. Either model it, "+
					"or add it to rawOnly with the reason.\n  vector: %s", v.Description, v.Query)
			t.Logf("raw-only, as recorded: %s", why)
		})
	}
}

// What a Go struct cannot say, named so it is a boundary rather than a
// surprise.
//
// A string field cannot distinguish an absent member from an empty one,
// and a slice with omitempty cannot distinguish an absent array from an
// empty one. So four shapes in the shared set cannot be emitted through
// the typed model: an item with no "id" or no "return", a query with no
// "meta", and a query whose "req" is []. All four are rejected by every
// planner anyway - they are fixtures for wallet behaviour, not requests a
// verifier has a reason to send - and Raw emits them exactly when one is
// wanted.
//
// Making the fields pointers would move the limitation rather than remove
// it: an empty-string handle would then be the shape that needs Raw.
func TestAbsentAndEmptyAreNotDistinguishedInTheTypedModel(t *testing.T) {
	for _, tc := range []struct{ name, in string }{
		{"an item with no id", `{"id":"q","format":"circuit_zk","meta":{},"req":[{"return":"h"}]}`},
		{"an item with no return", `{"id":"q","format":"circuit_zk","meta":{},"req":[{"id":"age_check"}]}`},
		{"an empty req array", `{"id":"q","format":"circuit_zk","meta":{},"req":[]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var query CredentialQuery
			require.NoError(t, json.Unmarshal([]byte(tc.in), &query))
			encoded, err := json.Marshal(query)
			require.NoError(t, err)
			assert.False(t, sameJSON(t, []byte(tc.in), encoded),
				"if this now round-trips, the model gained a distinction it did not have "+
					"and this boundary can be deleted")

			// And Raw emits it exactly.
			viaRaw, err := json.Marshal(CredentialQuery{Raw: json.RawMessage(tc.in)})
			require.NoError(t, err)
			assert.True(t, sameJSON(t, []byte(tc.in), viaRaw))
		})
	}
}

// Raw replaces the query entirely, and may not be combined with Extra.
func TestRawReplacesTheQuery(t *testing.T) {
	encoded, err := json.Marshal(CredentialQuery{
		ID: "ignored", Format: "ignored",
		Raw: json.RawMessage(`{"anything":[1,2,3]}`),
	})
	require.NoError(t, err)
	assert.JSONEq(t, `{"anything":[1,2,3]}`, string(encoded))

	_, err = json.Marshal(CredentialQuery{
		Raw:   json.RawMessage(`{"a":1}`),
		Extra: map[string]any{"b": 2},
	})
	require.Error(t, err, "raw would discard extra, so setting both is a configuration mistake")

	_, err = json.Marshal(CredentialQuery{Raw: json.RawMessage(`{not json`)})
	require.Error(t, err, "invalid JSON must not reach the wire inside a request object")
}

// And every vector's client_metadata, for the same reason: the circuit
// filter lives there, in two shapes the matcher accepts.
func TestEveryVectorClientMetadataRoundTrips(t *testing.T) {
	for name, v := range loadVectors(t) {
		if v.ClientMetadata == nil {
			continue
		}
		var probe struct {
			VPFormats json.RawMessage `json:"vp_formats_supported"`
		}
		if err := json.Unmarshal(v.ClientMetadata, &probe); err != nil || probe.VPFormats == nil {
			continue // err_client_metadata_* cases with a non-object there
		}
		t.Run(name, func(t *testing.T) {
			var formats VPFormatsSupported
			if err := json.Unmarshal(probe.VPFormats, &formats); err != nil {
				t.Skipf("%s: vp_formats_supported is not an object of entries", v.Description)
			}
			encoded, err := json.Marshal(formats)
			require.NoError(t, err)
			assert.True(t, sameJSON(t, probe.VPFormats, encoded),
				"%s\n  vector: %s\n  ours:   %s", v.Description, probe.VPFormats, encoded)
		})
	}
}

// The two shapes named in the issue, spelled out rather than left to the
// vector loop: the normative req form this verifier emits, and the WIP
// envelope form it must still be able to produce for a wallet that wants
// one.
func TestTheTwoShapesTheIssueNames(t *testing.T) {
	t.Run("normative req", func(t *testing.T) {
		query := CredentialQuery{
			ID:     "nym_attestation",
			Format: FormatCircuitZk,
			Meta:   MetaQuery{DoctypeValue: "eu.europa.ec.eudi.nym_auth.1"},
			Req: []ReqItem{
				{ID: FunctionPseudonym, Return: "nym-123", Params: map[string]any{
					"config": "known-offender-matching-ssc", "verifier_id_type": "x509_san_dns",
				}},
				{ID: FunctionAgeCheck, Return: "age-range-123", Params: map[string]any{
					"ge": "2008-10-10", "le": "2013-10-09",
				}},
			},
		}
		encoded, err := json.Marshal(query)
		require.NoError(t, err)

		raw, err := os.ReadFile(filepath.Join(vectorDir, "ok_normative_plain.json"))
		require.NoError(t, err)
		var v vector
		require.NoError(t, json.Unmarshal(raw, &v))

		assert.True(t, sameJSON(t, v.Query, encoded),
			"the builder must produce the rulebook's normative example\n  vector: %s\n  ours:   %s", v.Query, encoded)
	})

	t.Run("the envelope form, through Extra", func(t *testing.T) {
		formats := VPFormatsSupported{CircuitZk: &CircuitZkFormat{Extra: map[string]any{
			"fn_id": "circuit_zk_longfellow",
			"input": "eyJjaXJjdWl0X3Byb29mX3N5c3RlbV92YWx1ZXMiOiBbImxvbmdmZWxsb3ctbGliemstdjEiXSwgImNpcmN1aXRfaWRfdmFsdWVzIjogWyJ1cm46Y2lyY3VpdHM6bG9uZ2ZlbGxvdzpueW1fYXV0aDp2MSJdfQ==",
		}}}
		encoded, err := json.Marshal(formats)
		require.NoError(t, err)
		assert.JSONEq(t,
			`{"circuit_zk":{"fn_id":"circuit_zk_longfellow","input":"eyJjaXJjdWl0X3Byb29mX3N5c3RlbV92YWx1ZXMiOiBbImxvbmdmZWxsb3ctbGliemstdjEiXSwgImNpcmN1aXRfaWRfdmFsdWVzIjogWyJ1cm46Y2lyY3VpdHM6bG9uZ2ZlbGxvdzpueW1fYXV0aDp2MSJdfQ=="}}`,
			string(encoded),
			"an operator must be able to send a shape this build does not model")
	})
}

// A request this build considers wrong must go out exactly as configured.
//
// The verifier is the tool wallets are tested WITH, so the builder is a
// serialiser and not a validator: no repair, no dropping, no reordering
// that changes meaning. Every case here violates something the nym_auth
// rulebook requires.
func TestBadRequestsAreEmittedUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name  string
		query CredentialQuery
		want  string
	}{
		{
			name: "le before ge, and a span under 365 days",
			query: CredentialQuery{ID: "q", Format: FormatCircuitZk, Meta: MetaQuery{DoctypeValue: "d"},
				Req: []ReqItem{{ID: FunctionAgeCheck, Return: "a", Params: map[string]any{"ge": "2013-10-09", "le": "2008-10-10"}}}},
			want: `{"id":"q","format":"circuit_zk","meta":{"doctype_value":"d"},"req":[{"id":"age_check","return":"a","params":{"ge":"2013-10-09","le":"2008-10-10"}}]}`,
		},
		{
			name: "two pseudonym items, which the rulebook forbids",
			query: CredentialQuery{ID: "q", Format: FormatCircuitZk, Meta: MetaQuery{DoctypeValue: "d"},
				Req: []ReqItem{
					{ID: FunctionPseudonym, Return: "p1"},
					{ID: FunctionPseudonym, Return: "p2"},
				}},
			want: `{"id":"q","format":"circuit_zk","meta":{"doctype_value":"d"},"req":[{"id":"pseudonym-v1-sha256","return":"p1"},{"id":"pseudonym-v1-sha256","return":"p2"}]}`,
		},
		{
			name: "a duplicate handle",
			query: CredentialQuery{ID: "q", Format: FormatCircuitZk, Meta: MetaQuery{DoctypeValue: "d"},
				Req: []ReqItem{{ID: FunctionAgeCheck, Return: "same"}, {ID: FunctionPseudonym, Return: "same"}}},
			want: `{"id":"q","format":"circuit_zk","meta":{"doctype_value":"d"},"req":[{"id":"age_check","return":"same"},{"id":"pseudonym-v1-sha256","return":"same"}]}`,
		},
		{
			name: "an unknown function",
			query: CredentialQuery{ID: "q", Format: FormatCircuitZk, Meta: MetaQuery{DoctypeValue: "d"},
				Req: []ReqItem{{ID: "no-such-function-v9", Return: "h", Params: map[string]any{"whatever": 1}}}},
			want: `{"id":"q","format":"circuit_zk","meta":{"doctype_value":"d"},"req":[{"id":"no-such-function-v9","return":"h","params":{"whatever":1}}]}`,
		},
		{
			name: "no verifier_id_type, and a verifier_context past 64 bytes",
			query: CredentialQuery{ID: "q", Format: FormatCircuitZk, Meta: MetaQuery{DoctypeValue: "d"},
				Req: []ReqItem{{ID: FunctionPseudonym, Return: "p", Params: map[string]any{
					"config": "known-offender-matching-ssc", "verifier_context": strings.Repeat("c", 65),
				}}}},
			want: `{"id":"q","format":"circuit_zk","meta":{"doctype_value":"d"},"req":[{"id":"pseudonym-v1-sha256","return":"p","params":{"config":"known-offender-matching-ssc","verifier_context":"` + strings.Repeat("c", 65) + `"}}]}`,
		},
		{
			name: "an empty req, and an empty handle",
			query: CredentialQuery{ID: "q", Format: FormatCircuitZk, Meta: MetaQuery{DoctypeValue: "d"},
				Req: []ReqItem{{ID: FunctionAgeCheck, Return: ""}}},
			want: `{"id":"q","format":"circuit_zk","meta":{"doctype_value":"d"},"req":[{"id":"age_check","return":""}]}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := json.Marshal(tc.query)
			require.NoError(t, err, "a bad request must still serialise; refusing here would make negative tests impossible")
			assert.JSONEq(t, tc.want, string(encoded))
		})
	}
}

// Extra may not supply a member the struct models, whether or not that
// member's field happens to be set.
//
// Checking the ENCODED output would only catch the collision when the
// typed field survived omitempty - so an empty one would let Extra take
// over the member silently, and only sometimes. Changing a modelled
// member's type is what Raw is for.
func TestExtraCannotSupplyAModelledMember(t *testing.T) {
	for _, tc := range []struct {
		name string
		do   func() ([]byte, error)
	}{
		{"req item, field set", func() ([]byte, error) {
			return json.Marshal(ReqItem{ID: "f", Return: "h", Extra: map[string]any{"id": "other"}})
		}},
		{"req item, field EMPTY", func() ([]byte, error) {
			return json.Marshal(ReqItem{Return: "h", Extra: map[string]any{"params": "not an object"}})
		}},
		{"credential query, field set", func() ([]byte, error) {
			return json.Marshal(CredentialQuery{ID: "q", Format: FormatCircuitZk, Extra: map[string]any{"format": "other"}})
		}},
		{"credential query, field EMPTY", func() ([]byte, error) {
			return json.Marshal(CredentialQuery{ID: "q", Format: FormatCircuitZk, Extra: map[string]any{"req": "not an array"}})
		}},
		{"circuit metadata, field set", func() ([]byte, error) {
			return json.Marshal(CircuitZkFormat{CircuitIDValues: []string{"a"}, Extra: map[string]any{"circuit_id_values": []string{"b"}}})
		}},
		{"circuit metadata, field EMPTY", func() ([]byte, error) {
			return json.Marshal(CircuitZkFormat{Extra: map[string]any{"circuit_id_values": "x"}})
		}},
		{"vp_formats_supported, field EMPTY", func() ([]byte, error) {
			return json.Marshal(VPFormatsSupported{Extra: map[string]any{"circuit_zk": "x"}})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.do()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "a member this type models")
		})
	}

	// A member the type does not model still goes through, which is the
	// whole purpose of Extra.
	encoded, err := json.Marshal(ReqItem{ID: "f", Return: "h", Extra: map[string]any{"source": map[string]any{"path": []string{"ssc"}}}})
	require.NoError(t, err)
	assert.JSONEq(t, `{"id":"f","return":"h","source":{"path":["ssc"]}}`, string(encoded))
}

// A function parameter is passed through unchanged, and "unchanged"
// includes numbers a float64 cannot hold.
//
// Decoding an `any` with plain Unmarshal makes every number a float64, so
// 9007199254740993 comes back out as ...992 - a parameter the verifier
// never configured, inside a request a wallet is being tested against.
func TestParamsPreserveNumbersExactly(t *testing.T) {
	const in = `{"id":"f","return":"h","params":{` +
		`"big":9007199254740993,` +
		`"negative":-9007199254740993,` +
		`"huge":123456789012345678901234567890,` +
		`"precise":0.1234567890123456789,` +
		`"nested":{"also_big":9007199254740993},` +
		`"list":[9007199254740993]}}`

	var item ReqItem
	require.NoError(t, json.Unmarshal([]byte(in), &item))
	encoded, err := json.Marshal(item)
	require.NoError(t, err)
	assert.JSONEq(t, in, string(encoded))
	assert.Contains(t, string(encoded), "9007199254740993", "the exact integer must survive")

	// The same for members this build does not model, which reach the
	// wire through Extra.
	const withExtra = `{"id":"f","return":"h","future":{"n":9007199254740993}}`
	var item2 ReqItem
	require.NoError(t, json.Unmarshal([]byte(withExtra), &item2))
	encoded, err = json.Marshal(item2)
	require.NoError(t, err)
	assert.JSONEq(t, withExtra, string(encoded))

	// And for a whole credential query, since Extra lives there too.
	const query = `{"id":"q","format":"circuit_zk","meta":{},"future":9007199254740993}`
	var q CredentialQuery
	require.NoError(t, json.Unmarshal([]byte(query), &q))
	encoded, err = json.Marshal(q)
	require.NoError(t, err)
	assert.JSONEq(t, query, string(encoded))
}

func TestIsCircuitZkFormat(t *testing.T) {
	assert.True(t, IsCircuitZkFormat(FormatCircuitZk))
	assert.False(t, IsCircuitZkFormat(FormatMsoMdocZk), "circuit_zk is not multipaz's ZK mdoc")
	assert.False(t, IsCircuitZkFormat(FormatMsoMdoc))
	assert.False(t, IsCircuitZkFormat(""))
}

// sameJSON compares two encodings for semantic equality.
func sameJSON(t *testing.T, a, b []byte) bool {
	t.Helper()
	var x, y any
	require.NoError(t, json.Unmarshal(a, &x))
	require.NoError(t, json.Unmarshal(b, &y))
	return reflect.DeepEqual(x, y)
}
