package openid4vp

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	yamlv2 "gopkg.in/yaml.v2"

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

// Every vector's credential query must be emittable with every member
// and value intact.
//
// Not byte for byte, which this never checked and the implementation
// cannot promise: encoding/json compacts and HTML-escapes whatever a
// MarshalJSON returns, so an operator's layout and an ampersand's
// spelling do not survive. What does survive, and what the comparison
// checks, is every member, its nesting, and every value - numeric
// literals included, which is why that comparison decodes with
// UseNumber rather than into a float64.
//
// This is the conformance that matters for a REQUEST builder. The planner
// vectors describe what a wallet must accept, so a query we cannot
// reproduce is a query we cannot send - including the shapes this
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
			// Raw non-nil means the decode fell back rather than
			// modelling the shape - decoding is total now, so "no error"
			// no longer means the model understood it.
			if err := json.Unmarshal(v.Query, &query); err == nil && query.Raw == nil {
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
			if err == nil && query.Raw == nil {
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

// What a Go struct cannot SAY, and what this type nevertheless carries.
//
// A string field cannot distinguish an absent member from an empty one,
// and a slice with omitempty cannot distinguish an absent array from an
// empty one. So four shapes in the shared set have no typed
// representation: an item with no "id" or no "return", a query with no
// "meta", and a query whose "req" is []. Making the fields pointers would
// move that limitation rather than remove it - an empty-string handle
// would then be the shape with nowhere to live.
//
// They survive anyway, because decoding does not ask "did this parse" but
// "does it encode back to what arrived". A shape the typed model would
// change is kept verbatim in Raw instead, so it reaches the wallet as
// configured and survives the HA cache on the way.
//
// Which matters precisely because these are not requests a verifier has a
// reason to send: they are fixtures for wallet behaviour, every planner
// rejects them, and a serialiser that quietly repaired them would make
// the negative tests untestable.
func TestShapesWithNoTypedRepresentationSurviveAnyway(t *testing.T) {
	for _, tc := range []struct{ name, in string }{
		{"an item with no id", `{"id":"q","format":"circuit_zk","meta":{},"req":[{"return":"h"}]}`},
		{"an item with no return", `{"id":"q","format":"circuit_zk","meta":{},"req":[{"id":"age_check"}]}`},
		{"an empty req array", `{"id":"q","format":"circuit_zk","meta":{},"req":[]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var query CredentialQuery
			require.NoError(t, json.Unmarshal([]byte(tc.in), &query))
			require.NotNil(t, query.Raw,
				"the typed form of this shape is not the shape, so it has to be kept verbatim")

			encoded, err := json.Marshal(query)
			require.NoError(t, err)
			assert.True(t, sameJSON(t, []byte(tc.in), encoded),
				"what was configured has to be what is sent")

			// Including across the HA cache, which is the round trip that
			// made this worth fixing rather than documenting.
			stored, err := json.Marshal(&DCQL{Credentials: []CredentialQuery{query}})
			require.NoError(t, err)
			var loaded DCQL
			require.NoError(t, json.Unmarshal(stored, &loaded))
			require.Len(t, loaded.Credentials, 1)
			out, err := json.Marshal(loaded.Credentials[0])
			require.NoError(t, err)
			assert.True(t, sameJSON(t, []byte(tc.in), out))
		})
	}
}

// The counterpart: a shape the typed model DOES represent faithfully must
// not be pushed down the raw path, or the distinction stops meaning
// anything and every query becomes opaque bytes.
func TestFaithfulShapesStayTyped(t *testing.T) {
	for _, in := range []string{
		`{"id":"q","format":"circuit_zk","meta":{"doctype_value":"d"},"req":[{"id":"age_check","return":"h"}]}`,
		`{"id":"q","format":"mso_mdoc","meta":{"doctype_value":"d"}}`,
		`{"id":"q","format":"dc+sd-jwt","meta":{"vct_values":["urn:x"]},"multiple":true}`,
	} {
		var query CredentialQuery
		require.NoError(t, json.Unmarshal([]byte(in), &query))
		assert.Nilf(t, query.Raw, "this shape is modelled exactly and must decode typed: %s", in)
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
					"config": "known-offender-matching-ssc",
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
	return decodeExactly(t, a) == decodeExactly(t, b)
}

// decodeExactly renders a JSON document in a form where two documents
// compare equal only if their VALUES are equal, numbers included.
//
// json.Unmarshal into an any decodes every number as a float64, so a
// comparison built on it reports equality after a value has changed
// precision - 9007199254740993 against 9007199254740992, say. These
// helpers carry the all-vectors conformance test's entire claim that a
// request is emitted unchanged, and a request parameter is an input to a
// proof, so that is the one thing they must not miss.
//
// UseNumber keeps each literal as text; re-encoding then gives a string
// that differs whenever any value does. Member order does not matter,
// because the decoded maps are re-encoded by encoding/json, which sorts
// keys.
func decodeExactly(t *testing.T, data []byte) string {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	require.NoError(t, decoder.Decode(&value))
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	return string(encoded)
}

// The helper the all-vectors conformance test rests on has to see a
// changed number.
//
// json.Unmarshal into an any decodes every number as a float64, so the
// version this replaced reported equality after a value had lost
// precision - and a req param is an input to a proof, so a comparison
// that cannot see that is not checking the thing the test exists for.
func TestSameJSONSeesAChangedNumber(t *testing.T) {
	for _, tc := range []struct {
		name, a, b string
		same       bool
	}{
		{"identical", `{"p":1}`, `{"p":1}`, true},
		{"member order, which is not a difference", `{"a":1,"b":2}`, `{"b":2,"a":1}`, true},
		{"whitespace, likewise", `{"p":1}`, "{ \"p\" : 1 }", true},

		// The pair a float64 cannot tell apart. This is the case the old
		// helper passed.
		{"a value that lost precision", `{"p":9007199254740993}`, `{"p":9007199254740992}`, false},
		{"and a decimal that did", `{"p":1.00000000000000001}`, `{"p":1}`, false},

		{"an added member", `{"p":1}`, `{"p":1,"q":2}`, false},
		{"a dropped array", `{"p":[]}`, `{}`, false},
		{"a number against its string", `{"p":1}`, `{"p":"1"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.same, sameJSON(t, []byte(tc.a), []byte(tc.b)))
		})
	}
}

// A request whose REQ this build cannot model must survive the HA cache.
//
// NewRawCredentialQuery accepts the vendored negative vectors - that is
// the escape hatch working - but reading one back refused it: the outer
// req is an array, so the decode guard classified its item-level failure
// as an ordinary invalid query rather than an unmodelled shape. A request
// object is JSON-encoded into the cache and read by another node, so such
// a request could be published and then reload nowhere but the node that
// built it.
//
// Driven from the vendored vectors rather than hand-written JSON: these
// are the shapes the shared conformance set says a verifier must be able
// to send, so if they change, this changes with them.
func TestMalformedReqSurvivesACacheRoundTrip(t *testing.T) {
	for _, name := range []string{
		"err_item_function_id_not_string.json", // a numeric req-item id
		"err_params_not_object.json",           // array-valued params
	} {
		t.Run(name, func(t *testing.T) {
			query := vectorQuery(t, name)

			built, err := NewRawCredentialQuery(query)
			require.NoError(t, err, "the constructor accepts it; that is the escape hatch")

			// Out to the cache...
			encoded, err := json.Marshal(built)
			require.NoError(t, err)

			// ...and back in on another node.
			var reloaded CredentialQuery
			require.NoError(t, json.Unmarshal(encoded, &reloaded),
				"a request this verifier published must reload")
			require.NotNil(t, reloaded.Raw,
				"a shape the model cannot hold must reload raw, not be repaired into it")

			// And what reloaded is what was sent. A reload that silently
			// normalised the request would pass the assertions above and
			// still change what the wallet receives.
			again, err := json.Marshal(reloaded)
			require.NoError(t, err)
			assert.JSONEq(t, string(encoded), string(again))
		})
	}
}

// And the strict rule still holds everywhere else, which is the half that
// must not be lost.
//
// meta and claims are what the SD-JWT and mdoc validation reads. A decode
// error there laundered into Raw would turn an unreadable constraint into
// a query that validates, because there would be nothing left to judge -
// so these stay refused on the way back in, even though the constructor
// accepts them. The asymmetry is deliberate: sending one is a test of a
// wallet, reloading one as if it were fine is a hole in this verifier.
func TestMalformedConstraintsAreStillRefusedOnReload(t *testing.T) {
	for _, name := range []string{
		"err_meta_doctype_not_string.json",
		"err_meta_vct_values_not_strings.json",
	} {
		t.Run(name, func(t *testing.T) {
			built, err := NewRawCredentialQuery(vectorQuery(t, name))
			require.NoError(t, err)
			encoded, err := json.Marshal(built)
			require.NoError(t, err)

			var reloaded CredentialQuery
			assert.Error(t, json.Unmarshal(encoded, &reloaded),
				"a constraint the validation reads must not be laundered into Raw")
		})
	}
}

// vectorQuery reads the "query" member of a vendored conformance vector.
func vectorQuery(t *testing.T, name string) json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorDir, name))
	require.NoError(t, err)
	var vec struct {
		Query json.RawMessage `json:"query"`
	}
	require.NoError(t, json.Unmarshal(raw, &vec))
	require.True(t, isJSONObject(vec.Query), "%s does not carry an object query", name)
	return vec.Query
}

// A member spelled in a different case is an UNKNOWN member, not the
// modelled one.
//
// encoding/json matches a struct field case-insensitively, so
// "CIRCUIT_ID_VALUES" bound to CircuitIDValues, while the extension half
// matched exactly and kept it as unknown too. Re-encoding wrote both, and
// an extension nobody modelled rewrote a modelled member - an empty
// circuit_id_values, which is a filter matching NOTHING, came back
// permitting the circuit the unknown member named.
func TestCaseAliasedMemberDoesNotRewriteTheModelledOne(t *testing.T) {
	t.Run("circuit_zk client metadata", func(t *testing.T) {
		const in = `{"circuit_id_values":[],"CIRCUIT_ID_VALUES":["urn:unexpected"]}`

		var format CircuitZkFormat
		require.NoError(t, json.Unmarshal([]byte(in), &format))

		// The modelled member keeps what IT was given: present, and
		// empty, which is a filter that matches nothing.
		require.NotNil(t, format.CircuitIDValues, "an explicit [] is a filter, not an absent member")
		assert.Empty(t, format.CircuitIDValues)
		assert.Equal(t, map[string]any{"CIRCUIT_ID_VALUES": []any{"urn:unexpected"}}, format.Extra)

		out, err := json.Marshal(format)
		require.NoError(t, err)

		// Round trips unchanged: the extension survives verbatim and the
		// modelled filter still matches nothing.
		var back CircuitZkFormat
		require.NoError(t, json.Unmarshal(out, &back))
		require.NotNil(t, back.CircuitIDValues)
		assert.Empty(t, back.CircuitIDValues, "re-encoding must not let the extension fill the filter: %s", out)
		assert.Equal(t, format.Extra, back.Extra)
	})

	t.Run("req item", func(t *testing.T) {
		var item ReqItem
		require.NoError(t, json.Unmarshal([]byte(`{"id":"keep","ID":"shadow"}`), &item))
		assert.Equal(t, "keep", item.ID)
		assert.Equal(t, map[string]any{"ID": "shadow"}, item.Extra)
	})

	t.Run("vp_formats_supported", func(t *testing.T) {
		var formats VPFormatsSupported
		require.NoError(t, json.Unmarshal([]byte(`{"MSO_MDOC":{"alg":["ES256"]}}`), &formats))
		assert.Nil(t, formats.MsoMdoc, "a differently cased name must not bind to the modelled entry")
		assert.Contains(t, formats.Extra, "MSO_MDOC")
	})
}

// Copying a query must not REPAIR it.
//
// A raw leaf is bytes, and copyAnyMap re-parsed them, so a payload a
// Verifier wrote to be malformed came back well-formed: {"x":1,"x":2}
// became {"x":2}. The point of such a payload is to see what a wallet does
// with it, so templating the query quietly changed the request under test.
// Member order and a number's spelling went the same way.
//
// Asserted on the EMITTED TEXT, not the parsed tree, because parsing is
// exactly the step that hides the difference.
func TestCopyDCQLPreservesRawLeavesByteForByte(t *testing.T) {
	const duplicate = `{"x":1,"x":2}`
	const spelled = `{"b":1,"a":1.50}` // member order and a long-form number

	src := &DCQL{Credentials: []CredentialQuery{{
		ID:     "q",
		Format: FormatCircuitZk,
		Meta:   MetaQuery{DoctypeValue: "d"},
		Req: []ReqItem{{
			ID:     FunctionAgeCheck,
			Return: "a",
			Params: map[string]any{
				"payload": json.RawMessage(duplicate),
				// A raw leaf inside a slice inside a map.
				"nested": []any{map[string]any{"inner": json.RawMessage(spelled)}},
			},
		}},
	}}}

	dst := copyDCQL(src)
	require.NotNil(t, dst)

	params := dst.Credentials[0].Req[0].Params
	emitted, err := json.Marshal(params["payload"])
	require.NoError(t, err)
	assert.Equal(t, duplicate, string(emitted),
		"a raw leaf must be copied as bytes; re-parsing it drops the duplicate member")

	nested := params["nested"].([]any)[0].(map[string]any)
	nestedEmitted, err := json.Marshal(nested["inner"])
	require.NoError(t, err)
	assert.Equal(t, spelled, string(nestedEmitted),
		"a raw leaf nested inside containers must be copied as bytes too")

	// And it is a COPY: neither direction leaks.
	srcParams := src.Credentials[0].Req[0].Params
	srcNested := srcParams["nested"].([]any)[0].(map[string]any)

	params["payload"] = json.RawMessage(`{"changed":true}`)
	nested["inner"] = json.RawMessage(`{"changed":true}`)
	assert.Equal(t, duplicate, string(srcParams["payload"].(json.RawMessage)),
		"writing to the copy must not reach the original")
	assert.Equal(t, spelled, string(srcNested["inner"].(json.RawMessage)),
		"the nested container must not be shared with the original")

	srcNested["inner"] = json.RawMessage(`{"other":true}`)
	assert.Equal(t, `{"changed":true}`, string(nested["inner"].(json.RawMessage)),
		"writing to the original must not reach the copy")
}

// A nil slice is not an empty one.
//
// nil encodes as null and an empty slice as [], so allocating during the
// copy sent [] where the query said null.
func TestCopyDCQLPreservesNilSlices(t *testing.T) {
	src := &DCQL{Credentials: []CredentialQuery{{
		ID: "q", Format: FormatCircuitZk, Meta: MetaQuery{DoctypeValue: "d"},
		Req: []ReqItem{{ID: FunctionAgeCheck, Return: "a", Params: map[string]any{
			"absent":  []any(nil),
			"present": []any{},
		}}},
	}}}

	before, err := json.Marshal(src.Credentials[0].Req[0].Params)
	require.NoError(t, err)
	after, err := json.Marshal(copyDCQL(src).Credentials[0].Req[0].Params)
	require.NoError(t, err)
	assert.Equal(t, string(before), string(after), "copying must not turn null into []")
	assert.Contains(t, string(after), `"absent":null`)
	assert.Contains(t, string(after), `"present":[]`)
}

// A raw leaf inside a TYPED container is still a raw leaf.
//
// map[string]json.RawMessage and []json.RawMessage fell through to the
// encoding fallback, where re-parsing collapsed a duplicate member - so
// templating still changed a deliberately malformed payload even after
// direct raw leaves were preserved.
//
// Compared as text, never semantically: a semantic comparison is exactly
// what hides a dropped duplicate.
func TestCopyDCQLPreservesRawLeavesInTypedContainers(t *testing.T) {
	const inMap = `{"x":1,"x":2}`
	const inSlice = `{"y":1,"y":2}`

	src := &DCQL{Credentials: []CredentialQuery{{
		ID: "q", Format: FormatCircuitZk, Meta: MetaQuery{DoctypeValue: "d"},
		Req: []ReqItem{{ID: FunctionAgeCheck, Return: "a", Params: map[string]any{
			"typed_map":   map[string]json.RawMessage{"a": json.RawMessage(inMap)},
			"typed_slice": []json.RawMessage{json.RawMessage(inSlice)},
		}}},
	}}}

	params := copyDCQL(src).Credentials[0].Req[0].Params

	encoded, err := json.Marshal(params)
	require.NoError(t, err)
	assert.Contains(t, string(encoded), inMap, "a raw leaf in a typed map must survive as bytes")
	assert.Contains(t, string(encoded), inSlice, "a raw leaf in a typed slice must survive as bytes")

	// And the containers are copies, not the originals.
	srcParams := src.Credentials[0].Req[0].Params
	params["typed_map"].(map[string]json.RawMessage)["a"] = json.RawMessage(`{"changed":true}`)
	assert.Equal(t, inMap, string(srcParams["typed_map"].(map[string]json.RawMessage)["a"]),
		"writing to the copied typed map must not reach the original")
}

// namedObject and namedItems are the containers the reflective copy did
// not survive: a NAMED map or slice of any, holding a nil interface
// beside a raw leaf.
type (
	namedObject map[string]any
	namedItems  []any
)

// A nil element must not condemn the whole container.
//
// copyAnyValue returns a nil interface unchanged, reflect.ValueOf gives
// an invalid Value for it, and treating that as "does not fit" sent the
// entire container through the encoding - re-parsing every raw leaf
// beside the nil and collapsing the duplicate members inside them.
//
// Compared as text: a semantic comparison hides a dropped duplicate.
func TestCopyDCQLPreservesRawLeavesBesideNilElements(t *testing.T) {
	const inMap = `{"x":1,"x":2}`
	const inSlice = `{"y":1,"y":2}`

	src := &DCQL{Credentials: []CredentialQuery{{
		ID: "q", Format: FormatCircuitZk, Meta: MetaQuery{DoctypeValue: "d"},
		Req: []ReqItem{{ID: FunctionAgeCheck, Return: "a", Params: map[string]any{
			"named_map":   namedObject{"absent": nil, "raw": json.RawMessage(inMap)},
			"named_slice": namedItems{nil, json.RawMessage(inSlice)},
		}}},
	}}}

	before, err := json.Marshal(src.Credentials[0].Req[0].Params)
	require.NoError(t, err)
	after, err := json.Marshal(copyDCQL(src).Credentials[0].Req[0].Params)
	require.NoError(t, err)

	assert.Equal(t, string(before), string(after), "copying a named container must change nothing")
	assert.Contains(t, string(after), inMap, "a raw leaf beside a nil in a named map must survive as bytes")
	assert.Contains(t, string(after), inSlice, "a raw leaf beside a nil in a named slice must survive as bytes")
	assert.Contains(t, string(after), `"absent":null`, "the nil element must still be null")
}

// An absent raw leaf and an empty one are not the same leaf.
//
// Appending to a nil slice returns a nil slice, so an empty-but-present
// json.RawMessage came out nil. They do not mean the same thing: an empty
// one fails to marshal, while nil marshals as null - so flattening them
// turned a request that cannot be sent into one that quietly says null.
//
// Found while auditing this function for the absent/empty confusion that
// the nil-slice and nil-element findings were both instances of.
func TestCopyPreservesTheDifferenceBetweenAbsentAndEmptyRawLeaves(t *testing.T) {
	var absent json.RawMessage
	empty := json.RawMessage{}

	copiedAbsent, ok := copyAnyValue(absent).(json.RawMessage)
	require.True(t, ok)
	assert.Nil(t, copiedAbsent, "an absent raw leaf stays absent")

	copiedEmpty, ok := copyAnyValue(empty).(json.RawMessage)
	require.True(t, ok)
	assert.NotNil(t, copiedEmpty, "an empty raw leaf must not become an absent one")
	assert.Empty(t, copiedEmpty)

	// The distinction is observable: one marshals, the other refuses.
	_, err := json.Marshal(map[string]any{"k": copiedAbsent})
	require.NoError(t, err, "absent marshals as null")
	_, err = json.Marshal(map[string]any{"k": copiedEmpty})
	require.Error(t, err, "empty must still refuse to marshal, as it did before copying")
}

// A pointer to a raw leaf is still a raw leaf.
//
// *json.RawMessage missed the json.RawMessage case and went to the
// encoding, where re-parsing collapsed a duplicate member - so the
// pointered spelling was still repaired while the value form beside it
// was preserved.
func TestCopyDCQLPreservesPointerRawLeaves(t *testing.T) {
	const duplicate = `{"x":1,"x":2}`
	payload := json.RawMessage(duplicate)

	src := &DCQL{Credentials: []CredentialQuery{{
		ID: "q", Format: FormatCircuitZk, Meta: MetaQuery{DoctypeValue: "d"},
		Req: []ReqItem{{ID: FunctionAgeCheck, Return: "a", Params: map[string]any{
			"payload": &payload,
		}}},
	}}}

	params := copyDCQL(src).Credentials[0].Req[0].Params
	encoded, err := json.Marshal(params)
	require.NoError(t, err)
	assert.Contains(t, string(encoded), duplicate,
		"a pointer-valued raw leaf must be copied as bytes")

	// Independent of the original: writing through either pointer must
	// not reach the other.
	copiedPointer, ok := params["payload"].(*json.RawMessage)
	require.True(t, ok, "the copy keeps the pointer shape")
	require.NotSame(t, &payload, copiedPointer, "the copy must not alias the original pointer")

	*copiedPointer = json.RawMessage(`{"changed":true}`)
	assert.Equal(t, duplicate, string(payload), "writing through the copy must not reach the original")

	payload = json.RawMessage(`{"other":true}`)
	assert.Equal(t, `{"changed":true}`, string(*copiedPointer), "writing to the original must not reach the copy")
}

// rawHolder and privateHolder are the struct shapes the copy had to
// learn: one it can copy field by field, one it must refuse to.
type (
	rawHolder struct {
		Payload json.RawMessage `json:"payload"`
	}
	privateHolder struct {
		Payload json.RawMessage `json:"payload"`
		hidden  string
	}
)

// Arrays and structs hold raw leaves too.
//
// Only map, slice and pointer were copied structurally, so an array or a
// struct went to the encoding and had its duplicate members collapsed -
// the same defect as the slice and pointer cases, in the two shapes left
// over. Found by enumerating what can still reach the encoding fallback
// while holding a raw leaf, rather than waiting for the next review.
func TestCopyPreservesRawLeavesInArraysAndStructs(t *testing.T) {
	t.Run("array", func(t *testing.T) {
		const duplicate = `{"x":1,"x":2}`
		src := map[string]any{"arr": [2]json.RawMessage{json.RawMessage(duplicate), json.RawMessage(`{"y":1}`)}}
		out, err := json.Marshal(copyAnyMap(src))
		require.NoError(t, err)
		assert.Contains(t, string(out), duplicate, "a raw leaf in an array must survive as bytes")
	})

	t.Run("struct", func(t *testing.T) {
		const duplicate = `{"z":1,"z":2}`
		src := map[string]any{"s": rawHolder{Payload: json.RawMessage(duplicate)}}
		out, err := json.Marshal(copyAnyMap(src))
		require.NoError(t, err)
		assert.Contains(t, string(out), duplicate, "a raw leaf in a struct field must survive as bytes")

		// And it is a copy, not the original.
		copied, ok := copyAnyMap(src)["s"].(rawHolder)
		require.True(t, ok, "the copy keeps the struct shape")
		copied.Payload[1] = 'Z'
		assert.Equal(t, duplicate, string(src["s"].(rawHolder).Payload),
			"writing to the copied struct must not reach the original")
	})

	t.Run("a struct with an unexported field is normalised, not silently truncated", func(t *testing.T) {
		src := map[string]any{"s": privateHolder{Payload: json.RawMessage(`{"z":1}`), hidden: "x"}}
		out, err := json.Marshal(copyAnyMap(src))
		require.NoError(t, err)
		// Reflection can neither read nor set the unexported field, so
		// this falls back to the encoding rather than dropping it.
		assert.Contains(t, string(out), `"payload"`)
	})
}

// A null filter is neither absent nor empty, and the model cannot hold it.
//
// {"circuit_id_values":null} decoded to a nil slice, which omitzero then
// omitted, so an explicitly supplied filter re-encoded as {} - no filter
// at all, and the wallet saw an unfiltered request. {"circuit_id_values":
// [null]} decoded the element to the zero string and re-encoded as [""],
// turning a filter that names nothing into one that names the empty
// string. Both are refused rather than repaired.
func TestNullFiltersAreRefusedNotRepaired(t *testing.T) {
	for _, name := range []string{"circuit_id_values", "circuit_proof_system_values"} {
		t.Run(name+" null array (JSON)", func(t *testing.T) {
			var f CircuitZkFormat
			err := json.Unmarshal([]byte(`{"`+name+`":null}`), &f)
			require.Error(t, err, "a null filter must not decode to an absent one")
			assert.Contains(t, err.Error(), "cannot be told from an absent member")
		})

		t.Run(name+" null element (JSON)", func(t *testing.T) {
			var f CircuitZkFormat
			err := json.Unmarshal([]byte(`{"`+name+`":[null]}`), &f)
			require.Error(t, err, "a null element must not decode to an empty string")
			assert.Contains(t, err.Error(), "read back as an empty string")
		})
	}

	// The YAML path decodes the same two spellings into the same two
	// wrong answers, so it carries the same refusal.
	t.Run("null array (YAML)", func(t *testing.T) {
		var f CircuitZkFormat
		err := yamlv2.Unmarshal([]byte("circuit_id_values: null\n"), &f)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot be told from an absent member")
	})

	t.Run("null element (YAML)", func(t *testing.T) {
		var f CircuitZkFormat
		err := yamlv2.Unmarshal([]byte("circuit_id_values:\n  - null\n"), &f)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "read back as an empty string")
	})

	// The two spellings that DO have a meaning still work, in both
	// directions: absent is no filter, empty is a filter matching nothing.
	t.Run("absent and empty still round-trip", func(t *testing.T) {
		var absent CircuitZkFormat
		require.NoError(t, json.Unmarshal([]byte(`{}`), &absent))
		encoded, err := json.Marshal(absent)
		require.NoError(t, err)
		assert.JSONEq(t, `{}`, string(encoded))

		var empty CircuitZkFormat
		require.NoError(t, json.Unmarshal([]byte(`{"circuit_id_values":[]}`), &empty))
		encoded, err = json.Marshal(empty)
		require.NoError(t, err)
		assert.JSONEq(t, `{"circuit_id_values":[]}`, string(encoded))
	})
}
