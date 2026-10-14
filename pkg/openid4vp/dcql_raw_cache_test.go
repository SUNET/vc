package openid4vp

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A request object is JSON-encoded into the HA cache and read back by
// another node (internal/verifier/cache). So a query this model cannot
// hold has to survive that round trip, or the escape hatch works only on
// the node that built the request - which is the shape of bug that shows
// up as "it works on one replica".
func TestRawSurvivesAJSONRoundTrip(t *testing.T) {
	for _, tc := range []struct{ name, query string }{
		{"the WIP shape, claims as an object", `{"id":"q","format":"circuit_zk","meta":{"doctype_value":"d"},"claims":{"_req":[{"fn_id":"age_check","id":"h"}]}}`},
		{"req as an object, as a later generation might", `{"id":"q","format":"circuit_zk","req":{"not":"an array"}}`},
		{"a member whose type the model does not expect", `{"id":"q","format":"circuit_zk","meta":"not an object"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// As the verifier built it.
			built := CredentialQuery{Raw: json.RawMessage(tc.query)}

			// Into the cache.
			stored, err := json.Marshal(&DCQL{Credentials: []CredentialQuery{built}})
			require.NoError(t, err)

			// And back out on another node.
			var loaded DCQL
			require.NoError(t, json.Unmarshal(stored, &loaded),
				"a query the model cannot hold must still load; otherwise the request exists only where it was made")
			require.Len(t, loaded.Credentials, 1)

			// What goes to the wallet is what was configured.
			out, err := json.Marshal(loaded.Credentials[0])
			require.NoError(t, err)
			assert.JSONEq(t, tc.query, string(out))
		})
	}
}

// A query the model DOES understand still decodes typed, so the fallback
// does not quietly swallow everything.
func TestTypedQueriesStillDecodeTyped(t *testing.T) {
	const in = `{"id":"q","format":"circuit_zk","meta":{"doctype_value":"d"},"req":[{"id":"age_check","return":"h"}]}`
	var query CredentialQuery
	require.NoError(t, json.Unmarshal([]byte(in), &query))

	assert.Nil(t, query.Raw, "this shape is modelled, so it must not fall back to raw")
	require.Len(t, query.Req, 1)
	assert.Equal(t, FunctionAgeCheck, query.Req[0].ID)
}

// Invalid JSON is still an error. The fallback keeps shapes, not rubbish:
// bytes that are not JSON cannot be put inside a request object at all.
func TestInvalidJSONIsStillRejected(t *testing.T) {
	var query CredentialQuery
	require.Error(t, json.Unmarshal([]byte(`{not json`), &query))
}

// The escape hatch has to get PAST the ingress, not just through the
// serialiser. UIInteraction and the two VC 2.0 paths run every query they
// are handed through ValidateCredentialQuery.
//
// What it must NOT do is become a way around the format rules. A raw
// query is therefore judged by its own bytes: the format and the
// constraint are re-read from them, so the hatch covers a member whose
// shape this build does not model and nothing else.
func TestValidateJudgesARawQueryByItsOwnBytes(t *testing.T) {
	for _, tc := range []struct {
		name, query, wantErr string
	}{
		{
			name:  "circuit_zk, which this build does not constrain either way",
			query: `{"id":"q","format":"circuit_zk","meta":{"doctype_value":"d"},"claims":{"_req":[]}}`,
		},
		{
			name:  "an mdoc query whose doctype survived the member that did not",
			query: `{"id":"q","format":"mso_mdoc","meta":{"doctype_value":"d"},"claims":{"_req":[]}}`,
		},
		{
			name:    "an sd-jwt query with no vct_values is still an unconstrained request",
			query:   `{"id":"q","format":"vc+sd-jwt","claims":{"_req":[]}}`,
			wantErr: "vct_values",
		},
		{
			name:    "and an mdoc one with no doctype",
			query:   `{"id":"q","format":"mso_mdoc","claims":{"_req":[]}}`,
			wantErr: "doctype_value",
		},
		// "Cannot read the constraint" and "there is no constraint" are
		// the same thing downstream, so an unreadable meta is judged as an
		// empty one. Otherwise the check is dodged by making the member
		// harder to read rather than by leaving it out.
		{
			name:    "meta unreadable, on a format that has a rule",
			query:   `{"id":"q","format":"vc+sd-jwt","meta":"not an object"}`,
			wantErr: "cannot read",
		},
		{
			name:    "and the whole query not being an object is the same thing",
			query:   `[1,2,3]`,
			wantErr: "cannot read",
		},
		{
			name:  "meta unreadable, on a format that has none",
			query: `{"id":"q","format":"circuit_zk","meta":"not an object"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var query CredentialQuery
			require.NoError(t, json.Unmarshal([]byte(tc.query), &query))
			require.NotNil(t, query.Raw, "the point of this case is that it fell back to raw")

			err := ValidateCredentialQuery(query)
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// Raw is authoritative for the wire and nothing else. The rest of the
// stack routes by id - UIInteraction copies it into the authorization
// context's scopes, and the response path matches a presentation back to
// it - so a raw query that kept an empty id would be sent correctly and
// then match nothing that came back.
func TestRawRetainsTheMembersTheStackRoutesBy(t *testing.T) {
	const in = `{"id":"q","format":"circuit_zk","meta":{"doctype_value":"d"},"claims":{"_req":[]}}`
	var query CredentialQuery
	require.NoError(t, json.Unmarshal([]byte(in), &query))

	require.NotNil(t, query.Raw)
	assert.Equal(t, "q", query.ID, "the response path looks a presentation up by this")
	assert.Equal(t, FormatCircuitZk, query.Format, "every format decision after this reads it")

	// And the wire is still the bytes that arrived, not a re-encoding of
	// the two members just adopted.
	out, err := json.Marshal(query)
	require.NoError(t, err)
	assert.JSONEq(t, in, string(out))
}

// Best effort, both ways: a routing member of a type this build does not
// expect is left alone rather than coerced, and does not stop the rest.
func TestRawRoutingIgnoresMembersItCannotRead(t *testing.T) {
	var query CredentialQuery
	require.NoError(t, json.Unmarshal([]byte(`{"id":7,"format":"circuit_zk","claims":{"_req":[]}}`), &query))
	require.NotNil(t, query.Raw)
	assert.Empty(t, query.ID)
	assert.Equal(t, FormatCircuitZk, query.Format)
}

// Not judging is not the same as not looking. Raw is emitted verbatim, so
// bytes that are not JSON would make the whole request object unencodable
// at send time, far from the configuration that caused it.
func TestValidateRejectsRawThatIsNotJSON(t *testing.T) {
	err := ValidateCredentialQuery(CredentialQuery{Raw: json.RawMessage(`{not json`)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "raw")
}

// The escape hatch is meant to be used in code too, not only reached by
// a decode that failed. A query built as CredentialQuery{Raw: ...} - a
// template the verifier assembles, say - carries none of the struct's
// shadow copies of id and format, so validation has to read them from the
// bytes rather than trust the struct.
//
// Without that, an empty Format means SD-JWT to every reader, and a raw
// circuit_zk query is refused for a vct_values it was never going to
// have, on every production path that validates.
func TestValidateReadsTheFormatFromRawNotFromTheStruct(t *testing.T) {
	for _, tc := range []struct {
		name, query, wantErr string
	}{
		{
			name:  "circuit_zk, built in code with no decode in sight",
			query: `{"id":"q","format":"circuit_zk","meta":{"doctype_value":"d"},"claims":{"_req":[]}}`,
		},
		{
			name:  "mso_mdoc with its doctype, likewise",
			query: `{"id":"q","format":"mso_mdoc","meta":{"doctype_value":"d"},"claims":{"_req":[]}}`,
		},
		{
			name:    "and the rules still apply: sd-jwt with no vct_values",
			query:   `{"id":"q","format":"vc+sd-jwt","claims":{"_req":[]}}`,
			wantErr: "vct_values",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Constructed directly. No UnmarshalJSON anywhere.
			query := CredentialQuery{Raw: json.RawMessage(tc.query)}
			require.Empty(t, query.Format, "the point of this case is that the struct carries nothing")

			err := ValidateCredentialQuery(query)
			if tc.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

// Raw is authoritative for the WIRE and nothing else. Plenty of this
// stack reads the struct - matching reads Meta.TypeValues, Multiple and
// RequireCryptographicHolderBinding change what a response may contain -
// so a query that arrived raw and kept zero values for those was sent
// correctly and then judged against defaults nobody chose.
//
// Derived from the struct tags, so this test also fails if a new member
// is added to CredentialQuery and left out of the shadow.
func TestRawShadowsEveryReadableModelledMember(t *testing.T) {
	const in = `{
		"id": "w3c",
		"format": "ldp_vc",
		"multiple": true,
		"require_cryptographic_holder_binding": false,
		"meta": {"type_values": [["https://www.w3.org/2018/credentials#VerifiableCredential","https://example.org#Diploma"]]},
		"claim_sets": [["a"]],
		"claims": {"_req": [{"fn_id": "age_check"}]}
	}`
	var query CredentialQuery
	require.NoError(t, json.Unmarshal([]byte(in), &query))
	require.NotNil(t, query.Raw, "claims as an object is what sends this down the raw path")

	assert.Equal(t, "w3c", query.ID)
	assert.Equal(t, FormatLdpVCDCQL, query.Format)
	assert.True(t, query.Multiple, "a response is allowed more than one credential because of this")
	require.NotNil(t, query.RequireCryptographicHolderBinding)
	assert.False(t, *query.RequireCryptographicHolderBinding, "an explicit false must not revert to the spec default")
	require.Len(t, query.Meta.TypeValues, 1, "matching reads this; empty matches nothing")
	assert.Equal(t, [][]string{{"a"}}, query.ClaimSet)

	// The member that could not be read is simply absent, not fatal.
	assert.Empty(t, query.Claims)

	// And the wire is still exactly what arrived.
	out, err := json.Marshal(query)
	require.NoError(t, err)
	assert.JSONEq(t, in, string(out))
}

// The shadow is derived from the tags, so every json-tagged member of
// CredentialQuery has to be reachable through it. A member added without
// being shadowed is the bug this catches on the commit that adds it.
func TestEveryModelledMemberIsShadowed(t *testing.T) {
	structure := reflect.TypeOf(CredentialQuery{})
	var shadowed int
	for i := range structure.NumField() {
		name, _, _ := strings.Cut(structure.Field(i).Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue // Raw and Extra, which are not wire members
		}
		shadowed++
	}
	// Fail closed: a walk that found nothing proves nothing.
	require.NotZero(t, shadowed)

	// Every one of them set to a non-zero value in the raw bytes must
	// come back out of the shadow.
	raw := map[string]any{
		"id": "q", "format": "mso_mdoc", "multiple": true,
		"meta":                                 map[string]any{"doctype_value": "d"},
		"trusted_authorities":                  []any{map[string]any{"type": "aki", "values": []string{"x"}}},
		"require_cryptographic_holder_binding": false,
		"claim_sets":                           [][]string{{"a"}},
		"req":                                  []any{map[string]any{"id": "f", "return": "h"}},
		// claims is the member that forces the raw path.
		"claims": map[string]any{"_req": []any{}},
	}
	encoded, err := json.Marshal(raw)
	require.NoError(t, err)

	var query CredentialQuery
	require.NoError(t, json.Unmarshal(encoded, &query))
	require.NotNil(t, query.Raw)

	value := reflect.ValueOf(query)
	for i := range structure.NumField() {
		name, _, _ := strings.Cut(structure.Field(i).Tag.Get("json"), ",")
		if name == "" || name == "-" || name == "claims" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			assert.Falsef(t, value.Field(i).IsZero(),
				"%s is set in the raw bytes but zero on the struct, so everything reading the struct sees a default nobody chose", name)
		})
	}
}

// The constructor is what makes a hand-built raw query usable: the
// shadow has to be on the STORED query, not only on the copy validation
// happens to make, because the response path reads the stored one.
func TestNewRawCredentialQueryFillsTheShadow(t *testing.T) {
	const in = `{"id":"w3c","format":"ldp_vc","multiple":true,"meta":{"type_values":[["https://example.org#Diploma"]]},"claims":{"_req":[]}}`

	query, err := NewRawCredentialQuery(json.RawMessage(in))
	require.NoError(t, err)

	assert.Equal(t, "w3c", query.ID, "the response path matches a presentation back to this")
	assert.Equal(t, FormatLdpVCDCQL, query.Format)
	assert.True(t, query.Multiple)
	require.Len(t, query.Meta.TypeValues, 1, "matching reads this; empty matches nothing")

	// And the wire is still exactly the bytes handed in.
	out, err := json.Marshal(query)
	require.NoError(t, err)
	assert.JSONEq(t, in, string(out))
}

// It refuses bytes that are not JSON rather than deferring the failure to
// send time, where it would surface as an unencodable request object a
// long way from the call that caused it.
func TestNewRawCredentialQueryRefusesNonJSON(t *testing.T) {
	_, err := NewRawCredentialQuery(json.RawMessage(`{not json`))
	require.Error(t, err)
}

// The copy is independent: mutating the caller's slice afterwards must
// not change what the query sends.
func TestNewRawCredentialQueryCopiesItsInput(t *testing.T) {
	raw := []byte(`{"id":"q","format":"circuit_zk","claims":{"_req":[]}}`)
	query, err := NewRawCredentialQuery(raw)
	require.NoError(t, err)

	before, err := json.Marshal(query)
	require.NoError(t, err)
	copy(raw, []byte(`{"id":"X"`))
	after, err := json.Marshal(query)
	require.NoError(t, err)
	assert.JSONEq(t, string(before), string(after))
}

// escapedAmpersand is how encoding/json writes & inside a string. Built
// rather than spelled so this file contains no escape sequence that could
// be mistaken for the thing it describes.
var escapedAmpersand = string(rune(92)) + "u0026"

// What Raw does and does not promise.
//
// encoding/json post-processes whatever a MarshalJSON returns on its way
// into the enclosing document: it compacts, and it HTML-escapes. So "the
// exact bytes" was never true, and the semantic comparisons everywhere
// else in this file could not have caught that. This pins the real
// guarantee from both sides, so neither half is an assumption.
func TestRawPreservesTheValueAndNotTheBytes(t *testing.T) {
	// Spaced and indented the way an operator might write it, with a
	// character encoding/json escapes inside a string value.
	const configured = `{
		"id": "q",
		"format": "circuit_zk",
		"meta": { "doctype_value": "a&b" },
		"claims": { "_req": [] }
	}`

	query, err := NewRawCredentialQuery(json.RawMessage(configured))
	require.NoError(t, err)
	encoded, err := json.Marshal(&DCQL{Credentials: []CredentialQuery{query}})
	require.NoError(t, err)

	t.Run("the bytes are not preserved, and this is the documented limit", func(t *testing.T) {
		assert.NotContains(t, string(encoded), "\n\t\t",
			"encoding/json compacts, so an operator's layout does not reach the wire")
		assert.NotContains(t, string(encoded), "a&b",
			"and it HTML-escapes, so the configured text is not what appears on the wire")
		assert.Contains(t, string(encoded), "a"+escapedAmpersand+"b",
			"the ampersand is written as its escape")
	})

	t.Run("every member and value is preserved, which is the promise", func(t *testing.T) {
		var decoded DCQL
		require.NoError(t, json.Unmarshal(encoded, &decoded))
		require.Len(t, decoded.Credentials, 1)

		out, err := json.Marshal(decoded.Credentials[0])
		require.NoError(t, err)
		assert.JSONEq(t, configured, string(out),
			"including claims as an object, which the typed model cannot hold")

		// And the escaping is a spelling, not a change: a wallet reading
		// it gets the string that was configured.
		var shape struct {
			Credentials []struct {
				Meta struct {
					DoctypeValue string `json:"doctype_value"`
				} `json:"meta"`
			} `json:"credentials"`
		}
		require.NoError(t, json.Unmarshal(encoded, &shape))
		assert.Equal(t, "a&b", shape.Credentials[0].Meta.DoctypeValue)
	})
}

// A duplicate member is invisible to the encode-back-to comparison:
// encoding/json keeps the last one, so {"id":"first","id":"last"}
// re-encodes as just "last" and compares equal to itself. The query would
// go out with the duplicate silently removed.
//
// Two reasons that is wrong here. It is a changed request, and a
// duplicate member is exactly the kind of malformed input a Verifier
// sends on purpose to see what a wallet does with it. And it is a parser
// differential - decoders disagree about which value wins - so a request
// where that matters has to arrive as written rather than as this build
// happens to read it.
func TestDuplicateMembersGoRawAndSurvive(t *testing.T) {
	for _, tc := range []struct {
		name, query string
		wantRaw     bool
	}{
		{"a duplicate at the top level", `{"id":"first","id":"last","format":"circuit_zk","meta":{"doctype_value":"d"}}`, true},
		{"a duplicate nested inside a req param", `{"id":"q","format":"circuit_zk","meta":{},"req":[{"id":"f","return":"h","params":{"p":1,"p":2}}]}`, true},
		{"a duplicate inside meta", `{"id":"q","format":"mso_mdoc","meta":{"doctype_value":"a","doctype_value":"b"}}`, true},

		// The same NAME in two different objects is not a duplicate. A
		// scanner that missed this would push every ordinary req down the
		// raw path.
		{"the same name in sibling objects", `{"id":"q","format":"circuit_zk","meta":{"doctype_value":"d"},"req":[{"id":"a","return":"h"},{"id":"b","return":"h2"}]}`, false},
		{"and the same name at different depths", `{"id":"q","format":"circuit_zk","meta":{"doctype_value":"d"},"req":[{"id":"a","return":"h","params":{"id":"inner"}}]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var query CredentialQuery
			require.NoError(t, json.Unmarshal([]byte(tc.query), &query))

			if !tc.wantRaw {
				assert.Nil(t, query.Raw, "this query has no duplicate and must still decode typed")
				return
			}
			require.NotNil(t, query.Raw, "a duplicate member has nowhere to live in the typed model")

			// And it reaches the wire intact, BOTH members present.
			//
			// Compared as text, not with JSONEq: that parses both sides,
			// which collapses the duplicate on each, so it would pass
			// just as happily if one member had been dropped. These
			// inputs are already compact and carry nothing
			// encoding/json escapes, so the bytes stand.
			out, err := json.Marshal(query)
			require.NoError(t, err)
			assert.Equal(t, tc.query, string(out))
		})
	}
}

// The escape hatch must not become a laundry for invalid ordinary
// queries.
//
// Making the decode total meant any query the model rejected became Raw -
// including one that is plain DCQL and simply WRONG. An SD-JWT query with
// claims:[{"path":[]}] is refused by ClaimQuery.UnmarshalJSON, and used
// to be refused outright; under a total decode it became Raw, the shadow
// left Claims empty, and validation then found nothing to object to. The
// UI path would sign and send a query that previously could not be
// decoded at all.
//
// The line is the JSON KIND. A member of a kind the model does not have
// is a shape this build has never seen, and belongs in Raw. A member of
// the right kind that the model still rejects is an ordinary query that
// is invalid, and stays refused.
func TestInvalidModelledMembersAreNotLaunderedIntoRaw(t *testing.T) {
	for _, tc := range []struct {
		name, query string
		wantErr     bool
	}{
		{
			name:    "an empty claim path, which the model rejects",
			query:   `{"id":"q","format":"dc+sd-jwt","meta":{"vct_values":["urn:x"]},"claims":[{"path":[]}]}`,
			wantErr: true,
		},
		{
			name:    "and the same inside an otherwise fine mdoc query",
			query:   `{"id":"q","format":"mso_mdoc","meta":{"doctype_value":"d"},"claims":[{"path":[]}]}`,
			wantErr: true,
		},
		{
			// Same member, different KIND: an object where DCQL has an
			// array. This is the rulebook's WIP shape and the reason Raw
			// exists at all.
			name:  "claims as an object, which the model does not have",
			query: `{"id":"q","format":"circuit_zk","meta":{"doctype_value":"d"},"claims":{"_req":[]}}`,
		},
		{
			name:  "req as an object, likewise",
			query: `{"id":"q","format":"circuit_zk","meta":{"doctype_value":"d"},"req":{"not":"an array"}}`,
		},
		{
			name:  "an ordinary valid query",
			query: `{"id":"q","format":"dc+sd-jwt","meta":{"vct_values":["urn:x"]},"claims":[{"path":["a"]}]}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var query CredentialQuery
			err := json.Unmarshal([]byte(tc.query), &query)
			if tc.wantErr {
				require.Error(t, err,
					"a query the model rejects must stay rejected, not become raw and then validate")
				return
			}
			require.NoError(t, err)
		})
	}
}
