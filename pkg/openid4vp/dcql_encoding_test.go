package openid4vp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Adding MarshalJSON to CredentialQuery and VPFormatsSupported changes how
// EVERY format is encoded, not just circuit_zk - these types carry mdoc,
// SD-JWT and W3C queries too.
//
// So with no extension set, the output must be byte-identical to the
// struct encoding the method replaced. Not merely equivalent: identical,
// because these bytes are signed. A request object is a JWS over this
// JSON, so a reordered or differently-omitted member changes a signature
// that wallets and conformance fixtures have already pinned.
//
// The comparison is against encoding the same value through a type that
// has no methods, which is exactly what encoding/json did before.
func TestCredentialQueryEncodingUnchanged(t *testing.T) {
	requireTrue := new(true)
	requireFalse := new(false)

	for _, tc := range []struct {
		name  string
		query CredentialQuery
	}{
		{name: "empty", query: CredentialQuery{}},
		{
			name: "an mdoc query",
			query: CredentialQuery{
				ID: "pid", Format: FormatMsoMdoc,
				Meta:   MetaQuery{DoctypeValue: "eu.europa.ec.eudi.pid.1"},
				Claims: []ClaimQuery{{Path: StringPath("eu.europa.ec.eudi.pid.1", "family_name")}},
			},
		},
		{
			name: "an SD-JWT query with claim sets and holder binding",
			query: CredentialQuery{
				ID: "pid", Format: FormatSDJWTVC, Multiple: new(true),
				Meta:                              MetaQuery{VCTValues: []string{"urn:eudi:pid:1"}},
				Claims:                            []ClaimQuery{{ID: "a", Path: StringPath("family_name")}},
				ClaimSet:                          [][]string{{"a"}},
				RequireCryptographicHolderBinding: requireTrue,
			},
		},
		{
			name: "a W3C query with trusted authorities and binding false",
			query: CredentialQuery{
				ID: "dip", Format: FormatVCLDJSON,
				Meta:                              MetaQuery{TypeValues: [][]string{{"https://example.org/Diploma"}}},
				TrustedAuthorities:                []TrustedAuthority{{Type: "aki", Values: []string{"abc"}}},
				RequireCryptographicHolderBinding: requireFalse,
			},
		},
		{
			name: "a ZK mdoc query",
			query: CredentialQuery{
				ID: "mdl", Format: FormatMsoMdocZk,
				Meta: MetaQuery{
					DoctypeValue: "org.iso.18013.5.1.mDL",
					ZKSystemType: []ZKSystemTypeSpec{{ID: "x", System: "y", Params: map[string]string{"n": "1"}}},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			type plain CredentialQuery // no methods: the old encoding
			before, err := json.Marshal(plain(tc.query))
			require.NoError(t, err)

			after, err := json.Marshal(tc.query)
			require.NoError(t, err)

			assert.Equal(t, string(before), string(after),
				"these bytes are signed; a change here changes a signature")
			assert.NotContains(t, string(after), `"req"`, "a non-circuit_zk query must not grow a req member")
		})
	}
}

func TestVPFormatsSupportedEncodingUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name    string
		formats VPFormatsSupported
	}{
		{name: "empty", formats: VPFormatsSupported{}},
		{
			name: "every pre-existing format",
			formats: VPFormatsSupported{
				LDPVC:     &LDPVCFormat{ProofTypeValues: []string{"DataIntegrityProof"}},
				JWTVCJson: &JWTVCFormat{AlgValues: []string{"ES256"}},
				SDJWT:     &SDJWTVCFormat{SDJWTAlgValues: []string{"ES256"}},
				MsoMdoc:   &MsoMdocFormat{IssuerAuthAlgValues: []int{-7}},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			type plain VPFormatsSupported
			before, err := json.Marshal(plain(tc.formats))
			require.NoError(t, err)
			after, err := json.Marshal(tc.formats)
			require.NoError(t, err)
			assert.Equal(t, string(before), string(after))
			assert.NotContains(t, string(after), "circuit_zk")
		})
	}
}

// A decode of a query carrying no unknown members must leave Extra nil,
// so a request read in and written back out is unchanged - and so the
// byte-identity above is not quietly bypassed by every decoded query
// acquiring an empty map.
func TestDecodingAKnownQueryLeavesNoExtra(t *testing.T) {
	const in = `{"id":"pid","format":"mso_mdoc","meta":{"doctype_value":"d"}}`
	var query CredentialQuery
	require.NoError(t, json.Unmarshal([]byte(in), &query))
	assert.Nil(t, query.Extra)
	assert.Nil(t, query.Raw)

	out, err := json.Marshal(query)
	require.NoError(t, err)
	assert.JSONEq(t, in, string(out))
}

// An ordinary query must stay MUTABLE, because something downstream
// mutates it.
//
// Multiple was a plain bool with omitempty, so `"multiple": false` - a
// valid, unremarkable SD-JWT query - did not encode back to what arrived
// and was kept as Raw. A raw query is emitted from its original bytes, so
// augmentDCQLFromVCTM's rewrite of the shadow Claims was silently
// discarded and the request went out with the un-augmented paths. Nothing
// failed; the wallet simply got a different query than the one the
// verifier had decided to send.
//
// The decode-augment-serialise cycle is the thing to assert, not the Raw
// flag on its own: a future member with the same omitempty problem would
// reintroduce exactly this, and the flag alone would not say what it
// cost.
func TestOrdinaryQueriesSurviveDecodeAugmentSerialise(t *testing.T) {
	for _, body := range []string{
		`{"id":"pid","format":"dc+sd-jwt","multiple":false,"meta":{"vct_values":["urn:x"]},"claims":[{"path":["address","locality"]}]}`,
		`{"id":"pid","format":"dc+sd-jwt","multiple":true,"meta":{"vct_values":["urn:x"]},"claims":[{"path":["address","locality"]}]}`,
		`{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:x"]},"claims":[{"path":["address","locality"]}]}`,
	} {
		t.Run(body, func(t *testing.T) {
			var q CredentialQuery
			require.NoError(t, json.Unmarshal([]byte(body), &q))

			require.Nil(t, q.Raw,
				"an ordinary query must not be kept raw; a raw one ignores the edits below")

			// What augmentDCQLFromVCTM does to a query whose parent claim
			// has configured children.
			q.Claims = []ClaimQuery{{Path: StringPath("address")}}

			encoded, err := json.Marshal(q)
			require.NoError(t, err)
			assert.Contains(t, string(encoded), `"claims":[{"path":["address"]}]`,
				"the augmented claims must be what goes on the wire")
			assert.NotContains(t, string(encoded), `"locality"`,
				"the pre-augmentation path must not survive")
		})
	}
}

// And the member that caused it round-trips in all three states, which is
// the property a plain bool could not have: absent, explicitly false, and
// explicitly true are three different requests.
func TestMultipleRoundTripsAbsentFalseAndTrue(t *testing.T) {
	for _, tc := range []struct {
		body         string
		wantInOutput string
		allows       bool
	}{
		{`{"id":"q","format":"dc+sd-jwt","meta":{}}`, "", false},
		{`{"id":"q","format":"dc+sd-jwt","multiple":false,"meta":{}}`, `"multiple":false`, false},
		{`{"id":"q","format":"dc+sd-jwt","multiple":true,"meta":{}}`, `"multiple":true`, true},
	} {
		t.Run(tc.body, func(t *testing.T) {
			var q CredentialQuery
			require.NoError(t, json.Unmarshal([]byte(tc.body), &q))
			require.Nil(t, q.Raw)
			assert.Equal(t, tc.allows, q.AllowsMultiple())

			encoded, err := json.Marshal(q)
			require.NoError(t, err)
			if tc.wantInOutput == "" {
				assert.NotContains(t, string(encoded), `"multiple"`,
					"an omitted member must stay omitted, not become an explicit false")
				return
			}
			assert.Contains(t, string(encoded), tc.wantInOutput)
		})
	}
}

// A constraint this verifier reads one way and a wallet reads another is
// not a request to sign, and reaching the Raw path must not be a way past
// that rule.
//
// The duplicate check ran only after a SUCCESSFUL typed decode. An
// unmodelled member - `"req": {}` - made the decode fail, the query went
// raw, and the check never ran: the shadow still reported the last meta's
// constraint, so validation passed, while the request was emitted with
// BOTH metas. A first-wins wallet reads the empty one and is handed an
// unconstrained SD-JWT request.
//
// Case is the same hole by another route. encoding/json matches field
// names case-insensitively, so "VCT_VALUES" populates MetaQuery.VCTValues
// and the shadow reports a constraint - while the signed bytes carry a
// member name no conformant wallet reads.
func TestRawPathIsNotAWayPastTheConstraintChecks(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{
			name: "duplicate meta, reached through an unmodelled member",
			body: `{"id":"q","format":"dc+sd-jwt","meta":{},"meta":{"vct_values":["urn:x"]},"req":{}}`,
			want: "named more than once",
		},
		{
			name: "duplicate meta, reached through object-valued claims",
			body: `{"id":"q","format":"dc+sd-jwt","meta":{},"meta":{"vct_values":["urn:x"]},"claims":{}}`,
			want: "named more than once",
		},
		{
			name: "duplicate format, same route",
			body: `{"id":"q","format":"dc+sd-jwt","format":"mso_mdoc","meta":{},"req":{}}`,
			want: "named more than once",
		},
		{
			name: "a case-aliased constraint inside meta",
			body: `{"id":"q","format":"dc+sd-jwt","meta":{"VCT_VALUES":["urn:x"]}}`,
			want: "differs only in case",
		},
		{
			name: "a case-aliased meta itself",
			body: `{"id":"q","format":"dc+sd-jwt","META":{"vct_values":["urn:x"]}}`,
			want: "differs only in case",
		},
		{
			name: "a case-aliased doctype_value",
			body: `{"id":"q","format":"mso_mdoc","meta":{"DocType_Value":"org.iso.18013.5.1.mDL"}}`,
			want: "differs only in case",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var q CredentialQuery
			err := json.Unmarshal([]byte(tc.body), &q)
			require.Error(t, err, "this request must not be readable; it decoded to %#v", q)
			assert.Contains(t, err.Error(), tc.want)

			// And the explicit constructor refuses it too, so neither
			// entrance can produce one.
			_, cerr := NewRawCredentialQuery(json.RawMessage(tc.body))
			require.Error(t, cerr)
			assert.Contains(t, cerr.Error(), tc.want)
		})
	}
}

// And the rule is narrow: an unmodelled member on its own is exactly what
// the raw path is for, and an exactly-spelled constraint beside it is
// still read and still emitted as it arrived.
func TestRawPathStillCarriesUnmodelledMembers(t *testing.T) {
	for _, body := range []string{
		`{"id":"q","format":"dc+sd-jwt","meta":{"vct_values":["urn:x"]},"req":{}}`,
		`{"id":"q","format":"dc+sd-jwt","meta":{"vct_values":["urn:x"]},"claims":{}}`,
		`{"id":"q","format":"dc+sd-jwt","meta":{"vct_values":["urn:x"],"future_member":1}}`,
	} {
		t.Run(body, func(t *testing.T) {
			var q CredentialQuery
			require.NoError(t, json.Unmarshal([]byte(body), &q),
				"an unmodelled member is the point of the raw path")

			encoded, err := json.Marshal(q)
			require.NoError(t, err)
			assert.JSONEq(t, body, string(encoded), "and it goes out as it came in")
		})
	}
}

// A claim value is judged on what the number IS, not how it is spelled.
//
// 10, 10.0 and 1e1 are the same integer, and ordinary SD-JWT and mdoc
// queries use all three. An earlier version of this check tested the
// spelling and rejected the last two - a regression for every query that
// did not happen to write its integers the shortest way.
//
// Decided on the digits rather than by parsing, because parsing is what
// the exact-copy work exists to avoid: a float64 cannot hold
// 9007199254740993.
func TestClaimValuesAreJudgedByValueNotSpelling(t *testing.T) {
	for _, tc := range []struct {
		literal string
		ok      bool
	}{
		{"10", true},
		{"10.0", true},
		{"10.000", true},
		{"1e1", true},
		{"1E1", true},
		{"1.5e1", true},  // 15
		{"-1.5e1", true}, // -15
		{"1e+2", true},   // 100
		{"0", true},
		{"0.0", true},
		{"0e-5", true}, // zero is an integer however it is spelled
		{"9007199254740993", true},
		{"123456789012345678901234567890", true},
		{"-9007199254740993", true},

		{"1.5", false},
		{"1e-1", false},   // 0.1
		{"1.55e1", false}, // 15.5
		{"0.001", false},
		{"1e-20", false},

		// An exponent may sit at the very end of the int range. Both of
		// these are nonzero magnitudes far below one, so neither is an
		// integer - but reaching that answer by negating the shift wraps
		// to a negative cut and panics the slice, and reaching it by
		// subtracting the fraction length wraps the other way and calls a
		// fraction integral.
		{"1e-9223372036854775808", false},
		{"1.0e-9223372036854775808", false},
	} {
		t.Run(tc.literal, func(t *testing.T) {
			body := `{"id":"q","format":"dc+sd-jwt","meta":{"vct_values":["urn:x"]},` +
				`"claims":[{"path":["a"],"values":[` + tc.literal + `]}]}`
			var q CredentialQuery
			err := json.Unmarshal([]byte(body), &q)
			if tc.ok {
				require.NoError(t, err, "%s is an integer", tc.literal)

				// And it goes out as it came in: judging the literal must
				// not mean rewriting it.
				encoded, mErr := json.Marshal(q)
				require.NoError(t, mErr)
				assert.Contains(t, string(encoded), tc.literal)
				return
			}
			require.Error(t, err, "%s is not an integer", tc.literal)
		})
	}
}
