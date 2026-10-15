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
