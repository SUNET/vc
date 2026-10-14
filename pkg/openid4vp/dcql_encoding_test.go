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
				ID: "pid", Format: FormatSDJWTVC, Multiple: true,
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
