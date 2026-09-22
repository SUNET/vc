package apiv1

import (
	"encoding/base64"
	"testing"

	"github.com/SUNET/vc/pkg/mdoc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDetectCredentialFormat_MDocZk confirms that detectCredentialFormat
// distinguishes a ZK-mdoc ("mso_mdoc_zk") vp_token from a plain "mso_mdoc"
// one, even though both are wire-compatible base64url CBOR at the
// byte-sniffing level this function otherwise relies on - see
// mdoc.PeekIsZkDeviceResponse.
func TestDetectCredentialFormat_MDocZk(t *testing.T) {
	wrapped, err := mdoc.WrapInEncodedCBOR(mdoc.ZkDocumentDataMdoc{
		ZkSystemID: "longfellow-libzk-v1_8_1_4259_2945",
		DocType:    mdoc.DocType,
		Timestamp:  mdoc.TDate("2026-08-17T00:00:00Z"),
		IssuerSigned: map[string][]mdoc.ZkSignedItemMdoc{
			mdoc.Namespace: {{ElementIdentifier: "given_name", ElementValue: "John"}},
		},
	})
	require.NoError(t, err)

	response := &mdoc.DeviceResponseMdoc{
		Version: "1.0",
		Status:  0,
		ZkDocuments: []mdoc.ZkDocumentMdoc{
			{Proof: []byte{0x01, 0x02}, DocumentData: wrapped},
		},
	}
	data, err := mdoc.EncodeDeviceResponse(response)
	require.NoError(t, err)

	vpToken := base64.RawURLEncoding.EncodeToString(data)
	assert.Equal(t, FormatMDocZK, detectCredentialFormat(vpToken))
}

// TestDetectCredentialFormat_PlainMDoc confirms detectCredentialFormat still
// classifies a plain (non-ZK) mso_mdoc DeviceResponse as FormatMDoc, not
// FormatMDocZK - i.e. the new zkDocuments peek is additive and doesn't
// misclassify existing traffic.
func TestDetectCredentialFormat_PlainMDoc(t *testing.T) {
	response := &mdoc.DeviceResponseMdoc{Version: "1.0", Status: 0}
	data, err := mdoc.EncodeDeviceResponse(response)
	require.NoError(t, err)

	vpToken := base64.RawURLEncoding.EncodeToString(data)
	assert.Equal(t, FormatMDoc, detectCredentialFormat(vpToken))
}

func TestDetectCredentialFormat_Unknown(t *testing.T) {
	assert.Equal(t, FormatUnknown, detectCredentialFormat("not valid base64!!!"))
}

// TestDetectCredentialFormat_VC20 pins W3C VC 2.0 detection, and the ordering
// it depends on.
//
// A JSON-LD credential is a JSON object, plain or base64url-wrapped. The mdoc
// branch base64-decodes anything without dots or tildes, so a wrapped JSON
// body would be claimed as CBOR before anything looked at it - the JSON test
// has to come first.
func TestDetectCredentialFormat_VC20(t *testing.T) {
	const credential = `{"@context":["https://www.w3.org/ns/credentials/v2"],` +
		`"type":["VerifiableCredential","UniversityDegreeCredential"],` +
		`"issuer":"did:example:issuer","credentialSubject":{"degree":"Master of Science"}}`

	t.Run("plain JSON-LD", func(t *testing.T) {
		assert.Equal(t, FormatVC20, detectCredentialFormat(credential))
	})

	t.Run("leading whitespace", func(t *testing.T) {
		assert.Equal(t, FormatVC20, detectCredentialFormat("\n  "+credential))
	})

	t.Run("base64url-wrapped, which the mdoc branch would have claimed", func(t *testing.T) {
		assert.Equal(t, FormatVC20,
			detectCredentialFormat(base64.RawURLEncoding.EncodeToString([]byte(credential))))
	})

	t.Run("the other formats still classify", func(t *testing.T) {
		assert.Equal(t, FormatSDJWT, detectCredentialFormat("eyJhbGciOiJFUzI1NiJ9.e30.sig~disclosure~"))
		assert.Equal(t, FormatSDJWT, detectCredentialFormat("eyJhbGciOiJFUzI1NiJ9.e30.sig"))
		assert.Equal(t, FormatUnknown, detectCredentialFormat("not a credential at all"))
	})
}
