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
