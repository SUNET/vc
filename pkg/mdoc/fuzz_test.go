package mdoc

import (
	"testing"
)

// FuzzDecodeDeviceEngagement fuzzes CBOR decoding of device engagement.
// Device engagement is received from untrusted devices via QR code or NFC.
func FuzzDecodeDeviceEngagement(f *testing.F) {
	// Minimal valid-ish CBOR map
	f.Add([]byte{0xa0})                               // empty CBOR map
	f.Add([]byte{0xa1, 0x00, 0x63, 0x31, 0x2e, 0x30}) // {"0": "1.0"}
	f.Add([]byte{})
	f.Add([]byte{0xff}) // invalid CBOR
	f.Add([]byte{0x00})
	f.Add(make([]byte, 256)) // large zero block

	f.Fuzz(func(t *testing.T, data []byte) {
		de, err := DecodeDeviceEngagement(data)
		if err != nil {
			return
		}
		if de == nil {
			t.Fatal("DecodeDeviceEngagement returned nil without error")
		}
	})
}

// FuzzDecodeDeviceResponse fuzzes CBOR decoding of mdoc device responses.
// These are received from untrusted holder devices during presentation.
func FuzzDecodeDeviceResponse(f *testing.F) {
	f.Add([]byte{0xa0})
	f.Add([]byte{})
	f.Add([]byte{0xff})
	f.Add([]byte{0xa1, 0x67, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x63, 0x31, 0x2e, 0x30}) // {"version":"1.0"}

	f.Fuzz(func(t *testing.T, data []byte) {
		resp, err := DecodeDeviceResponse(data)
		if err != nil {
			return
		}
		if resp == nil {
			t.Fatal("DecodeDeviceResponse returned nil without error")
		}
	})
}

// FuzzParseQRCode fuzzes QR code parsing of device engagement strings.
func FuzzParseQRCode(f *testing.F) {
	f.Add("mdoc:oRCA")
	f.Add("mdoc:")
	f.Add("")
	f.Add("mdoc:!!!invalid-base64!!!")
	f.Add("not-mdoc:abc")

	f.Fuzz(func(t *testing.T, qrData string) {
		de, err := ParseQRCode(qrData)
		if err != nil {
			return
		}
		if de == nil {
			t.Fatal("ParseQRCode returned nil without error")
		}
	})
}

// FuzzCOSESign1UnmarshalCBOR fuzzes COSE_Sign1 CBOR unmarshaling.
// COSE structures are embedded in mdoc issuer-signed data.
func FuzzCOSESign1UnmarshalCBOR(f *testing.F) {
	// CBOR array with 4 elements (COSE_Sign1 structure)
	f.Add([]byte{0x84, 0x40, 0xa0, 0x40, 0x40}) // [h'', {}, h'', h'']
	f.Add([]byte{})
	f.Add([]byte{0xff})

	f.Fuzz(func(t *testing.T, data []byte) {
		var s COSESign1
		_ = s.UnmarshalCBOR(data)
	})
}
