package mdoc

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLookupUnprotectedHeader_LabelRepresentations pins every spelling of a
// COSE header label we are willing to read.
//
// The integer forms differ only by how the value reached us: cbor.Unmarshal
// into an any-typed map yields uint64, a map built in Go code yields int or
// int64. The decimal-string form is not valid COSE and is accepted only
// defensively - see the note on lookupUnprotectedHeader.
func TestLookupUnprotectedHeader_LabelRepresentations(t *testing.T) {
	want := []byte("chain")

	tests := []struct {
		name string
		key  any
	}{
		{"int64 label, as built in Go", int64(33)},
		{"uint64 label, as decoded from CBOR", uint64(33)},
		{"int label", 33},
		{"decimal string label, from a holder with string-only keys", "33"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := lookupUnprotectedHeader(map[any]any{tt.key: want}, HeaderX5Chain)
			require.True(t, ok, "label %#v must resolve", tt.key)
			assert.Equal(t, want, got)
		})
	}

	t.Run("an unrelated label does not resolve", func(t *testing.T) {
		_, ok := lookupUnprotectedHeader(map[any]any{"x5chain": want}, HeaderX5Chain)
		assert.False(t, ok, "only the numeric label and its decimal spelling are x5chain")
	})

	t.Run("a near-miss numeric string does not resolve", func(t *testing.T) {
		_, ok := lookupUnprotectedHeader(map[any]any{"330": want}, HeaderX5Chain)
		assert.False(t, ok)
	})
}

// TestGetCertificateChainFromSign1_StringLabel is the regression test for the
// real failure this guards against.
//
// x5chain moved from the protected header to the unprotected one to match RFC
// 9360. The protected header is an opaque byte string, so its integer labels
// survive anything that reserializes the surrounding structure; the
// unprotected header is a live CBOR map and does not. A holder that decodes a
// stored credential into string-keyed structures and re-encodes it at
// presentation time therefore turns label 33 into "33" - and because the
// unprotected header is not covered by the signature, it does so without any
// signature failure. The result was a verifier reporting "no x5chain in
// headers" for a credential whose certificates were present all along.
func TestGetCertificateChainFromSign1_StringLabel(t *testing.T) {
	chainDER := realIssuerAuthChain(t)

	t.Run("integer label", func(t *testing.T) {
		sign1 := &COSESign1{
			Protected:   mustMarshalProtectedAlg(t),
			Unprotected: map[any]any{uint64(33): toAnySlice(chainDER)},
		}
		certs, err := GetCertificateChainFromSign1(sign1)
		require.NoError(t, err)
		require.Len(t, certs, 2)
	})

	t.Run("string label", func(t *testing.T) {
		sign1 := &COSESign1{
			Protected:   mustMarshalProtectedAlg(t),
			Unprotected: map[any]any{"33": toAnySlice(chainDER)},
		}
		certs, err := GetCertificateChainFromSign1(sign1)
		require.NoError(t, err, "a string-spelled label must still yield the chain")
		require.Len(t, certs, 2)
		assert.Equal(t, "creds", certs[1].Subject.CommonName)
	})

	t.Run("genuinely absent", func(t *testing.T) {
		sign1 := &COSESign1{
			Protected:   mustMarshalProtectedAlg(t),
			Unprotected: map[any]any{},
		}
		_, err := GetCertificateChainFromSign1(sign1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no x5chain in headers")
	})
}

// TestRealVPTokenWithStringX5ChainLabel runs an actual vp_token produced by
// the stack, whose issuerAuth carries the string-spelled label. Synthetic
// cases prove the lookup handles the shape; this proves we handle the token
// that was failing in testing.
func TestRealVPTokenWithStringX5ChainLabel(t *testing.T) {
	sign1, deviceSigned := realVPTokenSign1(t)

	// The defect is confined to the issuer's header. The device signature is
	// created fresh at presentation and keeps its integer labels, which is
	// what localises this to the holder's credential storage rather than to
	// the transport carrying the response.
	require.NotNil(t, deviceSigned)
	for k := range deviceSigned {
		assert.IsType(t, uint64(0), k,
			"deviceSignature labels are untouched, so the response envelope is not the culprit")
	}

	var sawStringLabel bool
	for k := range sign1.Unprotected {
		if s, ok := k.(string); ok && s == "33" {
			sawStringLabel = true
		}
	}
	require.True(t, sawStringLabel, "fixture must still exhibit the defect it guards against")

	certs, err := GetCertificateChainFromSign1(sign1)
	require.NoError(t, err, "this token previously failed with \"no x5chain in headers\"")
	require.Len(t, certs, 2)
	// Compared as a slice so a changed subject encoding fails the assertion
	// rather than panicking on an empty one. The value is a domain because
	// the issuer populates countryName with one - noted, not asserted upon
	// beyond pinning the fixture's identity.
	assert.Equal(t, []string{"native-dcapi-test.issuer.id.siros.org"}, certs[0].Subject.Country,
		"leaf is the issuing signer")
	assert.Equal(t, "creds", certs[1].Subject.CommonName, "followed by its CA")
}

// realVPTokenSign1 decodes the stored vp_token and returns the issuerAuth as
// a COSESign1 plus the deviceSignature's unprotected header.
func realVPTokenSign1(t *testing.T) (*COSESign1, map[any]any) {
	t.Helper()

	b64, err := os.ReadFile("testdata/vp_token_string_x5chain_label.b64")
	require.NoError(t, err)
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(b64)))
	require.NoError(t, err)

	var resp struct {
		Documents []struct {
			IssuerSigned struct {
				IssuerAuth []any `cbor:"issuerAuth"`
			} `cbor:"issuerSigned"`
			DeviceSigned struct {
				DeviceAuth struct {
					DeviceSignature []any `cbor:"deviceSignature"`
				} `cbor:"deviceAuth"`
			} `cbor:"deviceSigned"`
		} `cbor:"documents"`
	}
	require.NoError(t, cbor.Unmarshal(raw, &resp))
	require.Len(t, resp.Documents, 1)

	// Assert each element's type rather than discarding the ok result: a
	// changed fixture shape would otherwise yield nils here and surface as a
	// confusing panic further down, instead of failing at the decode step.
	ia := resp.Documents[0].IssuerSigned.IssuerAuth
	require.Len(t, ia, 4)
	protected, ok := ia[0].([]byte)
	require.True(t, ok, "issuerAuth[0] (protected) must be a byte string")
	unprotected, ok := ia[1].(map[any]any)
	require.True(t, ok, "issuerAuth[1] (unprotected) must be a map")
	payload, ok := ia[2].([]byte)
	require.True(t, ok, "issuerAuth[2] (payload) must be a byte string")
	signature, ok := ia[3].([]byte)
	require.True(t, ok, "issuerAuth[3] (signature) must be a byte string")

	ds := resp.Documents[0].DeviceSigned.DeviceAuth.DeviceSignature
	require.Len(t, ds, 4)
	dsUnprotected, ok := ds[1].(map[any]any)
	require.True(t, ok, "deviceSignature[1] (unprotected) must be a map")

	return &COSESign1{
		Protected:   protected,
		Unprotected: unprotected,
		Payload:     payload,
		Signature:   signature,
	}, dsUnprotected
}

// realIssuerAuthChain pulls the DER certificates out of the stored token so
// the synthetic cases above use real certificates rather than stubs.
func realIssuerAuthChain(t *testing.T) [][]byte {
	t.Helper()
	sign1, _ := realVPTokenSign1(t)
	raw, ok := lookupUnprotectedHeader(sign1.Unprotected, HeaderX5Chain)
	require.True(t, ok)
	entries, ok := raw.([]any)
	require.True(t, ok)
	out := make([][]byte, 0, len(entries))
	for _, e := range entries {
		der, ok := e.([]byte)
		require.True(t, ok)
		out = append(out, der)
	}
	return out
}

func toAnySlice(in [][]byte) []any {
	out := make([]any, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}

func mustMarshalProtectedAlg(t *testing.T) []byte {
	t.Helper()
	b, err := cbor.Marshal(map[int64]any{HeaderAlgorithm: AlgorithmES256})
	require.NoError(t, err)
	return b
}
