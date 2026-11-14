package mdoc

import (
	"crypto/elliptic"
	"encoding/base64"
	"testing"
	"time"
)

// issueStatusMDoc issues an mdoc, optionally with a status reference, and returns it as a VP token.
func issueStatusMDoc(t *testing.T, status *MSOStatusList) (token string, h *MDocHandler) {
	t.Helper()

	trustEvaluator, _, dsKey, certChain := createTestTrustList(t)
	issuer, err := NewIssuer(IssuerConfig{SignerKey: dsKey, CertificateChain: certChain, DefaultValidity: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	deviceKey, err := GenerateDeviceKeyPair(elliptic.P256())
	if err != nil {
		t.Fatal(err)
	}
	issued, err := issuer.Issue(&IssuanceRequest{
		DocumentData:    testMDLDocumentData(t),
		DevicePublicKey: &deviceKey.PublicKey,
		Schema:          testMDLSchema(),
		Status:          status,
	})
	if err != nil {
		t.Fatal(err)
	}

	encoder, err := NewCBOREncoder()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := encoder.Marshal(issued.DocumentMdoc)
	if err != nil {
		t.Fatal(err)
	}

	h, err = NewMDocHandler(WithMDocTrustEvaluator(trustEvaluator))
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), h
}

// The status in the signed MSO must reach the extracted claims, or the verifier has nothing to check.
func TestMDocHandler_VerifyAndExtract_CarriesMSOStatus(t *testing.T) {
	const uri = "https://registry.example.com/statuslists/3"

	t.Run("status reference is returned", func(t *testing.T) {
		token, h := issueStatusMDoc(t, &MSOStatusList{URI: uri, Idx: 42})

		result, err := h.VerifyAndExtract(t.Context(), token)
		if err != nil {
			t.Fatalf("VerifyAndExtract() error = %v", err)
		}
		claims := result.Documents["org.iso.18013.5.1.mDL"]
		if claims == nil {
			t.Fatalf("no mDL document in %v", result.Documents)
		}
		if claims.Status == nil || claims.Status.StatusList == nil {
			t.Fatal("extracted claims carry no status")
		}
		if got := claims.Status.StatusList; got.URI != uri || got.Idx != 42 {
			t.Errorf("status = %+v, want uri %q idx 42", got, uri)
		}
	})

	t.Run("legacy credential has none", func(t *testing.T) {
		token, h := issueStatusMDoc(t, nil)

		result, err := h.VerifyAndExtract(t.Context(), token)
		if err != nil {
			t.Fatalf("VerifyAndExtract() error = %v", err)
		}
		if got := result.Documents["org.iso.18013.5.1.mDL"].Status; got != nil {
			t.Errorf("status = %+v, want none", got)
		}
	})
}
