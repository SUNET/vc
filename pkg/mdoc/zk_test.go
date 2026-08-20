package mdoc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func createTestZkCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test ZK DS"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	return cert
}

func buildTestZkDocumentData(t *testing.T, cert *x509.Certificate, zkSystemID string, includePseudonym bool) ZkDocumentDataMdoc {
	t.Helper()

	issuerSigned := map[string][]ZkSignedItemMdoc{
		Namespace: {
			{ElementIdentifier: "given_name", ElementValue: "John"},
		},
	}
	if includePseudonym {
		issuerSigned[Namespace] = append(issuerSigned[Namespace], ZkSignedItemMdoc{
			ElementIdentifier: PseudonymClaimIdentifier,
			ElementValue:      []byte("0123456789abcdef0123456789abcdef"[:32]),
		})
	}

	return ZkDocumentDataMdoc{
		ZkSystemID:   zkSystemID,
		DocType:      DocType,
		Timestamp:    TDate(time.Now().UTC().Format("2006-01-02T15:04:05Z")),
		IssuerSigned: issuerSigned,
		MsoX5Chain:   cert.Raw,
	}
}

func encodeTestZkDeviceResponse(t *testing.T, dd ZkDocumentDataMdoc, proof []byte) []byte {
	t.Helper()

	wrapped, err := WrapInEncodedCBOR(dd)
	if err != nil {
		t.Fatalf("WrapInEncodedCBOR() error = %v", err)
	}

	response := &DeviceResponseMdoc{
		Version: "1.0",
		Status:  0,
		ZkDocuments: []ZkDocumentMdoc{
			{Proof: proof, DocumentData: wrapped},
		},
	}

	data, err := EncodeDeviceResponse(response)
	if err != nil {
		t.Fatalf("EncodeDeviceResponse() error = %v", err)
	}
	return data
}

func TestPeekIsZkDeviceResponse_ZkResponse(t *testing.T) {
	cert := createTestZkCert(t)
	dd := buildTestZkDocumentData(t, cert, "longfellow-libzk-v1_8_1_4259_2945", false)
	data := encodeTestZkDeviceResponse(t, dd, []byte{0x01, 0x02, 0x03})

	isZK, err := PeekIsZkDeviceResponse(data)
	if err != nil {
		t.Fatalf("PeekIsZkDeviceResponse() error = %v", err)
	}
	if !isZK {
		t.Errorf("PeekIsZkDeviceResponse() = false, want true")
	}
}

func TestPeekIsZkDeviceResponse_PlainMdoc(t *testing.T) {
	// A plain DeviceResponse with no zkDocuments at all.
	response := &DeviceResponseMdoc{Version: "1.0", Status: 0}
	data, err := EncodeDeviceResponse(response)
	if err != nil {
		t.Fatalf("EncodeDeviceResponse() error = %v", err)
	}

	isZK, err := PeekIsZkDeviceResponse(data)
	if err != nil {
		t.Fatalf("PeekIsZkDeviceResponse() error = %v", err)
	}
	if isZK {
		t.Errorf("PeekIsZkDeviceResponse() = true, want false")
	}
}

func TestPeekIsZkDeviceResponse_Garbage(t *testing.T) {
	if _, err := PeekIsZkDeviceResponse([]byte{0xff, 0xff, 0xff}); err == nil {
		t.Error("PeekIsZkDeviceResponse() expected error for garbage input, got nil")
	}
}

func TestZkDocumentMdoc_ParseZkDocumentData_RoundTrip(t *testing.T) {
	cert := createTestZkCert(t)
	want := buildTestZkDocumentData(t, cert, "longfellow-libzk-v1_8_1_4259_2945", true)
	data := encodeTestZkDeviceResponse(t, want, []byte{0xAA, 0xBB})

	response, err := DecodeDeviceResponse(data)
	if err != nil {
		t.Fatalf("DecodeDeviceResponse() error = %v", err)
	}
	if len(response.ZkDocuments) != 1 {
		t.Fatalf("len(ZkDocuments) = %d, want 1", len(response.ZkDocuments))
	}

	got, err := response.ZkDocuments[0].ParseZkDocumentData()
	if err != nil {
		t.Fatalf("ParseZkDocumentData() error = %v", err)
	}

	if got.ZkSystemID != want.ZkSystemID {
		t.Errorf("ZkSystemID = %q, want %q", got.ZkSystemID, want.ZkSystemID)
	}
	if got.DocType != want.DocType {
		t.Errorf("DocType = %q, want %q", got.DocType, want.DocType)
	}
	if string(got.Timestamp) != string(want.Timestamp) {
		t.Errorf("Timestamp = %q, want %q", got.Timestamp, want.Timestamp)
	}

	claims := got.FlattenIssuerSigned()
	if claims[Namespace]["given_name"] != "John" {
		t.Errorf("given_name = %v, want John", claims[Namespace]["given_name"])
	}
	pseudonym, ok := claims[Namespace][PseudonymClaimIdentifier].([]byte)
	if !ok || len(pseudonym) != 32 {
		t.Errorf("pairwise_pseudonym = %v, want 32 bytes", claims[Namespace][PseudonymClaimIdentifier])
	}

	certs, err := got.X5ChainCertificates()
	if err != nil {
		t.Fatalf("X5ChainCertificates() error = %v", err)
	}
	if len(certs) != 1 || certs[0].SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Errorf("X5ChainCertificates() = %v, want [%v]", certs, cert)
	}
}

func TestZkDocumentDataMdoc_X5ChainCertificates_Chain(t *testing.T) {
	cert1 := createTestZkCert(t)
	cert2 := createTestZkCert(t)
	dd := ZkDocumentDataMdoc{MsoX5Chain: [][]byte{cert1.Raw, cert2.Raw}}

	certs, err := dd.X5ChainCertificates()
	if err != nil {
		t.Fatalf("X5ChainCertificates() error = %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("len(certs) = %d, want 2", len(certs))
	}
}

func TestZkDocumentDataMdoc_X5ChainCertificates_Missing(t *testing.T) {
	dd := ZkDocumentDataMdoc{}
	if _, err := dd.X5ChainCertificates(); err == nil {
		t.Error("X5ChainCertificates() expected error for missing msoX5chain, got nil")
	}
}

func TestZkDocumentDataMdoc_FlattenDeviceSigned(t *testing.T) {
	dd := ZkDocumentDataMdoc{
		DeviceSigned: map[string][]ZkSignedItemMdoc{
			Namespace: {{ElementIdentifier: "some_device_claim", ElementValue: "x"}},
		},
	}
	flat := dd.FlattenDeviceSigned()
	if flat[Namespace]["some_device_claim"] != "x" {
		t.Errorf("FlattenDeviceSigned() = %v", flat)
	}
}
