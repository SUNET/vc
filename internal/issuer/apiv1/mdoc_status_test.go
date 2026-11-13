package apiv1

import (
	"testing"

	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/SUNET/vc/pkg/logger"
)

const statusTestMDDL = `{
	"format": "mso_mdoc",
	"doctype": "org.iso.18013.5.1.mDL",
	"claims": {"org.iso.18013.5.1": {
		"family_name": {"mandatory": true, "value_type": "tstr"}
	}}
}`

// issuedMSOStatus issues an mdoc and returns the status in its signature-verified MSO.
func issuedMSOStatus(t *testing.T, c *Client) *mdoc.MSOStatus {
	t.Helper()

	tracer, err := trace.NewForTesting(t.Context(), "test", logger.NewSimple("trace"))
	if err != nil {
		t.Fatal(err)
	}
	c.tracer = tracer
	c.cfg = &model.Cfg{Issuer: &model.Issuer{}}
	c.mdocIssuer = testMDocIssuer(t)

	reply, err := c.MakeMDoc(t.Context(), &CreateMDocRequest{
		Scope:           "mdl",
		DocumentData:    []byte(`{"family_name":"Andersson"}`),
		DevicePublicKey: testDeviceKeyDER(t),
		DeviceKeyFormat: "der",
		MDDL:            []byte(statusTestMDDL),
	})
	if err != nil {
		t.Fatalf("MakeMDoc() error = %v", err)
	}

	encoder, err := mdoc.NewCBOREncoder()
	if err != nil {
		t.Fatal(err)
	}
	var response mdoc.DeviceResponseMdoc
	if err := encoder.Unmarshal(reply.MDoc, &response); err != nil {
		t.Fatalf("decode issued mdoc: %v", err)
	}
	if len(response.Documents) != 1 {
		t.Fatalf("Documents = %d, want 1", len(response.Documents))
	}
	issuerAuth, ok := response.Documents[0].IssuerSigned.IssuerAuth.([]any)
	if !ok || len(issuerAuth) != 4 {
		t.Fatalf("unexpected IssuerAuth %T", response.Documents[0].IssuerSigned.IssuerAuth)
	}

	cert := c.mdocIssuer.CertificateChain()[0]
	sign1 := &mdoc.COSESign1{}
	sign1.Protected, _ = issuerAuth[0].([]byte)
	sign1.Payload, _ = issuerAuth[2].([]byte)
	sign1.Signature, _ = issuerAuth[3].([]byte)
	mso, err := mdoc.VerifyMSO(sign1, cert)
	if err != nil {
		t.Fatalf("VerifyMSO() error = %v", err)
	}
	return mso.Status
}

// The status entry the registry allocated must end up in the signed MSO,
// or the verifier has nothing to check.
func TestMakeMDocEmbedsAllocatedStatus(t *testing.T) {
	c := &Client{
		log:            logger.NewSimple("test"),
		registryClient: &mockRegistryClient{section: 3},
	}

	got := issuedMSOStatus(t, c)
	if got == nil || got.StatusList == nil {
		t.Fatal("signed MSO carries no status")
	}
	if want := "https://test-registry.sunet.se/statuslists/3"; got.StatusList.URI != want {
		t.Errorf("status uri = %q, want %q", got.StatusList.URI, want)
	}
	if got.StatusList.Idx != 1 {
		t.Errorf("status idx = %d, want 1 (first allocation)", got.StatusList.Idx)
	}
}

func TestMakeMDocWithoutRegistryHasNoStatus(t *testing.T) {
	c := &Client{log: logger.NewSimple("test")}

	if got := issuedMSOStatus(t, c); got != nil {
		t.Errorf("MSO status = %+v, want none without a registry", got)
	}
}
