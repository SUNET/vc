package apiv1

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/mdoc/zkcircuit"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/fxamacker/cbor/v2"
)

const vegaManifest = `{"circuits":[{"id":"vega-r12","system":"vega-mc","status":"active","published":true,` +
	`"docTypes":["org.iso.18013.5.1.mDL"],"params":{"saltBytes":"32"}}]}`

// saltClient is a Client carrying only what resolveZkSaltBytes touches.
// body is the manifest a fetch returns; a nil body makes every fetch fail.
func saltClient(t *testing.T, body string) *Client {
	t.Helper()
	c := &Client{log: logger.NewSimple("test")}
	if body == "" {
		return c
	}
	catalog := &zkcircuit.Client{
		Sources: []string{"https://catalog.example"},
		FetchText: func(context.Context, string) (string, error) {
			if body == "fail" {
				return "", errors.New("catalog unreachable")
			}
			return body, nil
		},
	}
	c.zkResolver = zkcircuit.NewResolver(catalog)
	return c
}

func schema(systems []string, pin int) *mdoc.MDDLSchema {
	return &mdoc.MDDLSchema{
		Format:      "mso_mdoc",
		DocType:     "org.iso.18013.5.1.mDL",
		ZkSystems:   systems,
		ZkSaltBytes: pin,
	}
}

// A schema that declares no zk_systems is not asking. Its zk_salt_bytes -
// usually zero - is used as-is, which is every non-ZK mdoc in the tree.
func TestResolveZkSaltBytesLeavesANonZKSchemaAlone(t *testing.T) {
	c := saltClient(t, vegaManifest)

	for _, pin := range []int{0, 32} {
		got, err := c.resolveZkSaltBytes(t.Context(), schema(nil, pin))
		if err != nil || got != pin {
			t.Fatalf("resolveZkSaltBytes(pin=%d) = %d, %v; want %d, nil", pin, got, err, pin)
		}
	}
}

// The point of the whole path: the number comes from the circuit, not from
// a schema that hand-copied it once and cannot notice it going stale.
func TestResolveZkSaltBytesReadsTheCatalog(t *testing.T) {
	c := saltClient(t, vegaManifest)

	got, err := c.resolveZkSaltBytes(t.Context(), schema([]string{"vega-mc"}, 0))
	if err != nil {
		t.Fatalf("resolveZkSaltBytes() error = %v", err)
	}
	if got != 32 {
		t.Errorf("salt bytes = %d, want 32 from the catalog", got)
	}
}

// A pin is for the cases the catalog cannot serve - an air-gapped issuer,
// interop against a circuit that is not published yet - so it wins. What
// it must not do is win quietly, which the Error log line is for.
func TestResolveZkSaltBytesPinOverridesTheCatalog(t *testing.T) {
	c := saltClient(t, vegaManifest)

	got, err := c.resolveZkSaltBytes(t.Context(), schema([]string{"vega-mc"}, 16))
	if err != nil {
		t.Fatalf("resolveZkSaltBytes() error = %v", err)
	}
	if got != 16 {
		t.Errorf("salt bytes = %d, want the pinned 16", got)
	}
}

// Fail closed. Minting a credential whose salt length is a guess produces
// one that fails in the wallet's hands at presentation time, with an error
// that says nothing about why.
func TestResolveZkSaltBytesRefusesWhenItCannotResolve(t *testing.T) {
	tests := map[string]struct {
		body    string
		systems []string
		want    string
	}{
		"catalog unreachable and nothing pinned": {
			body:    "fail",
			systems: []string{"vega-mc"},
			want:    "circuit catalog",
		},
		"no sources configured and nothing pinned": {
			body:    "",
			systems: []string{"vega-mc"},
			want:    "issuer.zk_circuits.sources is empty",
		},
		"a system the catalog does not publish": {
			body:    vegaManifest,
			systems: []string{"nonesuch"},
			want:    "no active circuit",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			c := saltClient(t, tc.body)
			_, err := c.resolveZkSaltBytes(t.Context(), schema(tc.systems, 0))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want one containing %q", err, tc.want)
			}
		})
	}
}

// The other side of the same coin: a pin is exactly what keeps issuance
// alive when the catalog cannot answer, so it must not refuse there.
func TestResolveZkSaltBytesFallsBackToThePinWhenTheCatalogIsUnreachable(t *testing.T) {
	for name, body := range map[string]string{
		"catalog unreachable":   "fail",
		"no sources configured": "",
	} {
		t.Run(name, func(t *testing.T) {
			c := saltClient(t, body)
			got, err := c.resolveZkSaltBytes(t.Context(), schema([]string{"vega-mc"}, 32))
			if err != nil {
				t.Fatalf("resolveZkSaltBytes() error = %v", err)
			}
			if got != 32 {
				t.Errorf("salt bytes = %d, want the pinned 32", got)
			}
		})
	}
}

func TestNewZkCircuitResolverIsNilWithoutSources(t *testing.T) {
	if r := newZkCircuitResolver(nil, 0); r != nil {
		t.Error("no configured sources should leave the issuer without a resolver")
	}
	if r := newZkCircuitResolver([]string{"https://catalog.example"}, 0); r == nil {
		t.Error("a configured source should produce a resolver")
	}
}

// testMDocIssuer builds a real mdoc issuer over a self-signed P-256
// document-signer certificate, so MakeMDoc below exercises the production
// path rather than a stand-in.
func testMDocIssuer(t *testing.T) *mdoc.Issuer {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test document signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	issuer, err := mdoc.NewIssuer(mdoc.IssuerConfig{
		SignerKey:        key,
		CertificateChain: []*x509.Certificate{cert},
	})
	if err != nil {
		t.Fatal(err)
	}
	return issuer
}

func testDeviceKeyDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// issuedSaltLengths decodes a MakeMDoc reply and reports each claim's
// IssuerSignedItem salt length.
func issuedSaltLengths(t *testing.T, mdocCBOR []byte, namespace string) map[string]int {
	t.Helper()

	encoder, err := mdoc.NewCBOREncoder()
	if err != nil {
		t.Fatal(err)
	}
	var response mdoc.DeviceResponseMdoc
	if err := encoder.Unmarshal(mdocCBOR, &response); err != nil {
		t.Fatalf("decode issued mdoc: %v", err)
	}
	if len(response.Documents) != 1 {
		t.Fatalf("Documents = %d, want 1", len(response.Documents))
	}

	lengths := map[string]int{}
	for _, anyItem := range response.Documents[0].IssuerSigned.NameSpaces[namespace] {
		tag, ok := anyItem.(cbor.Tag)
		if !ok {
			t.Fatalf("unexpected item type %T in NameSpaces", anyItem)
		}
		content, ok := tag.Content.([]byte)
		if !ok {
			t.Fatalf("tag content is not []byte")
		}
		var item mdoc.IssuerSignedItem
		if err := cbor.Unmarshal(content, &item); err != nil {
			t.Fatalf("decode IssuerSignedItem: %v", err)
		}
		lengths[item.ElementIdentifier] = len(item.Random)
	}
	return lengths
}

// The end of the chain, and the one that matters: a schema that declares
// zk_systems and pins nothing is issued with the salt length the CATALOG
// publishes, right down to the bytes in the signed document.
//
// Deliberately resolves to 8 rather than 32. Both of this package's own
// defaults - 16 for a claim, 8 for pseudonym_seed - would otherwise be
// indistinguishable from a resolved answer for at least one claim, and a
// test that passes when the resolution is removed is not a test. 8 is a
// catalog answer that must now apply to EVERY claim, including the
// 16-byte-by-default ones.
func TestMakeMDocSizesSaltsFromTheCatalog(t *testing.T) {
	const catalogSalt = 8
	manifest := `{"circuits":[{"id":"vega-x","system":"vega-mc","status":"active","published":true,` +
		`"docTypes":["org.iso.18013.5.1.mDL"],"params":{"saltBytes":"8"}}]}`

	tracer, err := trace.NewForTesting(t.Context(), "test", logger.NewSimple("trace"))
	if err != nil {
		t.Fatal(err)
	}

	c := saltClient(t, manifest)
	c.tracer = tracer
	c.cfg = &model.Cfg{Issuer: &model.Issuer{}}
	c.mdocIssuer = testMDocIssuer(t)

	reply, err := c.MakeMDoc(t.Context(), &CreateMDocRequest{
		Scope:           "mdl_zk",
		DocumentData:    []byte(`{"family_name":"Andersson","given_name":"Erik","pseudonym_seed":"` + base64.StdEncoding.EncodeToString(make([]byte, 32)) + `"}`),
		DevicePublicKey: testDeviceKeyDER(t),
		DeviceKeyFormat: "der",
		MDDL: []byte(`{
			"format": "mso_mdoc",
			"doctype": "org.iso.18013.5.1.mDL",
			"zk_systems": ["vega-mc"],
			"claims": {"org.iso.18013.5.1": {
				"family_name": {"mandatory": true, "value_type": "tstr"},
				"given_name": {"mandatory": true, "value_type": "tstr"},
				"pseudonym_seed": {"value_type": "bstr"}
			}}
		}`),
	})
	if err != nil {
		t.Fatalf("MakeMDoc() error = %v", err)
	}

	lengths := issuedSaltLengths(t, reply.MDoc, "org.iso.18013.5.1")
	for _, elementID := range []string{"family_name", "given_name", "pseudonym_seed"} {
		got, ok := lengths[elementID]
		if !ok {
			t.Fatalf("claim %q missing from the issued document", elementID)
		}
		if got != catalogSalt {
			t.Errorf("%s: salt length = %d, want %d from the catalog", elementID, got, catalogSalt)
		}
	}
}
