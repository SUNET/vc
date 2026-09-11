package samlsp

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestSanitizePrintableStrings_RewritesTagWhenValueHasNonASCII(t *testing.T) {
	// Minimal SEQUENCE { SET { SEQUENCE { OID(2.5.4.10) PrintableString "å" } } }
	// OID 2.5.4.10 = organizationName: 0x06 0x03 0x55 0x04 0x0A
	// å in UTF-8 = 0xC3 0xA5
	oid := []byte{0x06, 0x03, 0x55, 0x04, 0x0A}
	printableAA := []byte{0x13, 0x02, 0xC3, 0xA5}
	inner := append([]byte{}, oid...)
	inner = append(inner, printableAA...)
	sequence := append([]byte{0x30, byte(len(inner))}, inner...)
	set := append([]byte{0x31, byte(len(sequence))}, sequence...)
	outer := append([]byte{0x30, byte(len(set))}, set...)

	got := sanitizePrintableStrings(outer)

	if !bytes.Contains(got, []byte{0x0C, 0x02, 0xC3, 0xA5}) {
		t.Fatalf("expected PrintableString tag 0x13 rewritten to UTF8String 0x0C; got %x", got)
	}
	if bytes.Contains(got, []byte{0x13, 0x02, 0xC3, 0xA5}) {
		t.Errorf("original 0x13 tag with non-ASCII bytes should be gone; got %x", got)
	}
}

func TestSanitizePrintableStrings_LeavesASCIIUntouched(t *testing.T) {
	// PrintableString "SE" — pure ASCII, must NOT be rewritten.
	printableSE := []byte{0x13, 0x02, 'S', 'E'}
	sequence := append([]byte{0x30, byte(len(printableSE))}, printableSE...)

	got := sanitizePrintableStrings(sequence)

	if got[2] != 0x13 {
		t.Errorf("ASCII PrintableString must keep tag 0x13; got %#x", got[2])
	}
}

func TestSanitizeMetadataCerts_RewritesEmbeddedCert(t *testing.T) {
	// Same "bad" cert-like DER as above, base64 encoded, wrapped in an
	// X509Certificate element with a namespace prefix.
	oid := []byte{0x06, 0x03, 0x55, 0x04, 0x0A}
	printableAA := []byte{0x13, 0x02, 0xC3, 0xA5}
	inner := append([]byte{}, oid...)
	inner = append(inner, printableAA...)
	sequence := append([]byte{0x30, byte(len(inner))}, inner...)
	set := append([]byte{0x31, byte(len(sequence))}, sequence...)
	outer := append([]byte{0x30, byte(len(set))}, set...)
	b64 := base64.StdEncoding.EncodeToString(outer)

	xmlIn := []byte(`<KeyInfo xmlns="urn:ns"><X509Data><X509Certificate>` + b64 + `</X509Certificate></X509Data></KeyInfo>`)

	xmlOut := sanitizeMetadataCerts(xmlIn)

	if !strings.Contains(string(xmlOut), "X509Certificate") {
		t.Fatalf("output lost X509Certificate element: %s", xmlOut)
	}
	if bytes.Equal(xmlOut, xmlIn) {
		t.Fatalf("output must differ from input when cert bytes needed rewriting")
	}
	// Every byte outside the base64 payload must be preserved.
	prefix := `<KeyInfo xmlns="urn:ns"><X509Data><X509Certificate>`
	suffix := `</X509Certificate></X509Data></KeyInfo>`
	if !strings.HasPrefix(string(xmlOut), prefix) || !strings.HasSuffix(string(xmlOut), suffix) {
		t.Errorf("wrapper bytes must be preserved exactly; got %s", xmlOut)
	}
}

func TestSanitizeMetadataCerts_PreservesEverythingWhenNoRewriteNeeded(t *testing.T) {
	// DER with an ASCII-only PrintableString "SE".
	oid := []byte{0x06, 0x03, 0x55, 0x04, 0x06}
	printableSE := []byte{0x13, 0x02, 'S', 'E'}
	inner := append([]byte{}, oid...)
	inner = append(inner, printableSE...)
	sequence := append([]byte{0x30, byte(len(inner))}, inner...)
	set := append([]byte{0x31, byte(len(sequence))}, sequence...)
	outer := append([]byte{0x30, byte(len(set))}, set...)
	b64 := base64.StdEncoding.EncodeToString(outer)

	xmlIn := []byte(`<md:KeyInfo xmlns:md="urn:x"><md:X509Data><md:X509Certificate>` + b64 + `</md:X509Certificate></md:X509Data></md:KeyInfo>`)
	xmlOut := sanitizeMetadataCerts(xmlIn)

	if !bytes.Equal(xmlIn, xmlOut) {
		t.Errorf("all-ASCII cert must leave XML byte-identical\nin : %s\nout: %s", xmlIn, xmlOut)
	}
}

func TestSanitizeBase64SAMLResponse_Idempotent(t *testing.T) {
	// A SAML response with no X509Certificate must pass through unchanged.
	orig := base64.StdEncoding.EncodeToString([]byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`))
	got := sanitizeBase64SAMLResponse(orig)
	if got != orig {
		t.Errorf("payload with no cert must be unchanged")
	}
}

func TestSanitizeBase64SAMLResponse_InvalidBase64Passthrough(t *testing.T) {
	got := sanitizeBase64SAMLResponse("!!!not base64!!!")
	if got != "!!!not base64!!!" {
		t.Errorf("invalid base64 must pass through unchanged")
	}
}
