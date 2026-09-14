package samlsp

import (
	"bytes"
	"encoding/base64"
	"regexp"
	"strings"
)

// sanitizePrintableStrings walks a DER-encoded ASN.1 value in-place and
// rewrites any PrintableString tag (0x13) whose bytes contain non-ASCII to
// UTF8String (0x0C). This is a defensive fix for X.509 certificates in which
// a CA mislabelled a UTF-8 attribute (typically an organizationName that
// contains "å", "ä" or "ö") as PrintableString — Go's crypto/x509 then
// rejects the cert with "invalid PrintableString", even though openssl
// tolerates it. Only the tag byte changes; the public key and the rest of
// the cert are byte-identical, so downstream signature verification is
// unaffected.
func sanitizePrintableStrings(der []byte) []byte {
	walkASN1(der)
	return der
}

func walkASN1(b []byte) {
	for i := 0; i < len(b); {
		if i >= len(b) {
			return
		}
		tag := b[i]
		tagIdx := i
		i++
		l, n, ok := readASN1Len(b[i:])
		if !ok {
			return
		}
		i += n
		if l < 0 || i+l > len(b) {
			return
		}
		val := b[i : i+l]
		if tag&0x20 != 0 {
			walkASN1(val)
		} else if tag == 0x13 && hasNonASCII(val) {
			b[tagIdx] = 0x0C
		}
		i += l
	}
}

func readASN1Len(b []byte) (length, consumed int, ok bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	first := b[0]
	if first < 0x80 {
		return int(first), 1, true
	}
	n := int(first & 0x7F)
	if n == 0 || n > 4 || 1+n > len(b) {
		return 0, 0, false
	}
	for j := 1; j <= n; j++ {
		length = (length << 8) | int(b[j])
	}
	return length, 1 + n, true
}

func hasNonASCII(b []byte) bool {
	for _, x := range b {
		if x >= 0x80 {
			return true
		}
	}
	return false
}

// x509CertificateRE matches the base64 chardata inside any XML
// <...X509Certificate>...</X509Certificate> element (optional namespace
// prefix). Byte-level substitution is used instead of re-encoding the XML
// because a full XML round-trip changes whitespace/attribute quoting and
// breaks XML DSig canonicalization on the SAML Response.
var x509CertificateRE = regexp.MustCompile(`(?s)(<(?:[A-Za-z_][\w.-]*:)?X509Certificate[^>]*>)(.*?)(</(?:[A-Za-z_][\w.-]*:)?X509Certificate>)`)

// sanitizeMetadataCerts rewrites every base64 X509Certificate payload in an
// XML document through sanitizePrintableStrings, preserving all other bytes
// exactly. Safe to call on SAML metadata and on signed SAML responses.
func sanitizeMetadataCerts(xmlBytes []byte) []byte {
	if !bytes.Contains(xmlBytes, []byte("X509Certificate")) {
		return xmlBytes
	}
	return x509CertificateRE.ReplaceAllFunc(xmlBytes, func(match []byte) []byte {
		sub := x509CertificateRE.FindSubmatch(match)
		if len(sub) != 4 {
			return match
		}
		fixed := rewriteBase64Cert(string(sub[2]))
		if fixed == string(sub[2]) {
			return match
		}
		var out bytes.Buffer
		out.Grow(len(match))
		out.Write(sub[1])
		out.WriteString(fixed)
		out.Write(sub[3])
		return out.Bytes()
	})
}

// rewriteBase64Cert decodes a whitespace-tolerant base64 X509 certificate,
// runs sanitizePrintableStrings, and re-encodes. Returns the input unchanged
// if base64 decoding fails or the DER doesn't need any rewriting.
func rewriteBase64Cert(b64 string) string {
	clean := strings.Join(strings.Fields(b64), "")
	der, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return b64
	}
	orig := append([]byte(nil), der...)
	sanitizePrintableStrings(der)
	if bytes.Equal(orig, der) {
		return b64
	}
	// Preserve original line wrapping when possible: if the original was
	// unwrapped (single line, no newlines), emit unwrapped. Otherwise wrap
	// at 64 columns like MIME base64 does.
	newB64 := base64.StdEncoding.EncodeToString(der)
	if !strings.ContainsAny(b64, "\r\n\t ") {
		return newB64
	}
	return wrapBase64(newB64, 64)
}

func wrapBase64(s string, cols int) string {
	if cols <= 0 || len(s) <= cols {
		return s
	}
	var out strings.Builder
	out.Grow(len(s) + len(s)/cols)
	for i := 0; i < len(s); i += cols {
		end := i + cols
		if end > len(s) {
			end = len(s)
		}
		out.WriteString(s[i:end])
		if end < len(s) {
			out.WriteByte('\n')
		}
	}
	return out.String()
}

// sanitizeBase64SAMLResponse decodes a base64 SAMLResponse (as posted to the
// ACS endpoint), rewrites embedded X509 certificates in place, and re-encodes.
// Returns the input unchanged when no cert bytes needed rewriting so that
// canonicalization stays byte-perfect for well-formed responses.
func sanitizeBase64SAMLResponse(b64 string) string {
	clean := strings.Join(strings.Fields(b64), "")
	raw, err := base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return b64
	}
	if !bytes.Contains(raw, []byte("X509Certificate")) {
		return b64
	}
	fixed := sanitizeMetadataCerts(raw)
	if bytes.Equal(fixed, raw) {
		return b64
	}
	return base64.StdEncoding.EncodeToString(fixed)
}
