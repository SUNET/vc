// Package lote — LoTE JWS signature verification per ETSI TS 119 615.
//
// VerifyLoTESignature verifies the JWS envelope of a LoTE JWT document when a
// non-nil trust anchor pool is provided. Three JWS serializations are supported:
//   - Compact serialization: "<header>.<payload>.<signature>"
//   - Flattened JSON serialization: {"protected":"…","payload":"…","signature":"…"}
//   - Embedded signature object: {"LoTE":{…},"signature":{"protected":"…","signature":"…"}}
//     (see jws_embedded.go)
//
// XML lists (TS 119 602 XML) carry an enveloped XMLDSig instead; they are
// verified with the same entry points, see verifyLoTEDocument.
//
// General JSON serialization (multiple signatures array) is NOT supported.
//
// If the trust anchor pool is nil VerifyLoTESignature returns nil (verification
// skipped); the Registry itself never calls it that way when Config.VerifyJWS is
// set, and refuses to load instead.
//
// References:
//   - ETSI TS 119 615 v1.1.1 — Trust Anchor validation procedures
//   - ETSI TS 119 612 v2.1.1 — Trusted List format (JSON)
//   - RFC 7515 — JSON Web Signature
package lote

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	// Import hash implementations so crypto.SHA256 etc. are available via .New().
	_ "crypto/sha256"
	_ "crypto/sha512"

	"github.com/sirosfoundation/g119612/pkg/etsi119602"
	"github.com/sirosfoundation/go-trust/pkg/registry"
)

// VerifyLoTESignature verifies the JWS signature of a raw LoTE payload.
//
// raw is the raw bytes fetched from the LoTE endpoint (compact JWT or JSON).
// roots is the CertPool to anchor the signer certificate chain; nil means skip.
// now is the verification time (normally time.Now(), injected for testing).
//
// On success the signer leaf certificate is returned so callers can log it.
// Returns (nil, nil) when roots is nil (verification skipped).
func VerifyLoTESignature(ctx context.Context, raw []byte, roots *x509.CertPool, now time.Time) (*x509.Certificate, error) {
	if roots == nil {
		return nil, nil
	}
	leaf, _, err := verifyLoTEDocument(ctx, raw, roots, now)
	return leaf, err
}

// verifyLoTEDocument verifies raw against roots, whatever its format: an XML
// list is verified by its enveloped XMLDSig, anything else as a JWS. The
// returned payload is the verified content in the same format as raw (XML or
// JSON), ready for parseLoTEPayload.
func verifyLoTEDocument(ctx context.Context, raw []byte, roots *x509.CertPool, now time.Time) (*x509.Certificate, []byte, error) {
	if etsi119602.IsXMLContent(raw) {
		return verifyTSLSignature(ctx, raw, roots, now)
	}
	return verifyLoTEJWS(ctx, raw, roots, now)
}

// parseLoTEPayload parses verified content from verifyLoTEDocument.
func parseLoTEPayload(payload []byte) (*etsi119602.ListOfTrustedEntities, error) {
	if etsi119602.IsXMLContent(payload) {
		return etsi119602.ParseLoTEXML(payload)
	}
	return etsi119602.ParseLoTE(payload)
}

// verifyLoTEJWS verifies the JWS envelope in raw against roots (which must be
// non-nil) and returns the signer leaf certificate together with the verified
// JWS payload. Callers that go on to parse the document MUST parse this
// returned payload, never raw: raw is the JWS envelope, and the payload is the
// only content the signature covers.
func verifyLoTEJWS(_ context.Context, raw []byte, roots *x509.CertPool, now time.Time) (*x509.Certificate, []byte, error) {
	if roots == nil {
		return nil, nil, fmt.Errorf("lote: no trust anchors available for JWS verification")
	}

	token := strings.TrimSpace(string(raw))

	var headerB64, payloadB64, sigB64 string
	if parts := strings.Split(token, "."); len(parts) == 3 && !strings.HasPrefix(token, "{") {
		// Compact JWS
		headerB64, payloadB64, sigB64 = parts[0], parts[1], parts[2]
	} else {
		// Embedded signature object: {"LoTE": {...}, "signature": {"protected", "signature"}}.
		emb, err := parseEmbeddedJWS(raw)
		if err != nil {
			return nil, nil, err
		}
		if emb != nil {
			headerB64 = emb.protected
			payloadB64 = base64.RawURLEncoding.EncodeToString(emb.payload)
			sigB64 = emb.signature
		} else {
			// Flattened JSON serialisation: {"protected":"…","payload":"…","signature":"…"}
			var flat struct {
				Protected string `json:"protected"`
				Payload   string `json:"payload"`
				Signature string `json:"signature"`
			}
			if err := json.Unmarshal(raw, &flat); err != nil {
				return nil, nil, fmt.Errorf("lote: cannot parse as compact JWT, flattened JSON JWS or embedded-signature JSON: %w", err)
			}
			headerB64 = flat.Protected
			payloadB64 = flat.Payload
			sigB64 = flat.Signature
		}
	}

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return nil, nil, fmt.Errorf("lote: decoding JWS header: %w", err)
	}
	var header struct {
		Alg string   `json:"alg"`
		X5C []string `json:"x5c"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, fmt.Errorf("lote: parsing JWS header: %w", err)
	}
	if len(header.X5C) == 0 {
		return nil, nil, fmt.Errorf("lote: JWS header missing x5c certificate chain required by ETSI TS 119 615")
	}

	// Parse x5c chain
	leaf, intermediates, err := registry.ParseJWSX5CChain(header.X5C)
	if err != nil {
		return nil, nil, fmt.Errorf("lote: parsing x5c from JWS header: %w", err)
	}

	// Verify signer certificate against trust anchors
	verifyOpts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err := leaf.Verify(verifyOpts); err != nil {
		return nil, nil, fmt.Errorf("lote: signer certificate chain validation failed: %w", err)
	}

	// Verify JWS signature
	signingInput := headerB64 + "." + payloadB64
	sigBytes, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, nil, fmt.Errorf("lote: decoding JWS signature: %w", err)
	}
	if err := registry.VerifyJWSSignature(header.Alg, leaf.PublicKey, []byte(signingInput), sigBytes); err != nil {
		return nil, nil, fmt.Errorf("lote: JWS signature verification failed: %w", err)
	}

	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, nil, fmt.Errorf("lote: decoding JWS payload: %w", err)
	}

	return leaf, payload, nil
}

// fetchRawSource fetches the raw bytes from a URL or local file path.
// Used to obtain the original JWS payload for signature verification before
// the parsed LoTE is accepted.
func fetchRawSource(src string, timeout time.Duration) ([]byte, error) {
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		client := &http.Client{Timeout: timeout}
		resp, err := client.Get(src) //nolint:noctx // timeout set on client
		if err != nil {
			return nil, fmt.Errorf("HTTP GET %s: %w", src, err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("HTTP GET %s returned status %d", src, resp.StatusCode)
		}
		return io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10 MiB safety limit
	}
	// Local file
	path := strings.TrimPrefix(src, "file://")
	return os.ReadFile(path)
}
