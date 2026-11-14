package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/registry/lote"
)

// verifyList checks a list's signature with go-trust's own verifier, so lol cannot disagree with it.
// fp is the SHA-256 fingerprint of the signer certificate, as colon-separated hex.
func verifyList(ctx context.Context, raw []byte, roots *x509.CertPool, now time.Time) (signer, fp string, err error) {
	leaf, err := lote.VerifyLoTESignature(ctx, raw, roots, now)
	if err != nil {
		return "", "", err
	}
	return leaf.Subject.String(), fingerprint(leaf), nil
}

// fingerprint formats a certificate's SHA-256 the way openssl prints it, for comparing out of band.
func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// payloadOf returns the list document inside a signed envelope; use it only on raw that verifyList accepted.
func payloadOf(raw []byte) []byte {
	token := bytes.TrimSpace(raw)
	switch {
	case len(token) == 0 || token[0] == '<':
		return raw
	case token[0] == '{':
		var f struct{ Payload string }
		if json.Unmarshal(token, &f) == nil && f.Payload != "" {
			if p, err := base64.RawURLEncoding.DecodeString(f.Payload); err == nil {
				return p
			}
		}
		return raw
	}
	if parts := bytes.Split(token, []byte(".")); len(parts) == 3 {
		if p, err := base64.RawURLEncoding.DecodeString(string(parts[1])); err == nil {
			return p
		}
	}
	return raw
}
