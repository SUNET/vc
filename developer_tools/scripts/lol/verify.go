package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/registry/lote"
)

// verifyList checks a list's signature with go-trust's own verifier, so lol cannot disagree with it.
func verifyList(ctx context.Context, raw []byte, roots *x509.CertPool, now time.Time) (signer string, err error) {
	leaf, err := lote.VerifyLoTESignature(ctx, raw, roots, now)
	if err != nil {
		return "", err
	}
	return leaf.Subject.String(), nil
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
