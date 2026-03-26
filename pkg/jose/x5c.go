package jose

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/sirosfoundation/go-cryptoutil"
)

// ExtractKIDFromCompactJWT extracts the "kid" field from the header of a compact-serialized JWT/JWE.
func ExtractKIDFromCompactJWT(compactToken string) (string, error) {
	header := strings.SplitN(compactToken, ".", 2)[0]
	b, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		// Fall back to RawStdEncoding for compatibility
		b, err = base64.RawStdEncoding.DecodeString(header)
		if err != nil {
			return "", fmt.Errorf("failed to decode JWT header: %w", err)
		}
	}

	var hdr struct {
		KID string `json:"kid"`
	}
	if err := json.Unmarshal(b, &hdr); err != nil {
		return "", fmt.Errorf("failed to parse JWT header: %w", err)
	}

	if hdr.KID == "" {
		return "", errors.New("kid not found in JWT header")
	}

	return hdr.KID, nil
}

// ParseX5CHeader parses the x5c header into a certificate chain.
// The x5c header is an array of base64-encoded DER certificates,
// with the leaf certificate first.
// Supports both standard and URL-safe base64 encoding.
// If ext is provided, certificates are parsed using extension-aware parsing
// (e.g. to support brainpool curves).
func ParseX5CHeader(x5cRaw any, ext ...*cryptoutil.Extensions) ([]*x509.Certificate, error) {
	x5cArray, ok := x5cRaw.([]any)
	if !ok {
		return nil, fmt.Errorf("x5c header must be an array")
	}

	if len(x5cArray) == 0 {
		return nil, fmt.Errorf("x5c header is empty")
	}

	certs := make([]*x509.Certificate, 0, len(x5cArray))
	for i, certRaw := range x5cArray {
		certB64, ok := certRaw.(string)
		if !ok {
			return nil, fmt.Errorf("x5c[%d] is not a string", i)
		}

		// x5c uses standard base64 encoding per RFC 7517
		certDER, err := base64.StdEncoding.DecodeString(certB64)
		if err != nil {
			// Try URL-safe base64 as fallback for compatibility
			certDER, err = base64.RawURLEncoding.DecodeString(certB64)
			if err != nil {
				return nil, fmt.Errorf("failed to decode x5c[%d]: %w", i, err)
			}
		}

		var cert *x509.Certificate
		if len(ext) > 0 && ext[0] != nil {
			cert, err = ext[0].ParseCertificate(certDER)
		} else {
			cert, err = x509.ParseCertificate(certDER)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to parse x5c[%d]: %w", i, err)
		}

		certs = append(certs, cert)
	}

	return certs, nil
}

// ParseJWKToPublicKey parses a JWK (as a map or JSON bytes) to extract the public key.
func ParseJWKToPublicKey(jwkData any) (crypto.PublicKey, error) {
	var jwkBytes []byte
	var err error

	switch v := jwkData.(type) {
	case map[string]any:
		jwkBytes, err = json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize jwk: %w", err)
		}
	case []byte:
		jwkBytes = v
	default:
		return nil, fmt.Errorf("jwkData must be map[string]any or []byte, got %T", jwkData)
	}

	key, err := jwk.ParseKey(jwkBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse jwk: %w", err)
	}

	var rawKey any
	if err := jwk.Export(key, &rawKey); err != nil {
		return nil, fmt.Errorf("failed to export jwk: %w", err)
	}

	pubKey, ok := rawKey.(crypto.PublicKey)
	if !ok {
		return nil, fmt.Errorf("jwk does not contain a public key")
	}

	return pubKey, nil
}
