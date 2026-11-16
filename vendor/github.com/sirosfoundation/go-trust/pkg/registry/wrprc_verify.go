package registry

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/sirosfoundation/go-trust/pkg/registry/rpcert"

	// Import hash implementations so crypto.SHA256 etc. are available via .New().
	_ "crypto/sha256"
	_ "crypto/sha512"
)

// WRPRCVerifier evaluates a presented WRPRC (the fronted relying party's
// registration certificate, ETSI TS 119 475): the typ, the registrar chain
// anchored in the configured roots, the JWT signature by the anchored
// chain's leaf key, the claims, and the validity period.
//
// rpcert deliberately does not verify JWT signatures — see its doc.go: the
// caller holds that step, because it holds the protocol context. For the x5c
// enrichment pipeline the caller IS this pipeline, so the step belongs here:
// the deprecated rpcert.JWTRegistrationCertValidator anchors the chain and
// decodes the payload but never checks that the payload was signed by the
// key in that chain — a payload swapped under an authentic registrar header
// passes it. It does not pass a WRPRCVerifier.
type WRPRCVerifier interface {
	VerifyWRPRC(ctx context.Context, token []byte) (*rpcert.RPEntitlements, error)
}

// NewAnchoredWRPRCVerifier returns a WRPRCVerifier that anchors the WRPRC's
// registrar chain in roots. A nil pool means every presentation fails: the
// enrichment fails closed when a WRPRC arrives with no anchors configured.
func NewAnchoredWRPRCVerifier(roots *x509.CertPool) WRPRCVerifier {
	return &anchoredWRPRCVerifier{roots: roots}
}

type anchoredWRPRCVerifier struct {
	roots *x509.CertPool
}

// VerifyWRPRC evaluates a compact-serialization rc-wrp+jwt: the header typ,
// the x5c chain against the anchors, the JWS signature under the anchored
// leaf's public key (RFC 7518), the payload claims, and the validity period.
func (v *anchoredWRPRCVerifier) VerifyWRPRC(_ context.Context, token []byte) (*rpcert.RPEntitlements, error) {
	if v.roots == nil {
		return nil, fmt.Errorf("wrprc: no registrar trust anchors configured")
	}
	trimmed := strings.TrimSpace(string(token))
	parts := strings.Split(trimmed, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("wrprc: expected a compact JWS with 3 parts, got %d", len(parts))
	}

	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("wrprc: decoding JWS header: %w", err)
	}
	var header struct {
		Typ  string   `json:"typ"`
		Alg  string   `json:"alg"`
		X5C  []string `json:"x5c"`
		Crit []string `json:"crit"`
	}
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return nil, fmt.Errorf("wrprc: parsing JWS header: %w", err)
	}
	// RFC 7515 §4.1.11: a JWS with a `crit` member a verifier does not
	// understand and process MUST be rejected. This verifier implements no
	// header extensions, so ANY crit member refuses the token.
	if len(header.Crit) > 0 {
		return nil, fmt.Errorf("wrprc: the JWS declares critical header parameters %v this verifier does not implement", header.Crit)
	}
	// GEN-5.2.2-01: the media type identifies the document. Compared exactly:
	// Registrars emit the lowercase form and the latitude of a
	// case-insensitive media type buys nothing.
	if header.Typ != rpcert.WRPRCTyp {
		return nil, fmt.Errorf("wrprc: unexpected JWS typ %q, want %q", header.Typ, rpcert.WRPRCTyp)
	}

	leaf, intermediates, err := ParseJWSX5CChain(header.X5C)
	if err != nil {
		return nil, err
	}
	opts := x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: intermediates,
		// ExtKeyUsageAny: the registrar signing certificate is not a TLS
		// server certificate; Go's zero-value KeyUsages would reject it.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err := leaf.Verify(opts); err != nil {
		return nil, fmt.Errorf("wrprc: registrar chain does not anchor: %w", err)
	}

	// THE signature: the payload was signed by the anchored chain's leaf
	// key — the step that makes a swapped-payload attack fail.
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("wrprc: decoding JWS signature: %w", err)
	}
	if err := VerifyJWSSignature(header.Alg, leaf.PublicKey, []byte(parts[0]+"."+parts[1]), sig); err != nil {
		return nil, fmt.Errorf("wrprc: JWS signature: %w", err)
	}

	payload, err := rpcert.ParseWRPRCJWTPayload(trimmed)
	if err != nil {
		return nil, err
	}
	ent, err := rpcert.ParseWRPRCClaims(payload)
	if err != nil {
		return nil, err
	}
	if err := rpcert.CheckWRPRCValidityPeriod(ent); err != nil {
		return nil, err
	}
	// The current window, not just the 12-month span of
	// CheckWRPRCValidityPeriod: both timestamps must be present and the
	// evaluation time must fall within them (60 seconds of iat latitude for
	// clock drift, the same skew the producer side applies).
	if ent.ValidFrom == nil || ent.ValidUntil == nil {
		return nil, fmt.Errorf("wrprc: the certificate carries no validity window (iat/exp)")
	}
	now := time.Now()
	if now.Add(60 * time.Second).Before(*ent.ValidFrom) {
		return nil, fmt.Errorf("wrprc: not yet valid (iat %s)", ent.ValidFrom.Format(time.RFC3339))
	}
	if now.After(*ent.ValidUntil) {
		return nil, fmt.Errorf("wrprc: expired (exp %s)", ent.ValidUntil.Format(time.RFC3339))
	}
	ent.Raw = trimmed
	return ent, nil
}

// ParseJWSX5CChain parses the base64-encoded DER certificate chain from a
// JWS x5c header into the leaf and an intermediates pool — the shared
// implementation the WRPRC verifier and the lote JWS verification both use.
func ParseJWSX5CChain(x5c []string) (*x509.Certificate, *x509.CertPool, error) {
	if len(x5c) == 0 {
		return nil, nil, fmt.Errorf("wrprc: JWS header missing x5c certificate chain")
	}
	intermediates := x509.NewCertPool()
	var leaf *x509.Certificate
	for i, b64 := range x5c {
		der, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			der, err = base64.RawStdEncoding.DecodeString(b64)
			if err != nil {
				return nil, nil, fmt.Errorf("wrprc: x5c[%d]: base64 decode failed: %w", i, err)
			}
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, nil, fmt.Errorf("wrprc: x5c[%d]: parse failed: %w", i, err)
		}
		if i == 0 {
			leaf = cert
		} else {
			intermediates.AddCert(cert)
		}
	}
	return leaf, intermediates, nil
}

// VerifyJWSSignature verifies a JWS signature per RFC 7518 — the shared
// implementation the WRPRC verifier and the lote JWS verification both use.
// The algorithm set is the RSA and ECDSA families registrars actually use per
// TS 119 182-1. HMAC algorithms are absent on purpose: a symmetric MAC has no
// place in a chain-anchored certificate.
func VerifyJWSSignature(alg string, pub crypto.PublicKey, signingInput, sig []byte) error {
	switch alg {
	case "RS256", "RS384", "RS512":
		rsaKey, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("algorithm %s requires RSA public key", alg)
		}
		h := JWSAlgHash(alg)
		hh := h.New()
		hh.Write(signingInput)
		return rsa.VerifyPKCS1v15(rsaKey, h, hh.Sum(nil), sig) //nolint:gosec
	case "PS256", "PS384", "PS512":
		rsaKey, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("algorithm %s requires RSA public key", alg)
		}
		h := JWSAlgHash(alg)
		hh := h.New()
		hh.Write(signingInput)
		pssOpts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h}
		return rsa.VerifyPSS(rsaKey, h, hh.Sum(nil), sig, pssOpts)
	case "ES256", "ES384", "ES512":
		ecKey, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("algorithm %s requires ECDSA public key", alg)
		}
		// RFC 7518 §3.4: the curve is fixed by the algorithm. Deriving the
		// coordinate width from the key's own curve would let an ES256 token
		// signed by a P-384 key pass with a 96-byte signature.
		var wantCurve elliptic.Curve
		switch alg {
		case "ES256":
			wantCurve = elliptic.P256()
		case "ES384":
			wantCurve = elliptic.P384()
		default:
			wantCurve = elliptic.P521()
		}
		if ecKey.Curve != wantCurve {
			return fmt.Errorf("algorithm %s requires curve %s, got %s",
				alg, wantCurve.Params().Name, ecKey.Curve.Params().Name)
		}
		h := JWSAlgHash(alg)
		hh := h.New()
		hh.Write(signingInput)
		digest := hh.Sum(nil)
		// ECDSA JWS signature is r || s (fixed-size big-endian) per RFC 7518 §3.4.
		keyBytes := (wantCurve.Params().BitSize + 7) / 8
		if len(sig) != 2*keyBytes {
			return fmt.Errorf("ECDSA signature has unexpected length %d (want %d)", len(sig), 2*keyBytes)
		}
		r := new(big.Int).SetBytes(sig[:keyBytes])
		s := new(big.Int).SetBytes(sig[keyBytes:])
		if !ecdsa.Verify(ecKey, digest, r, s) {
			return fmt.Errorf("ECDSA signature invalid")
		}
		return nil
	default:
		return fmt.Errorf("unsupported JWS algorithm %q", alg)
	}
}

// JWSAlgHash maps a JWA algorithm name to its crypto.Hash (RFC 7518 §3).
func JWSAlgHash(alg string) crypto.Hash {
	switch alg {
	case "RS256", "PS256", "ES256":
		return crypto.SHA256
	case "RS384", "PS384", "ES384":
		return crypto.SHA384
	default: // RS512, PS512, ES512
		return crypto.SHA512
	}
}
