package sdjwtvc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// Signer defines the interface for cryptographic signing operations.
type Signer interface {
	Sign(ctx context.Context, data []byte) ([]byte, error)
	Algorithm() string
	KeyID() string
	PublicKey() any
}

// certChainSigner is implemented by Signers that also expose an x5c-ready
// certificate chain (e.g. *pki.KeyMaterialSigner). Checked via an optional
// interface assertion in SignWithSigner rather than added to Signer directly,
// so Signer implementations with no certificate (HSM/PKCS#11 key-only setups)
// aren't forced to grow a method they can't meaningfully implement.
type certChainSigner interface {
	GetCertificateChain() []string
}

// Sign signs the JWT with the provided header, body, signing method, and signing key
func Sign(header, body jwt.MapClaims, signingMethod jwt.SigningMethod, signingKey any) (string, error) {
	token := jwt.NewWithClaims(signingMethod, body)
	token.Header = header

	signedToken, err := token.SignedString(signingKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

// SignWithSigner signs the JWT using a Signer interface (for HSM support).
func SignWithSigner(ctx context.Context, header, body jwt.MapClaims, signer Signer) (string, error) {
	// Set algorithm and kid from signer
	header["alg"] = signer.Algorithm()
	header["kid"] = signer.KeyID()

	// The EUDI reference wallet's SD-JWT VC claim extraction (multipaz's
	// SdJwtVcCredential.getClaimsImpl) requires an x5c certificate chain in
	// the JWS header and throws IllegalStateException("Only X509-certified
	// keys are supported in SD-JWT") otherwise -- it does not support
	// resolving the signer's key via a bare kid. That exception is swallowed
	// silently by DcqlRequestProcessor.findMatchesForQuery (wrapped in
	// runCatching with no logging), so a credential issued with kid-only,
	// no-x5c headers is invisibly excluded from every DCQL/openid4vp
	// presentation match -- confirmed live against the actual wallet-core
	// and multipaz sources (lpidproto PLAN.md workstream 7 task 7.5, finding
	// 17) after every other candidate (vct, claims, status, trust) checked
	// out fine and the wallet still reported "document not available".
	if cc, ok := signer.(certChainSigner); ok {
		if chain := cc.GetCertificateChain(); len(chain) > 0 {
			header["x5c"] = chain
		}
	}

	// Encode header
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Encode payload
	payloadJSON, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Create signing input
	signingInput := headerB64 + "." + payloadB64

	// Sign using the signer interface
	signature, err := signer.Sign(ctx, []byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("failed to sign: %w", err)
	}

	// Encode signature
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	return signingInput + "." + signatureB64, nil
}

// Combine combines the token, disclosures and keyBinding into an SD-JWT format
func Combine(token string, disclosures []string, keyBinding string) string {
	if len(disclosures) > 0 {
		token = fmt.Sprintf("%s~%s~", token, strings.Join(disclosures, "~"))
	} else {
		token = fmt.Sprintf("%s~", token)
	}

	if keyBinding != "" {
		token = fmt.Sprintf("%s%s", token, keyBinding)
	}

	return token
}
