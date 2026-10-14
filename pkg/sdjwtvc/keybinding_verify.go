package sdjwtvc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// KeyBindingExpectations are what a Key Binding JWT must say, beyond being
// signed by the key the Issuer bound the Credential to.
type KeyBindingExpectations struct {
	// Nonce is the challenge the Verifier issued. The KB-JWT's nonce must
	// equal it, and an empty value here is refused rather than skipped:
	// a presentation with nothing to replay against is replayable.
	Nonce string

	// Audience is what the presentation is addressed to. Same rule.
	Audience string
}

// VerifyKeyBinding checks that an SD-JWT VC presentation was made by the
// Holder the Credential was issued to, and made for THIS request.
//
// This is the step that makes a presentation a presentation rather than a
// copy. The Issuer's signature says the claims are genuine; it says
// nothing about who is presenting them, and a Credential plus its
// disclosures is a bearer token to anyone who obtains it. What ties it to
// the Holder is the cnf key the Issuer bound it to, and the only evidence
// that the presenter holds the corresponding private key is this
// signature - so parsing the KB-JWT without verifying it establishes
// nothing at all.
//
// Four things are checked, and all four are load-bearing:
//
//   - the signature, against the cnf key from the ISSUER-VERIFIED claims.
//     Claims read from an unverified issuer JWT would let a presenter
//     supply their own cnf, which is the same hole one level up.
//   - typ, which must be kb+jwt, so a JWT minted for another purpose and
//     signed by the same key cannot be replayed as a presentation.
//   - nonce and aud, which make it this request's presentation rather
//     than one captured from another.
//   - sd_hash, which binds the proof to the exact SD-JWT and the exact
//     set of disclosures sent with it - without it, a valid proof could
//     be re-attached to the same Credential with different claims
//     disclosed.
//
// issuerClaims must come from a verified issuer JWT. vpToken is the
// presentation as received: issuer JWT, disclosures and KB-JWT.
func VerifyKeyBinding(vpToken string, issuerClaims map[string]any, expected KeyBindingExpectations) error {
	if expected.Nonce == "" {
		return errors.New("key binding: no nonce to bind the presentation to")
	}
	if expected.Audience == "" {
		return errors.New("key binding: no audience to bind the presentation to")
	}

	issuerJWT, disclosures, kbJWT, err := splitPresentation(vpToken)
	if err != nil {
		return fmt.Errorf("key binding: %w", err)
	}

	holderKey, err := holderKeyFromCnf(issuerClaims)
	if err != nil {
		return fmt.Errorf("key binding: %w", err)
	}

	// Parsed with the signature verified and the algorithm pinned to the
	// family of the bound key: a presentation that chose its own
	// algorithm could otherwise pick one the key material trivially
	// satisfies.
	parser := jwt.NewParser(jwt.WithValidMethods(validMethodsFor(holderKey)))
	kbToken, err := parser.Parse(kbJWT, func(*jwt.Token) (any, error) { return holderKey, nil })
	if err != nil {
		return fmt.Errorf("key binding: the proof is not signed by the key this credential is bound to: %w", err)
	}

	if typ, _ := kbToken.Header["typ"].(string); typ != "kb+jwt" {
		return fmt.Errorf("key binding: typ is %q, and a key binding proof is kb+jwt", typ)
	}

	claims, ok := kbToken.Claims.(jwt.MapClaims)
	if !ok {
		return errors.New("key binding: the proof carries no claims")
	}

	if nonce, _ := claims["nonce"].(string); nonce != expected.Nonce {
		return errors.New("key binding: the proof answers a different request")
	}
	if aud, _ := claims["aud"].(string); aud != expected.Audience {
		return errors.New("key binding: the proof is addressed elsewhere")
	}

	// sd_hash is over the US-ASCII bytes of everything before the proof,
	// trailing separator included (SD-JWT VC §4.3.1).
	var presented strings.Builder
	presented.WriteString(issuerJWT)
	for _, disclosure := range disclosures {
		presented.WriteByte('~')
		presented.WriteString(disclosure)
	}
	presented.WriteByte('~')

	sum := sha256.Sum256([]byte(presented.String()))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if got, _ := claims["sd_hash"].(string); got != want {
		return errors.New("key binding: the proof was not made over this presentation")
	}

	return nil
}

// splitPresentation separates a presentation into the issuer JWT, the
// disclosures sent with it, and the Key Binding JWT - refusing one that
// carries no proof rather than returning an empty string for it.
func splitPresentation(vpToken string) (issuerJWT string, disclosures []string, kbJWT string, err error) {
	parts := strings.Split(vpToken, "~")
	if len(parts) < 2 {
		return "", nil, "", errors.New("the presentation carries no key binding proof")
	}

	issuerJWT = parts[0]
	kbJWT = parts[len(parts)-1]
	disclosures = parts[1 : len(parts)-1]

	if strings.Count(issuerJWT, ".") != 2 {
		return "", nil, "", errors.New("the issuer-signed JWT is malformed")
	}
	if strings.Count(kbJWT, ".") != 2 {
		return "", nil, "", errors.New("the presentation carries no key binding proof")
	}

	return issuerJWT, disclosures, kbJWT, nil
}

// holderKeyFromCnf returns the public key the Issuer bound the Credential
// to. A Credential with no cnf was not issued for key binding, and cannot
// be presented on a channel that requires it.
func holderKeyFromCnf(issuerClaims map[string]any) (crypto.PublicKey, error) {
	cnf, ok := issuerClaims["cnf"].(map[string]any)
	if !ok {
		return nil, errors.New("the credential has no cnf claim, so it is bound to no key")
	}
	jwkMap, ok := cnf["jwk"].(map[string]any)
	if !ok {
		return nil, errors.New("the credential's cnf claim carries no jwk")
	}
	key, err := jwkToPublicKey(jwkMap)
	if err != nil {
		return nil, fmt.Errorf("reading the key the credential is bound to: %w", err)
	}
	return key, nil
}

// validMethodsFor pins the algorithms a proof may be signed with to the
// family of the key the Credential is bound to.
//
// Without this the proof chooses its own algorithm, and "which algorithms
// are acceptable" becomes an attacker-supplied value - the oldest JWT
// mistake there is. The key type is already fixed by the Issuer, so there
// is nothing to negotiate.
func validMethodsFor(key crypto.PublicKey) []string {
	switch key.(type) {
	case *ecdsa.PublicKey:
		return []string{"ES256", "ES384", "ES512"}
	case ed25519.PublicKey:
		return []string{"EdDSA"}
	case *rsa.PublicKey:
		return []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512"}
	default:
		// Nothing is acceptable for a key this code does not recognise,
		// which refuses the presentation rather than letting the parser
		// decide.
		return nil
	}
}
