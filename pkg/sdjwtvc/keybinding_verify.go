package sdjwtvc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/SUNET/vc/pkg/jose"

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

	// MaxAge is how long after it was signed a proof is still accepted,
	// and ClockSkew is the tolerance applied at both ends of that window.
	// Zero means the package defaults below.
	//
	// There is no spec value to adopt: SD-JWT VC requires iat and leaves
	// the window to the Verifier. The defaults suit how the claim is
	// actually produced - a Holder signs the proof immediately before
	// sending it, so the gap between iat and arrival is a round trip, not
	// a user's deliberation.
	MaxAge    time.Duration
	ClockSkew time.Duration

	// Now is the moment the window is measured against. Zero means
	// time.Now, which is what every caller outside a test wants.
	Now time.Time
}

// The default freshness window for a Key Binding JWT. See
// KeyBindingExpectations.MaxAge.
const (
	DefaultKeyBindingMaxAge    = 5 * time.Minute
	DefaultKeyBindingClockSkew = time.Minute
)

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
//   - iat, which SD-JWT VC requires and which nothing else here was
//     reading. The parser does not check it by default, and enabling its
//     check would not be enough either: that only rejects a FUTURE iat,
//     and treats a missing one - and, through a quirk of NumericDate
//     parsing, an iat of exactly 0 - as absent and therefore fine. So a
//     correctly signed proof stamped a decade ago, or carrying no stamp
//     at all, passed every other check here.
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

	if err := checkIssuedAt(claims, expected); err != nil {
		return err
	}

	// sd_hash is over the US-ASCII bytes of everything before the proof,
	// trailing separator included (SD-JWT VC §4.3.1), and under the hash
	// the ISSUER chose.
	//
	// _sd_alg comes from the verified issuer claims rather than from the
	// proof: it is the algorithm the credential's own disclosure digests
	// use, a holder computes sd_hash with it, and a presenter must not be
	// able to nominate a weaker one. Absent means sha-256 (§4.1.1), which
	// is the common case and the only one a hardcoded SHA-256 got right.
	sdAlg, _ := issuerClaims["_sd_alg"].(string)
	if sdAlg == "" {
		sdAlg = "sha-256"
	}
	hasher, err := getHashFromAlgorithm(sdAlg)
	if err != nil {
		return fmt.Errorf("key binding: the credential's _sd_alg %q is not a hash this build computes: %w", sdAlg, err)
	}

	var presented strings.Builder
	presented.WriteString(issuerJWT)
	for _, disclosure := range disclosures {
		presented.WriteByte('~')
		presented.WriteString(disclosure)
	}
	presented.WriteByte('~')

	hasher.Reset()
	hasher.Write([]byte(presented.String()))
	want := base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))
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
	// jose.ParseJWKToPublicKey rather than this package's jwkToPublicKey:
	// that one handles EC alone - it returns an error for RSA and has no
	// OKP branch at all - so an RSA- or Ed25519-bound credential could
	// never have been presented, however correct its proof. Those
	// families are advertised by default in the proof algorithms and in
	// the request metadata, so refusing them here would have been a
	// silent contradiction of what this server asks wallets for.
	key, err := jose.ParseJWKToPublicKey(jwkMap)
	if err != nil {
		return nil, fmt.Errorf("reading the key the credential is bound to: %w", err)
	}

	// Narrowed to the public key types a proof can actually be verified
	// against. jwk.Export will hand back a PRIVATE key for a JWK carrying
	// private parameters, and a symmetric key for an oct JWK; neither is
	// something a credential may be bound to, and both would otherwise
	// reach the parser as "some key".
	switch key.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey:
		return key, nil
	default:
		return nil, fmt.Errorf("the credential is bound to a %T, which is not a public key a holder proof can be verified against", key)
	}
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

// checkIssuedAt requires iat and places it inside the freshness window.
//
// Read out of the claim map rather than through MapClaims.GetIssuedAt,
// which cannot express what is needed here: it reports a missing claim and
// an iat of exactly 0 identically, as "no error and no date", so a proof
// that omits the claim and one that stamps the Unix epoch both look like a
// proof that simply has nothing to check.
//
// Both ends of the window matter, for different reasons. A future stamp
// means the proof was not made when it says, which is either a broken
// clock or an attempt to extend a proof's usable life past this check. A
// stale one means a proof made for an earlier moment is being presented
// now - the nonce already makes that hard, and this makes it an explicit
// refusal rather than something the nonce happens to cover.
func checkIssuedAt(claims jwt.MapClaims, expected KeyBindingExpectations) error {
	raw, present := claims["iat"]
	if !present {
		return errors.New("key binding: the proof carries no iat, which a key binding proof requires")
	}
	seconds, ok := numericDateSeconds(raw)
	if !ok {
		return fmt.Errorf("key binding: iat is %v, which is not a NumericDate", raw)
	}
	issuedAt := time.Unix(seconds, 0)

	now := expected.Now
	if now.IsZero() {
		now = time.Now()
	}
	maxAge := expected.MaxAge
	if maxAge == 0 {
		maxAge = DefaultKeyBindingMaxAge
	}
	skew := expected.ClockSkew
	if skew == 0 {
		skew = DefaultKeyBindingClockSkew
	}

	if issuedAt.After(now.Add(skew)) {
		return fmt.Errorf("key binding: the proof is stamped %s in the future", issuedAt.Sub(now).Round(time.Second))
	}
	if issuedAt.Before(now.Add(-maxAge - skew)) {
		return fmt.Errorf("key binding: the proof was made %s ago, and this one accepts %s", now.Sub(issuedAt).Round(time.Second), maxAge)
	}
	return nil
}

// numericDateSeconds reads a JWT NumericDate from whatever the JSON decode
// produced for it. encoding/json gives float64; a decoder set to UseNumber
// gives json.Number, which is why both are read here rather than only the
// one this package happens to produce today.
//
// A fractional value is truncated rather than refused - RFC 7519 allows a
// non-integer NumericDate - but a value that is not a number at all is
// not a date, and a string spelling of one is not either: accepting "17..."
// would let a proof choose a type the rest of this build does not expect.
func numericDateSeconds(raw any) (int64, bool) {
	switch value := raw.(type) {
	case float64:
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return 0, false
		}
		return int64(value), true
	case json.Number:
		if seconds, err := value.Int64(); err == nil {
			return seconds, true
		}
		asFloat, err := value.Float64()
		if err != nil || math.IsNaN(asFloat) || math.IsInf(asFloat, 0) {
			return 0, false
		}
		return int64(asFloat), true
	default:
		return 0, false
	}
}
