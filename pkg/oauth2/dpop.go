package oauth2

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/SUNET/vc/pkg/jose"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidJTI       = errors.New("invalid JTI: must be at least 12 characters")
	ErrMissingJTI       = errors.New("missing required JTI claim")
	ErrJTIReplay        = errors.New("JTI has already been used (replay attack detected)")
	ErrMissingHTM       = errors.New("missing required HTM claim")
	ErrInvalidHTM       = errors.New("invalid HTM: must be a valid HTTP method")
	ErrMissingHTU       = errors.New("missing required HTU claim")
	ErrInvalidTokenType = errors.New("invalid token type: must be 'dpop+jwt'")
	ErrMissingJWK       = errors.New("missing JWK in token header")
	ErrMissingIAT       = errors.New("missing required IAT claim")
	ErrInvalidIAT       = errors.New("invalid IAT: timestamp is malformed")
	ErrTokenTooOld      = errors.New("token IAT is too old")
	ErrTokenFromFuture  = errors.New("token IAT is in the future")
	ErrTokenExpired     = errors.New("token has expired")
)

const (
	DefaultMaxAge    = 60 * time.Second
	DefaultClockSkew = 5 * time.Second
)

type DPoP struct {
	// JTI Unique identifier for the DPoP proof JWT. The value MUST be assigned such that there is a negligible probability that the same value will be assigned to any other DPoP proof used in the same context during the time window of validity. Such uniqueness can be accomplished by encoding (base64url or any other suitable encoding) at least 96 bits of pseudorandom data or by using a version 4 Universally Unique Identifier (UUID) string according to [RFC4122]. The jti can be used by the server for replay detection and prevention; see Section 11.1.
	JTI string `json:"jti" validate:"required"`

	// HTM The value of the HTTP method (Section 9.1 of [RFC9110]) of the request to which the JWT is attached.¶
	HTM string `json:"htm" validate:"required,oneof=POST GET PUT DELETE PATCH OPTIONS HEAD"`

	// HTU The HTTP target URI (Section 7.1 of [RFC9110]) of the request to which the JWT is attached, without query and fragment parts.¶
	HTU string `json:"htu" validate:"required,url"`

	// IAT Creation timestamp of the JWT (Section 4.1.6 of [RFC7519]).¶
	IAT int64 `json:"iat" validate:"required"`

	// ATH Hash of the access token. The value MUST be the result of a base64url encoding (as defined in Section 2 of [RFC7515]) the SHA-256 [SHS] hash of the ASCII encoding of the associated access token's value.¶
	ATH string `json:"ath"`

	// Thumbprint is the RFC 7638 thumbprint of the key in the proof's own
	// jwk HEADER, which is the key the signature was verified against. It
	// is what every DPoP key-binding decision in this build compares, so
	// it is the one field a proof must never be able to state about
	// itself.
	//
	// json:"-" is load-bearing, not tidiness. ValidateAndParseDPoPJWT
	// decodes the payload into this struct, and with a json name this
	// field was settable from the payload: a proof signed by key B
	// carrying {"thumbprint":"<A>"} came back claiming A's thumbprint and
	// passed the comparison against an exchange bound to A, without the
	// sender possessing A at all. encoding/json matches field names
	// case-insensitively, so "Thumbprint" and "THUMBPRINT" worked too.
	//
	// The derived value is also assigned AFTER the decode rather than
	// before. Either measure alone closes this; both are here because the
	// cost is nothing and the failure is silent.
	Thumbprint string `json:"-"`

	// JWK is the parsed header key, assigned after the decode for the
	// same reason and excluded from it for the same reason.
	JWK *jose.JWKWithMetadata `json:"-"`
}

func (d *DPoP) Unmarshal(claims jwt.MapClaims) error {
	// Unmarshal the claims into the DPoP struct
	data, err := json.Marshal(claims)
	if err != nil {
		return fmt.Errorf("failed to marshal claims: %w", err)
	}

	if err := json.Unmarshal(data, d); err != nil {
		return fmt.Errorf("failed to unmarshal claims into DPoP struct: %w", err)
	}

	return nil
}

// ValidateJTI validates the JTI claim for proper format and length
func (d *DPoP) ValidateJTI() error {
	if d.JTI == "" {
		return ErrMissingJTI
	}

	// JTI must be at least 96 bits (12 bytes) when base64url encoded
	// This is approximately 16 characters in base64url encoding
	if len(d.JTI) < 12 {
		return ErrInvalidJTI
	}

	return nil
}

// ValidateHTM validates the HTTP method claim
func (d *DPoP) ValidateHTM() error {
	if d.HTM == "" {
		return ErrMissingHTM
	}

	// Validate against allowed HTTP methods
	validMethods := map[string]bool{
		"GET":     true,
		"POST":    true,
		"PUT":     true,
		"DELETE":  true,
		"PATCH":   true,
		"HEAD":    true,
		"OPTIONS": true,
	}

	if !validMethods[d.HTM] {
		return ErrInvalidHTM
	}

	return nil
}

// ValidateHTU validates the HTTP URI claim
func (d *DPoP) ValidateHTU() error {
	if d.HTU == "" {
		return ErrMissingHTU
	}

	// HTU must not contain query or fragment per RFC 9449 §4.2
	u, err := url.Parse(d.HTU)
	if err != nil {
		return fmt.Errorf("invalid HTU: %w", err)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("HTU must not contain query or fragment")
	}

	return nil
}

// ValidateIAT validates the issued-at timestamp claim
// Ensures the token is not too old and not from the future
func (d *DPoP) ValidateIAT() error {
	return d.ValidateIATWithWindow(DefaultMaxAge, DefaultClockSkew)
}

// ValidateIATWithWindow validates IAT with custom time windows
func (d *DPoP) ValidateIATWithWindow(maxAge, clockSkew time.Duration) error {
	if d.IAT == 0 {
		return ErrMissingIAT
	}

	// Check if IAT is a valid timestamp (not negative, not too far in future)
	if d.IAT < 0 {
		return ErrInvalidIAT
	}

	iat := time.Unix(d.IAT, 0)
	now := time.Now()

	// Check if token is from the future (with clock skew tolerance)
	if iat.After(now.Add(clockSkew)) {
		return ErrTokenFromFuture
	}

	// Check if token is too old
	if now.Sub(iat) > maxAge {
		return ErrTokenTooOld
	}

	return nil
}

// Validate performs full validation of DPoP claims with default time windows
func (d *DPoP) Validate() error {
	return d.ValidateWithWindow(DefaultMaxAge, DefaultClockSkew)
}

// ValidateWithWindow performs full validation with custom time windows
func (d *DPoP) ValidateWithWindow(maxAge, clockSkew time.Duration) error {
	if err := d.ValidateJTI(); err != nil {
		return err
	}

	if err := d.ValidateHTM(); err != nil {
		return err
	}

	if err := d.ValidateHTU(); err != nil {
		return err
	}

	if err := d.ValidateIATWithWindow(maxAge, clockSkew); err != nil {
		return err
	}

	return nil
}

func ValidateAndParseDPoPJWT(dPopJWT string) (*DPoP, error) {
	if dPopJWT == "" {
		return nil, fmt.Errorf("DPoP JWT is empty")
	}

	// Parse and validate JWT with JWK in header
	claims, header, jwkHeader, thumbprint, err := jose.ParseJWTWithJWKHeader(dPopJWT)
	if err != nil {
		return nil, err
	}

	// Validate DPoP-specific token type
	if header["typ"] != "dpop+jwt" {
		return nil, ErrInvalidTokenType
	}

	// Unmarshal claims into DPoP struct.
	//
	// The thumbprint is assigned AFTER this, never before: the decode
	// writes into the same struct, so a value set first is a value the
	// signed payload can replace. See the field's own comment for what
	// that cost.
	dpopClaims := &DPoP{}

	if err := dpopClaims.Unmarshal(claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims into DPoP struct: %w", err)
	}
	dpopClaims.Thumbprint = thumbprint

	// Validate DPoP claims
	if err := dpopClaims.Validate(); err != nil {
		return nil, err
	}

	// Parse JWK header to jose.JWKWithMetadata
	jwk, err := jose.ParseJWK(jwkHeader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWK: %w", err)
	}

	dpopClaims.JWK = jwk

	return dpopClaims, nil
}

func (c *DPoP) IsAccessTokenDPoP(token string) bool {
	// ATH is base64url(SHA-256(ASCII(access_token))) per RFC 9449 §4.2
	if c.ATH == "" {
		return false
	}
	h := sha256.Sum256([]byte(token))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	return subtle.ConstantTimeCompare([]byte(c.ATH), []byte(computed)) == 1
}

// SameHTU reports whether a proof's htu names the same resource as the
// endpoint it arrived at.
//
// RFC 9449 §4.3 says to compare the two "ignoring any query and fragment
// parts" and after URI normalization, and both halves of that matter in
// practice. A deployment writes its endpoint URL in configuration and a
// wallet builds the htu from the URL it actually requested, so the two
// legitimately differ in every way RFC 3986 §6.2.2 calls insignificant:
// the case of the scheme and host, an explicitly written default port, and
// a host spelled in Unicode where the other side used its A-label. A byte
// comparison refuses those proofs, and the refusal is unfixable from the
// wallet's side - it is a correct proof for the URL it was sent to.
//
// The path is normalized only where RFC 3986 says two spellings are the
// same path, and not one step further. Two endpoints on one host differ
// only there, so a proof for /token must never satisfy a request to the
// Authorization Challenge Endpoint. Case is therefore significant, and so
// is every reserved escape - %2F is not a separator. What IS normalized
// is "" versus "/" (§6.2.3), the hex case of an escape (§6.2.2.1), and an
// escape of an unreserved character (§6.2.2.2), which is how /%74oken and
// /token come to be one path.
//
// Dot segments are deliberately NOT removed (§6.2.2.4 is not applied), so
// /a/../token and /token stay different. That keeps this comparison
// strict: the only spellings it merges are ones the RFC defines as the
// same path.
func SameHTU(htu, endpoint string) bool {
	normalizedHTU, okHTU := normalizeURIForComparison(htu)
	normalizedEndpoint, okEndpoint := normalizeURIForComparison(endpoint)
	if !okHTU || !okEndpoint {
		// Something that would not parse is compared as written rather
		// than silently treated as equal to anything.
		return htu == endpoint
	}
	return normalizedHTU == normalizedEndpoint
}

// normalizeURIForComparison applies RFC 3986 §6.2.2 syntax-based
// normalization to the parts of a URI that are case- or port-insignificant,
// and drops the query and fragment RFC 9449 §4.3 says to ignore.
func normalizeURIForComparison(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", false
	}

	scheme := strings.ToLower(u.Scheme)

	host := u.Hostname()
	// An address is normalized as an address, not as a name. IPv6 has many
	// spellings of one address - 2001:0db8:0:0:0:0:0:1 and 2001:db8::1 are
	// the same endpoint - and lowercasing alone leaves them different, so a
	// wallet that compressed the URL it was given got invalid_dpop_proof
	// for a proof that named this very endpoint. netip.Addr.String is the
	// canonical form from RFC 5952.
	//
	// netip rather than net.IP, and this is the whole reason: net.IP.String
	// UNMAPS, rendering ::ffff:127.0.0.1 as 127.0.0.1. That makes
	// https://[::ffff:127.0.0.1]/token and https://127.0.0.1/token compare
	// equal, and they are not the same thing. htu binds the target URI, not
	// the target address: the two reach a server with different Host
	// headers and can select different virtual hosts, so merging them
	// weakens exactly the binding this comparison exists to make. One
	// address, two authorities. netip preserves the family.
	//
	// Before the IDNA mapping, not after: an address is not a domain name
	// and has no business being mapped as one.
	//
	// IDNA gets the host as written, not lowercased: Unicode lowercasing is
	// not the IDNA mapping (İ lowercases to i, but maps to xn--i-9bb), so
	// pre-lowercasing would merge distinct hosts and split equivalent ones.
	if addr, parseErr := netip.ParseAddr(host); parseErr == nil {
		host = addr.String()
	} else if ascii, err := openid4vp.BrowserHost.ToASCII(host); err == nil {
		// A Unicode host and its A-label are the same host. The browser
		// profile accepts hosts a resolver profile rejects (e.g. "_").
		host = ascii
	} else {
		// No fallback: lowercasing an unmappable host can merge it with a
		// distinct one, so the caller compares as written instead.
		return "", false
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	// A port is a number, so leading zeroes are not part of it: ":0443" is
	// the https default and a wallet's parser drops it entirely, while
	// ":08443" and ":8443" are one port written two ways. Comparing the
	// written form refuses a proof that names this very endpoint.
	port := strings.TrimLeft(u.Port(), "0")
	if u.Port() != "" && port == "" {
		port = "0"
	}
	if port != "" && port != defaultPortFor(scheme) {
		host += ":" + port
	}

	path := normalizePercentEncoding(u.EscapedPath())
	if path == "" {
		path = "/"
	}

	return scheme + "://" + host + path, true
}

// normalizePercentEncoding applies the two percent-encoding rules of RFC
// 3986 §6.2.2 to an already-escaped path: an escape is written in upper
// case (§6.2.2.1), and an escape of an unreserved character is decoded
// (§6.2.2.2).
//
// url.URL.EscapedPath preserves whatever the sender wrote, which is right
// for a path and wrong for a comparison: /%74oken and /token are the same
// path under the RFC, and a wallet that normalized the endpoint URL it was
// configured with was refused for naming it that way.
//
// Only unreserved characters are decoded. A reserved escape stands,
// because decoding it would change the path - %2F is not a separator, and
// a proof for /a%2Fb must not satisfy a request to /a/b.
//
// A malformed escape - a stray % or a non-hex digit - is left exactly as
// written and no attempt is made to repair it. It is not a valid path, and
// a comparison is not the place to decide what the sender meant.
func normalizePercentEncoding(path string) string {
	if !strings.Contains(path, "%") {
		return path
	}
	var out strings.Builder
	out.Grow(len(path))
	for i := 0; i < len(path); {
		if path[i] != '%' || i+2 >= len(path) {
			out.WriteByte(path[i])
			i++
			continue
		}
		high, highOK := unhexDigit(path[i+1])
		low, lowOK := unhexDigit(path[i+2])
		if !highOK || !lowOK {
			out.WriteByte(path[i])
			i++
			continue
		}
		if octet := high<<4 | low; isUnreservedByte(octet) {
			out.WriteByte(octet)
		} else {
			out.WriteByte('%')
			out.WriteString(strings.ToUpper(path[i+1 : i+3]))
		}
		i += 3
	}
	return out.String()
}

func unhexDigit(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

// isUnreservedByte reports whether an octet is one of RFC 3986 §2.3's
// unreserved characters, whose escape carries no meaning.
func isUnreservedByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c == '-' || c == '.' || c == '_' || c == '~':
		return true
	default:
		return false
	}
}

// defaultPortFor returns the port that is implied by a scheme and so
// carries no meaning when written out, or "" where every port is
// significant.
func defaultPortFor(scheme string) string {
	switch scheme {
	case "https":
		return "443"
	case "http":
		return "80"
	default:
		return ""
	}
}
