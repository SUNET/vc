package oauth2

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/SUNET/vc/pkg/jose"

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

	Thumbprint string `json:"thumbprint,omitempty"` // Optional, used for JWK thumbprint

	JWK *jose.JWKWithMetadata `json:"jwk,omitempty"` // JWK claim, optional
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

	// Unmarshal claims into DPoP struct
	dpopClaims := &DPoP{
		Thumbprint: thumbprint,
	}

	if err := dpopClaims.Unmarshal(claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims into DPoP struct: %w", err)
	}

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
