package apiv1

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"math/big"
	"strings"
	"vc/internal/gen/status/apiv1_status"
	"vc/pkg/model"
)

const (
	MsgNoCredentialProvided = "no credential provided for verification"
	MsgNotAJwt              = "not a JWT"
	MsgInvalidJwtStructure  = "invalid SD-JWT structure: expected format is header.payload.signature with optional ~disclosure~ segments (e.g., ~disclosure1~disclosure2~)."
	MsgInvalidJwk           = "missing or invalid JWK"
	MsgUnableToParseToken   = "invalid JWT: unable to parse token or verify its signature. Check the token format, signing and algorithm."
	MsgInvalidToken         = "invalid JWT: token is expired, has invalid claims, or is not valid. Check its content and validity."
)

type Credential struct {
	// min 20 is the ~ teoretical minimum for a non-signed jwt encoded in base64
	Credential string `json:"credential" validate:"required,min=20"`
}

type VerifyCredentialRequest struct {
	Credential
}

type DecodeCredentialRequest struct {
	Credential
}

type DecodedCredential struct {
}

type VerifyCredentialReply struct {
	Valid bool `json:"valid" validate:"required"`
	// Message a high-level explanation for the public (i.e., the calling client) on why the credential is invalid.
	Message string `json:"message,omitempty"`
}

type SDJWTParts struct {
	JWTEncoded         string   `json:"jwt_encoded,omitempty"`
	HeaderDecoded      string   `json:"jwt_header_decoded,omitempty"`
	PayloadDecoded     string   `json:"jwt_payload_decoded,omitempty"`
	SignatureDecoded   string   `json:"jwt_signature_decoded,omitempty"`
	DisclosuresDecoded []string `json:"disclosures_decoded,omitempty"`
}

type JWK struct {
	Crv string `json:"crv"`
	Kty string `json:"kty"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// Status returns the status for each instance.
func (c *Client) Health(ctx context.Context, req *apiv1_status.StatusRequest) (*apiv1_status.StatusReply, error) {
	probes := model.Probes{}
	return probes.Check("verifier"), nil
}

// DecodeCredential for raw but human-readable viewing (ie, jwt: header, payload and signature and also all selective disclosures)
func (c *Client) DecodeCredential(ctx context.Context, request *Credential) (*DecodedCredential, error) {
	//TODO(mk): impl DecodeCredential for raw but readable presentation in UI
	return nil, errors.New("To be implemented!")
}

/*
	disclosureData := [salt, key, value]
	sha256(base64(disclosureData)) <- claim in JWT
	base64(disclosureData) in <jwt>~disclosure

	Note:
	 a disclosure may be recursive
	 _SD in jwt payload may contain decoy hashes
	 if vp+sd-jwt: a second signature may exist as holderProof (if exists, its found in the last ~disclosure~ so check if its the last one is a disclosure or a holderProof)
*/

// VerifyCredential verifies a credential (only sd-jwt or sd-jwt-vc signed with ES256 is currently supported)
func (c *Client) VerifyCredential(ctx context.Context, request *Credential) (*VerifyCredentialReply, error) {
	if request == nil || strings.TrimSpace(request.Credential) == "" {
		return c.createInvalidReply(MsgNoCredentialProvided, errors.New(MsgNoCredentialProvided))
	}

	//TODO: impl verify for openid4vp here...

	jwtHeader, err := extractAndDecodeJWTHeader(request.Credential)
	if err != nil {
		return c.createInvalidReply(MsgNotAJwt, err)
	}

	//TODO(mk): remove sd-jwt and just keep vc+sd-jwt?
	allowedTyp := []string{"sd-jwt", "vc+sd-jwt"}
	if !isHeaderTypSupported(jwtHeader, allowedTyp) {
		return c.createInvalidReply("supported jwt header.typ are: "+strings.Join(allowedTyp, ", "), errors.New("Typ not supported"))
	}

	//TODO(mk): add support for more algorithms?
	allowedAlg := []string{"ES256"}
	if !isHeaderAlgSupported(jwtHeader, allowedAlg) {
		return c.createInvalidReply("supported jwt header.alg are: "+strings.Join(allowedAlg, ", "), errors.New("Alg not supported"))
	}

	sdjwtParts, err := splitAndDecodeSDJWT(request.Credential)
	if err != nil {
		return c.createInvalidReply(MsgInvalidJwtStructure, err)
	}

	//c.log.Debug("credential", "parts", sdjwtParts)

	//disclosuresDecoded, err := decodeDisclosures(sdjwtParts)
	//fmt.Println("Disclusures decoded:", disclosuresDecoded)

	jwk, err := extractJWK(sdjwtParts.PayloadDecoded)
	if err != nil {
		return c.createInvalidReply(MsgInvalidJwk, err)
	}
	//c.log.Debug("jwk", "data", jwk)

	//TODO(mk): Verify that this verifier trusts the public key etc - as of now, the jwk-data used to create the pubkey is extracted from the jwt's payload.cnf.*, ie verify key binding/more info taken from the jwt.header etc!!!
	pubKey, err := createPubKey(jwk)
	if err != nil {
		return c.createInvalidReply(MsgInvalidJwk, err)
	}
	//c.log.Debug("pubkey", "data", pubKey)

	token, err := parseJWT(sdjwtParts.JWTEncoded, pubKey)
	if err != nil {
		return c.createInvalidReply(MsgUnableToParseToken, err)
	}
	//c.log.Debug("token", "data", token)

	if !token.Valid {
		return c.createInvalidReply(MsgInvalidToken, errors.New("invalid token"))
	}

	if _, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		//c.debugLogClaims(claims)
		c.log.Debug(" ### CREDENTIAL IS VALID ###")
		return &VerifyCredentialReply{Valid: true}, nil
	}

	//TODO(mk): if exist: verify that each passed disclosure match a claim hash found in jwt.payload

	//c.debugLogClaims(token.Claims.(jwt.MapClaims))

	//TODO(mk): if vp+sd-jwt: verify holderProof?

	c.log.Debug(" ### CREDENTIAL IS VALID ###")
	return &VerifyCredentialReply{Valid: true}, nil

}

type jwtHeader struct {
	Alg string `json:"alg" validate:"required,alg"`
	Typ string `json:"typ" validate:"required,typ"`
}

func extractAndDecodeJWTHeader(credential string) (*jwtHeader, error) {
	parts := strings.Split(credential, ".")
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT header: %w", err)
	}

	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to parse JWT header: %w", err)
	}

	return &header, nil
}

func isHeaderTypSupported(header *jwtHeader, allowedTyp []string) bool {
	for _, typ := range allowedTyp {
		if header.Typ == typ {
			return true
		}
	}
	return false
}

func isHeaderAlgSupported(header *jwtHeader, allowedAlg []string) bool {
	for _, alg := range allowedAlg {
		if header.Alg == alg {
			return true
		}
	}
	return false
}

func (c *Client) createInvalidReply(message string, err error) (*VerifyCredentialReply, error) {
	c.log.Debug(" ### INVALID CREDENTIAL ###", "message", message, "err", err)
	return &VerifyCredentialReply{Valid: false, Message: message}, nil
}

func (c *Client) debugLogClaims(claims jwt.MapClaims) {
	c.log.Debug("Token is valid. Claims:")
	for key, val := range claims {
		c.log.Debug("claim", "key", key, "val", val)
	}
}

func splitAndDecodeSDJWT(credential string) (*SDJWTParts, error) {
	parts := strings.Split(credential, "~")
	jwtParts := strings.Split(parts[0], ".")
	if len(jwtParts) != 3 {
		return nil, errors.New(MsgInvalidJwtStructure)
	}

	//TODO(mk): verify that it is a SD-JWT and not just a JWT after fix in issuer, ie has at least one ~ after signatureDecoded, ie headerDecoded.payloadDecoded.signatureDecoded~ (even if there are no disclosures)

	headerDecoded, err := decodeBase64URL(jwtParts[0])
	if err != nil {
		return nil, err
	}

	payloadDecoded, err := decodeBase64URL(jwtParts[1])
	if err != nil {
		return nil, err
	}

	signatureDecoded, err := decodeBase64URL(jwtParts[2])

	var disclosuresDecoded []string
	for _, disclosure := range parts[1:] {
		disclosureDecoded, err := decodeBase64URL(disclosure)
		if err != nil {
			return nil, err
		}
		disclosuresDecoded = append(disclosuresDecoded, disclosureDecoded)
	}

	return &SDJWTParts{
		JWTEncoded:         parts[0],
		HeaderDecoded:      headerDecoded,
		PayloadDecoded:     payloadDecoded,
		SignatureDecoded:   signatureDecoded,
		DisclosuresDecoded: disclosuresDecoded,
	}, nil
}

func extractJWK(payload string) (*JWK, error) {
	var payloadMap map[string]interface{}
	if err := json.Unmarshal([]byte(payload), &payloadMap); err != nil {
		return nil, errors.New("failed to parse payload JSON")
	}

	cnf, ok := payloadMap["cnf"].(map[string]interface{})
	if !ok {
		return nil, errors.New(MsgInvalidJwk)
	}

	jwkMap, ok := cnf["jwk"].(map[string]interface{})
	if !ok {
		return nil, errors.New(MsgInvalidJwk)
	}

	jwk := &JWK{}
	if x, ok := jwkMap["x"].(string); ok {
		jwk.X = x
	} else {
		return nil, errors.New("missing or invalid 'x' field in JWK")
	}

	if y, ok := jwkMap["y"].(string); ok {
		jwk.Y = y
	} else {
		return nil, errors.New("missing or invalid 'y' field in JWK")
	}

	if crv, ok := jwkMap["crv"].(string); ok {
		jwk.Crv = crv
	} else {
		return nil, errors.New("missing or invalid 'crv' field in JWK")
	}

	if kty, ok := jwkMap["kty"].(string); ok {
		jwk.Kty = kty
	} else {
		return nil, errors.New("missing or invalid 'kty' field in JWK")
	}

	return jwk, nil
}

func createPubKey(jwk *JWK) (*ecdsa.PublicKey, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("error decoding x: %w", err)
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("error decoding y: %w", err)
	}

	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}

	return pubKey, nil
}

func parseJWT(completeJWT string, pubKey *ecdsa.PublicKey) (*jwt.Token, error) {
	//TODO(mk): config what claims to check, ie use ParseWithClaims. Now only exp and nbf is checked if they exist
	return jwt.Parse(completeJWT, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return pubKey, nil
	})
}

func decodeBase64URL(encoded string) (string, error) {
	decodedBytes, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	return string(decodedBytes), nil
}

func decodeDisclosures(s *SDJWTParts) ([]string, error) {
	decodedDisclosures := make([]string, len(s.DisclosuresDecoded))

	for i, disclosure := range s.DisclosuresDecoded {
		decoded, err := decodeBase64URL(disclosure)
		if err != nil {
			return nil, fmt.Errorf("error decoding disclosure %d: %v", i, err)
		}
		decodedDisclosures[i] = decoded
	}

	return decodedDisclosures, nil
}
