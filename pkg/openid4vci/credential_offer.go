package openid4vci

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	vccrypto "github.com/SUNET/vc/pkg/crypto"
	"github.com/google/uuid"
	"github.com/skip2/go-qrcode"
)

// CredentialOfferParameters https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-parameters
type CredentialOfferParameters struct {
	CredentialIssuer           string         `json:"credential_issuer" bson:"credential_issuer" validate:"required"`
	CredentialConfigurationIDs []string       `json:"credential_configuration_ids" bson:"credential_configuration_ids" validate:"required"`
	Grants                     map[string]any `json:"grants"`
}

// Grant type constants used as map keys in CredentialOfferParameters.Grants
// and as GrantType values in TokenRequest.
const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypePreAuthorizedCode = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
)

// CredentialOfferResult wraps a credential offer with its pre-authorized code.
type CredentialOfferResult struct {
	CredentialOfferParameters
	ID string `json:"-"`
}

// Marshal marshals the CredentialOffer
func (c *CredentialOfferParameters) Marshal() ([]byte, error) {
	return json.Marshal(c)
}

// GrantAuthorizationCode authorization code grant
type GrantAuthorizationCode struct {
	IssuerState         string `json:"issuer_state" bson:"issuer_state"`
	AuthorizationServer string `json:"authorization,omitempty" bson:"authorization_server,omitempty"`
}

// GrantPreAuthorizedCode authorization code grant
type GrantPreAuthorizedCode struct {
	PreAuthorizedCode   string `json:"pre-authorized_code" bson:"pre-authorized_code" validate:"required"`
	TXCode              *TXCode `json:"tx_code,omitempty" bson:"tx_code,omitempty"`
	AuthorizationServer string  `json:"authorization_server,omitempty" bson:"authorization_server,omitempty"`
}

// TXCode Transaction Code
type TXCode struct {
	InputMode   string `json:"input_mode,omitempty" bson:"input_mode,omitempty" validate:"omitempty,oneof=numeric text"`
	Length      int    `json:"length,omitempty" bson:"length,omitempty"`
	Description string `json:"description,omitempty" bson:"description,omitempty"`
}

type CredentialOfferURIRequest struct {
	CredentialOfferUUID string `uri:"credential_offer_uuid" binding:"required" validate:"required,max=128,printascii"`
}

type CredentialOfferURIResponse struct{}

type CredentialOfferURI string

func (c *CredentialOfferURI) String() string {
	return string(*c)
}

func (c *CredentialOfferURI) QR(recoveryLevel, size int, walletURL, issuerURL string) (*QR, error) {
	u, err := url.Parse(issuerURL)
	if err != nil {
		return nil, err
	}

	q := u.Query()
	q.Set("credential_offer_uri", c.String())

	if walletURL == "" {
		walletURL = "openid-credential-offer://"
	}

	credentialOfferURL := fmt.Sprintf("%s?%s", walletURL, q.Encode())

	qrPNG, err := qrcode.Encode(credentialOfferURL, qrcode.RecoveryLevel(recoveryLevel), size)
	if err != nil {
		return nil, err
	}

	qrBase64 := base64.StdEncoding.EncodeToString(qrPNG)

	qr := &QR{
		QRBase64:           qrBase64,
		CredentialOfferURL: credentialOfferURL,
	}

	return qr, nil
}

// CredentialOffer URI
type CredentialOffer string

func (c *CredentialOffer) String() string {
	return string(*c)
}

// Unpack unpacks the CredentialOffer string into a CredentialOfferParameters
func (c *CredentialOffer) Unpack(ctx context.Context) (*CredentialOfferParameters, error) {
	_, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	u, err := url.Parse(c.String())
	if err != nil {
		return nil, err
	}

	credentialOffer := u.Query().Get("credential_offer")
	credentialOfferParameter := &CredentialOfferParameters{}
	if err := json.Unmarshal([]byte(credentialOffer), &credentialOfferParameter); err != nil {
		return nil, err
	}

	// grant type authorization_code
	authorizationCodeGrant, ok := credentialOfferParameter.Grants["authorization_code"]
	if ok {
		b, err := json.Marshal(authorizationCodeGrant)
		if err != nil {
			return nil, err
		}
		grant := &GrantAuthorizationCode{}
		if err := json.Unmarshal(b, grant); err != nil {
			return nil, err
		}

		credentialOfferParameter.Grants["authorization_code"] = grant
	}

	// grant type pre-authorized_code
	preAuthorizedCodeGrant, ok := credentialOfferParameter.Grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
	if ok {
		b, err := json.Marshal(preAuthorizedCodeGrant)
		if err != nil {
			return nil, err
		}
		grant := &GrantPreAuthorizedCode{}
		if err := json.Unmarshal(b, grant); err != nil {
			return nil, err
		}

		credentialOfferParameter.Grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"] = grant
	}

	return credentialOfferParameter, nil
}

// QR not part of the spec, for convenience
type QR struct {
	QRBase64           string `json:"qr_base64" bson:"qr_base64"`
	CredentialOfferURL string `json:"credential_offer_url" bson:"credential_offer_url"`
}

// QR returns a base64 encoded QR code, for convenience not part of the spec
func (c *CredentialOffer) QR(recoveryLevel, size int, walletURL string) (*QR, error) {
	if walletURL == "" {
		walletURL = "openid-credential-offer://"
	}

	qrURL := fmt.Sprintf("%s?%s", walletURL, c.String())

	qrPNG, err := qrcode.Encode(qrURL, qrcode.RecoveryLevel(recoveryLevel), size)
	if err != nil {
		return nil, err
	}

	qrBase64 := base64.StdEncoding.EncodeToString(qrPNG)

	qr := &QR{
		QRBase64:           qrBase64,
		CredentialOfferURL: qrURL,
	}

	return qr, nil
}

// CredentialOfferURI https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-sending-credential-offer-by-uri
func (c *CredentialOfferParameters) CredentialOfferURI() (CredentialOfferURI, error) {
	u, err := url.Parse(c.CredentialIssuer)
	if err != nil {
		return "", err
	}

	q := u.JoinPath("credential-offer", uuid.NewString())

	return CredentialOfferURI(q.String()), nil
}

func (c *CredentialOfferURI) UUID() (string, error) {
	u, err := url.Parse(c.String())
	if err != nil {
		return "", err
	}

	credentialOfferUUID := u.Path[len("/credential-offer/"):]

	return credentialOfferUUID, nil
}

// CredentialOffer creates a credential offer
func (c *CredentialOfferParameters) CredentialOffer() (CredentialOffer, error) {
	credentialOfferByte, err := c.Marshal()
	if err != nil {
		return "", err
	}

	urlValues := url.Values{
		"credential_offer": {string(credentialOfferByte)},
	}

	credentialOfferURL := urlValues.Encode()

	return CredentialOffer(credentialOfferURL), nil
}

// ParseCredentialOfferURI parses a credential offer URI to a CredentialOfferParameters
func ParseCredentialOfferURI(credentialOfferURI string) (*CredentialOfferParameters, error) {
	u, err := url.Parse(credentialOfferURI)
	if err != nil {
		return nil, err
	}

	credentialOffer := u.Query().Get("credential_offer")
	credentialOfferParameter := &CredentialOfferParameters{}
	if err := json.Unmarshal([]byte(credentialOffer), &credentialOfferParameter); err != nil {
		return nil, err
	}

	authorizationCode, ok := credentialOfferParameter.Grants["authorization_code"]
	if ok {
		b, err := json.Marshal(authorizationCode)
		if err != nil {
			return nil, err
		}

		grant := &GrantAuthorizationCode{}
		if err := json.Unmarshal(b, grant); err != nil {
			return nil, err
		}
		credentialOfferParameter.Grants["authorization_code"] = grant
	}

	preAuthorizedCode, ok := credentialOfferParameter.Grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
	if ok {
		b, err := json.Marshal(preAuthorizedCode)
		if err != nil {
			return nil, err
		}

		grant := &GrantPreAuthorizedCode{}
		if err := json.Unmarshal(b, grant); err != nil {
			return nil, err
		}
		credentialOfferParameter.Grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"] = grant
	}

	return credentialOfferParameter, nil
}

// NewCredentialOffer creates an OpenID4VCI credential offer for the given grant type.
// Supported grant types: GrantTypePreAuthorizedCode, GrantTypeAuthorizationCode.
func NewCredentialOffer(issuerURL, credentialConfigID, grantType string) (*CredentialOfferResult, error) {
	token, err := vccrypto.GenerateSecureToken(0, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	var grant any
	switch grantType {
	case GrantTypePreAuthorizedCode:
		grant = GrantPreAuthorizedCode{
			PreAuthorizedCode: token,
		}
	case GrantTypeAuthorizationCode:
		grant = GrantAuthorizationCode{
			IssuerState: token,
		}
	default:
		return nil, fmt.Errorf("unsupported grant type: %s", grantType)
	}

	return &CredentialOfferResult{
		CredentialOfferParameters: CredentialOfferParameters{
			CredentialIssuer:           issuerURL,
			CredentialConfigurationIDs: []string{credentialConfigID},
			Grants: map[string]any{
				grantType: grant,
			},
		},
		ID: token,
	}, nil
}
