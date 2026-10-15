package apiv1

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/oauth2"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/google/uuid"
)

// UIPaymentRequest asks /ui/interaction to attach an EC TS12 payment
// transaction_data entry (urn:eudi:sca:payment:1) to the request. It is the
// operator-facing shape; the wire entry is built from it by
// buildPaymentTransactionData, never the other way round.
type UIPaymentRequest struct {
	// Amount is the payment amount in major currency units, as a JSON number or a numeric string ("49.99"). Must be greater than zero.
	Amount PaymentAmount `json:"amount" validate:"required"`
	// Currency is an ISO 4217 alpha-3 code.
	Currency string `json:"currency" validate:"required"`
	// PayeeName and PayeeID are REQUIRED by the TS12 payment schema.
	PayeeName    string `json:"payee_name" validate:"required,max=256"`
	PayeeID      string `json:"payee_id" validate:"required,max=256"`
	PayeeWebsite string `json:"payee_website,omitempty" validate:"omitempty,max=512"`
	// TransactionID is the relying party's identifier of the interaction (1..36 characters). A fresh UUID when omitted.
	TransactionID string `json:"transaction_id,omitempty" validate:"omitempty,max=36"`
	// CredentialID is the DCQL credential query id of the SCA attestation that authorizes the payment. Required when the DCQL query has more than one credential query.
	CredentialID string `json:"credential_id,omitempty" validate:"omitempty,max=128"`
}

// PaymentAmount is the amount as the caller wrote it: a JSON number or a
// string. Decoding keeps the literal text and judges nothing, so that a bad
// amount ("token", true, {}) is refused by buildPaymentTransactionData as a
// 400 invalid_request with a description, instead of failing inside the JSON
// decoder as an error the status mapper cannot classify.
type PaymentAmount string

// UnmarshalJSON implements json.Unmarshaler.
func (a *PaymentAmount) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*a = PaymentAmount(s)
		return nil
	}
	if string(b) == "null" {
		*a = ""
		return nil
	}
	*a = PaymentAmount(b)
	return nil
}

func invalidPayment(format string, args ...any) error {
	// The shared type: RegEndpoint renders pkg/oauth2.OAuthError (status and
	// description); the verifier-local OAuthError would fall through to the
	// generic handler and lose both.
	return &oauth2.OAuthError{
		ErrorCode:        ErrCodeInvalidRequest,
		ErrorDescription: "payment: " + fmt.Sprintf(format, args...),
		HTTPStatus:       http.StatusBadRequest,
	}
}

// buildPaymentTransactionData validates a payment request against the DCQL
// query and returns the base64url transaction_data strings to send. It fails
// closed: TS12 v1.0.1 covers SD-JWT VC only, so anything that cannot be bound
// to a holder-bound SD-JWT VC credential query is refused rather than sent.
func (c *Client) buildPaymentTransactionData(p *UIPaymentRequest, dcql *openid4vp.DCQL) ([]string, error) {
	if !c.cfg.Verifier.TS12.Enable {
		return nil, invalidPayment("TS12 payment requests are not enabled on this verifier (verifier.ts12.enable)")
	}
	if dcql == nil || len(dcql.Credentials) == 0 {
		return nil, invalidPayment("a DCQL query with the SCA attestation is required")
	}

	var target *openid4vp.CredentialQuery
	if p.CredentialID == "" {
		if len(dcql.Credentials) != 1 {
			return nil, invalidPayment("credential_id is required when the DCQL query has more than one credential query")
		}
		target = &dcql.Credentials[0]
	} else {
		for i := range dcql.Credentials {
			if dcql.Credentials[i].ID == p.CredentialID {
				if target != nil {
					// DCQL requires unique ids; two matches leave it unclear which query's format and holder binding apply.
					return nil, invalidPayment("credential_id %q names more than one credential query", p.CredentialID)
				}
				target = &dcql.Credentials[i]
			}
		}
		if target == nil {
			return nil, invalidPayment("credential_id %q does not name a credential query", p.CredentialID)
		}
	}
	if target.Format != openid4vp.FormatSDJWTVC {
		return nil, invalidPayment("credential query %q has format %q; TS12 payment SCA requires %q", target.ID, target.Format, openid4vp.FormatSDJWTVC)
	}
	if len(target.Meta.VCTValues) == 0 {
		// Without a vct constraint any credential the trust policy accepts
		// could authorize the payment: the response check compares the
		// presented credential's vct against these values.
		return nil, invalidPayment("credential query %q must name the SCA attestation with meta.vct_values", target.ID)
	}
	if !target.RequiresCryptographicHolderBinding() {
		return nil, invalidPayment("credential query %q disables cryptographic holder binding, which transaction_data requires", target.ID)
	}

	txID := p.TransactionID
	if txID == "" {
		txID = uuid.NewString()
	}
	td, err := openid4vp.NewTS12PaymentTransactionData(openid4vp.TS12PaymentPayload{
		TransactionID: txID,
		Payee:         openid4vp.TS12Payee{Name: p.PayeeName, ID: p.PayeeID, Website: p.PayeeWebsite},
		Currency:      p.Currency,
		Amount:        openid4vp.RawNumber(p.Amount),
	}, []string{target.ID}, c.cfg.Verifier.TS12.HashAlgs)
	if err != nil {
		return nil, invalidPayment("%v", err)
	}
	encoded, err := td.Base64Encode()
	if err != nil {
		return nil, fmt.Errorf("encoding transaction_data: %w", err)
	}
	return []string{encoded}, nil
}

// issuedResponseModes are the response_mode values the verifier puts in the
// requests it issues for /ui/interaction: direct_post.jwt behind the QR code
// and link, and dc_api.jwt for the Digital Credentials API variant when that
// is enabled. The response arrives at one endpoint whichever was used, so a
// TS12 KB-JWT may echo either. Recorded on the session at issuance.
// TS12 KB-JWT may echo either.
func (c *Client) issuedResponseModes() []string {
	modes := []string{openid4vp.ResponseModeDirectPostJWT}
	if c.cfg.Verifier.DigitalCredentials.Enable {
		modes = append(modes, openid4vp.ResponseModeDCAPIJWT)
	}
	return modes
}

// claimJTI records a presented jti, refusing a repeat. With no replay cache it
// refuses: jti uniqueness cannot be honoured, so the presentation cannot be.
func (c *Client) claimJTI(ctx context.Context, jti string) error {
	refuse := func(format string, args ...any) error {
		return &openid4vp.ErrorResponse{ErrorCode: openid4vp.ErrorInvalidTransactionData, ErrorDescription: fmt.Sprintf(format, args...)}
	}
	if c.cacheService == nil || c.cacheService.UsedJTI == nil {
		return refuse("cannot verify jti freshness: no replay store configured")
	}
	// Atomic: a concurrent second submission of the same KB-JWT loses SetNX.
	fresh, err := c.cacheService.UsedJTI.SetNX(ctx, jti, true)
	if err != nil {
		return refuse("cannot verify jti freshness: %v", err)
	}
	if !fresh {
		return refuse("jti has been used before")
	}
	return nil
}

// checkBoundCredentialType refuses a presented credential whose vct is not one
// the bound credential query asked for. Fails closed: when the query cannot be
// found for this session (for example the DCQL is not available on this
// replica) the type cannot be compared and the presentation is refused.
func (c *Client) checkBoundCredentialType(authCtx *cache.AuthorizationContext, scopeQueryIDs map[string]string, scope string, claims map[string]any) error {
	refuse := func(format string, args ...any) error {
		return &openid4vp.ErrorResponse{ErrorCode: openid4vp.ErrorInvalidTransactionData, ErrorDescription: fmt.Sprintf(format, args...)}
	}
	query, ok := c.requestedQueryExact(authCtx, scopeQueryIDs, scope)
	if !ok {
		return refuse("cannot compare the credential type: the request's credential query is not available")
	}
	if len(query.Meta.VCTValues) == 0 {
		return refuse("cannot compare the credential type: the request named no vct_values")
	}
	vct, _ := claims["vct"].(string)
	if vct == "" {
		return refuse("credential has no vct")
	}
	if !slices.Contains(query.Meta.VCTValues, vct) {
		return refuse("credential vct %q is not one the request asked for", vct)
	}
	return nil
}
