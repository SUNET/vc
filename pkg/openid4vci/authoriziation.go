package openid4vci

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
)

// maxAuthorizationDetailsBytes bounds the raw JSON encoding of
// authorization_details on every request path (form-body raw string, generic
// JSON body, and gin's JSON binder). Kept in one place so the form-tag
// validator (max=16384) and the JSON paths stay in lockstep.
const maxAuthorizationDetailsBytes = 16384

// AuthorizationDetailsParameter https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-using-authorization-details
type AuthorizationDetailsParameter struct {
	Type string `json:"type" form:"type" validate:"required,oneof=openid_credential"`

	// CredentialConfigurationID: REQUIRED when format parameter is not present. String specifying a unique identifier of the Credential being described in the credential_configurations_supported map in the Credential Issuer Metadata as defined in Section 11.2.3. The referenced object in the credential_configurations_supported map conveys the details, such as the format, for issuance of the requested Credential. This specification defines Credential Format specific Issuer Metadata in Appendix A. It MUST NOT be present if format parameter is present.
	CredentialConfigurationID string `json:"credential_configuration_id,omitempty" form:"credential_configuration_id" validate:"required_without=Format"`

	// Format REQUIRED when credential_configuration_id parameter is not present. String identifying the format of the Credential the Wallet needs. This Credential format identifier determines further claims in the authorization details object needed to identify the Credential type in the requested format. This specification defines Credential Format Profiles in Appendix A. It MUST NOT be present if credential_configuration_id parameter is present.
	Format string `json:"format,omitempty" form:"format" validate:"required_without=CredentialConfigurationID"`

	// VCT is the SD-JWT VC type identifier (Appendix A.3.2). Required for
	// format="vc+sd-jwt" / "dc+sd-jwt"; must be absent for other formats.
	// Enforced format-specifically in ParseAuthorizationDetails.
	VCT string `json:"vct,omitempty" form:"vct"`

	// Doctype is the ISO mdoc doctype identifier (Appendix A.2.2). Required
	// for format="mso_mdoc"; must be absent for other formats. Enforced
	// format-specifically in ParseAuthorizationDetails.
	Doctype string `json:"doctype,omitempty" form:"doctype"`

	// Claims OPTIONAL. Object as defined in Appendix A.3.2 excluding the display and value_type parameters. mandatory parameter here is used by the Wallet to indicate to the Issuer that it only accepts Credential(s) issued with those claim(s).
	Claims map[string]any `json:"claims,omitempty" form:"claims"`

	// CredentialIdentifiers REQUIRED (Token Response only). A non-empty array of strings, each uniquely identifying
	// a Credential Dataset that can be issued using the Access Token returned in this response.
	CredentialIdentifiers []string `json:"credential_identifiers,omitempty"`
}

// PARRequest https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#RFC6749
type PARRequest struct {
	// RFC 6749#4.1.1
	ResponseType string `form:"response_type" json:"response_type" validate:"required,oneof=code"`
	ClientID     string `json:"client_id" form:"client_id" validate:"required"`
	RedirectURI  string `json:"redirect_uri" form:"redirect_uri" validate:"required"`
	Scope        string `json:"scope" form:"scope"`
	State        string `json:"state" form:"state"`

	Prompt string `json:"prompt" form:"prompt"`
	// AuthorizationDetails carries the parsed authorization_details array. The
	// form-body variant is a single JSON-array string in AuthorizationDetailsRaw,
	// which the endpoint post-parses because gin's form binder cannot decode a
	// JSON array into a []struct field.
	AuthorizationDetails    []AuthorizationDetailsParameter `json:"authorization_details" form:"-"`
	AuthorizationDetailsRaw string                          `json:"-" form:"authorization_details" validate:"omitempty,max=16384"`
	CodeChallenge           string                          `json:"code_challenge" form:"code_challenge" validate:"required"`
	CodeChallengeMethod     string                          `json:"code_challenge_method" form:"code_challenge_method" validate:"required,oneof=S256 plain"`

	// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-additional-request-paramete
	WalletIssuer string `json:"wallet_issuer" form:"wallet_issuer"`
	UserHint     string `json:"user_hint" form:"user_hint"`
	IssuingState string `json:"issuing_state" form:"issuing_state"`

	// Client authentication via wallet attestation.
	// Supports two mechanisms per draft-ietf-oauth-attestation-based-client-auth-04:
	//  1. HTTP headers: OAuth-Client-Attestation + OAuth-Client-Attestation-PoP (§3.1)
	//  2. Form body: client_assertion + client_assertion_type (legacy, deprecated)
	// The standard-compliant mechanism (1) takes precedence.
	ClientAttestation    string `json:"-" form:"-" header:"OAuth-Client-Attestation"`
	ClientAttestationPoP string `json:"-" form:"-" header:"OAuth-Client-Attestation-PoP"`
	ClientAssertion      string `json:"client_assertion" form:"client_assertion" validate:"omitempty,max=8192,printascii"`
	ClientAssertionType  string `json:"client_assertion_type" form:"client_assertion_type" validate:"omitempty,max=256,printascii"`
}

type ParResponse struct {
	// RequestURI : The request URI corresponding to the authorization request posted. This URI is used as reference to the respective request data in the subsequent authorization request only. The way the authorization process obtains the authorization request data is at the discretion of the authorization server and out of scope of this specification. There is no need to make the authorization request data available to other parties via this URI.
	RequestURI string `json:"request_uri" form:"request_uri" validate:"required"`

	// ExpiresIn : A JSON number that represents the lifetime of the request URI in seconds. The request URI lifetime is at the discretion of the authorization server and will typically be relatively short.
	ExpiresIn int `json:"expires_in" form:"expires_in" validate:"required"`
}

type AuthorizeRequest struct {
	ClientID   string `json:"client_id" uri:"client_id" form:"client_id" validate:"required"`
	RequestURI string `json:"request_uri" uri:"request_uri" form:"request_uri" validate:"required"`
}

// AuthorizationResponse RFC6749#4.1.2
type AuthorizationResponse struct {
	//	Code REQUIRED.  The authorization code generated by the authorization server.  The authorization code MUST expire shortly after it is issued to mitigate the risk of leaks. A maximum authorization code lifetime of 10 minutes is RECOMMENDED.  The client MUST NOT use the authorization code more than once.  If an authorization code is used more than once, the authorization server MUST deny the request and SHOULD	revoke (when possible) all tokens previously issued based on that authorization code. The authorization code is bound to the client identifier and redirection URI.
	Code string `json:"code" validate:"required"`

	// State REQUIRED if the "state" parameter was present in the client authorization request.  The exact value received from the client.
	State string `json:"state" validate:"required"`

	RedirectURL string `json:"-"`

	Scope string `json:"-"`

	ClientID string `json:"-"`

	WalletClientID string `json:"-"`

	SessionID string `json:"-"`
}

// BindAuthorizationRequest binds the AuthorizationRequest
func BindAuthorizationRequest(body io.ReadCloser) (*PARRequest, error) {
	if body == nil {
		return nil, errors.New("no_body")
	}

	authorizationRequest := &PARRequest{}

	v := map[string]any{}
	var err error

	err = json.NewDecoder(body).Decode(&v)
	if err != nil {
		return nil, err
	}

	if details, ok := v["authorization_details"]; ok {
		delete(v, "authorization_details")
		// authorization_details may arrive as a JSON array (standard) or a
		// URL-encoded JSON-array string (form-body variant surfaced via the
		// generic JSON decode above). Reject anything else, including null.
		switch d := details.(type) {
		case string:
			authorizationRequest.AuthorizationDetailsRaw, err = url.QueryUnescape(d)
			if err != nil {
				return nil, err
			}
		case []any:
			raw, err := json.Marshal(d)
			if err != nil {
				return nil, err
			}
			if len(raw) > maxAuthorizationDetailsBytes {
				return nil, fmt.Errorf("authorization_details exceeds %d bytes", maxAuthorizationDetailsBytes)
			}
			authorizationRequest.AuthorizationDetailsRaw = string(raw)
		case nil:
			return nil, errors.New("authorization_details must not be null")
		default:
			return nil, fmt.Errorf("authorization_details must be a JSON array or encoded string, got %T", details)
		}

		if err := authorizationRequest.ParseAuthorizationDetails(); err != nil {
			return nil, err
		}
	}

	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	if err = json.Unmarshal(b, authorizationRequest); err != nil {
		return nil, err
	}

	return authorizationRequest, nil
}

// UnmarshalJSON captures the raw authorization_details value so JSON binders
// can reject a present-but-null field the same way the form parser does.
// gin's JSON binding otherwise treats null and an omitted field identically.
func (r *PARRequest) UnmarshalJSON(data []byte) error {
	type alias PARRequest
	aux := struct {
		AuthorizationDetails json.RawMessage `json:"authorization_details,omitempty"`
		*alias
	}{alias: (*alias)(r)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	raw := bytes.TrimSpace(aux.AuthorizationDetails)
	if len(raw) == 0 {
		return nil
	}
	if bytes.Equal(raw, []byte("null")) {
		return errors.New("authorization_details must not be null")
	}
	if len(raw) > maxAuthorizationDetailsBytes {
		return fmt.Errorf("authorization_details exceeds %d bytes", maxAuthorizationDetailsBytes)
	}
	if raw[0] != '[' {
		return errors.New("authorization_details must be a JSON array")
	}
	if err := json.Unmarshal(raw, &r.AuthorizationDetails); err != nil {
		return fmt.Errorf("authorization_details parse: %w", err)
	}
	return nil
}

// ParseAuthorizationDetails ensures AuthorizationDetails is populated and
// per-entry validated. It decodes the form-body JSON string in
// AuthorizationDetailsRaw when the slice is empty, then validates every
// entry (including entries populated by gin's JSON binder), so the same
// per-field validation applies regardless of the request encoding.
func (r *PARRequest) ParseAuthorizationDetails() error {
	if r == nil {
		return nil
	}
	if r.AuthorizationDetailsRaw != "" && len(r.AuthorizationDetails) == 0 {
		trimmed := bytes.TrimSpace([]byte(r.AuthorizationDetailsRaw))
		if len(trimmed) == 0 {
			return errors.New("authorization_details is empty")
		}
		if len(trimmed) > maxAuthorizationDetailsBytes {
			return fmt.Errorf("authorization_details exceeds %d bytes", maxAuthorizationDetailsBytes)
		}
		if trimmed[0] != '[' {
			return errors.New("authorization_details must be a JSON array")
		}
		if err := json.Unmarshal(trimmed, &r.AuthorizationDetails); err != nil {
			return fmt.Errorf("authorization_details parse: %w", err)
		}
	}
	r.AuthorizationDetailsRaw = ""
	if len(r.AuthorizationDetails) == 0 {
		return nil
	}
	validate, err := NewValidator()
	if err != nil {
		return err
	}
	for i := range r.AuthorizationDetails {
		detail := &r.AuthorizationDetails[i]
		if detail.CredentialConfigurationID != "" && detail.Format != "" {
			return fmt.Errorf("authorization_details[%d]: credential_configuration_id and format are mutually exclusive", i)
		}
		if err := detail.checkFormatFields(); err != nil {
			return fmt.Errorf("authorization_details[%d]: %w", i, err)
		}
		if err := validate.Struct(detail); err != nil {
			return fmt.Errorf("authorization_details[%d]: %w", i, err)
		}
	}
	return nil
}

// checkFormatFields enforces which of vct/doctype belongs with which format.
// Unknown formats are permissive so downstream (issuer metadata lookup) owns
// the final say; the credential_configuration_id path (Format=="") must have
// neither field set.
func (a *AuthorizationDetailsParameter) checkFormatFields() error {
	switch a.Format {
	case "":
		if a.VCT != "" {
			return errors.New("vct requires format")
		}
		if a.Doctype != "" {
			return errors.New("doctype requires format")
		}
	case "vc+sd-jwt", "dc+sd-jwt":
		if a.VCT == "" {
			return fmt.Errorf("format %q requires vct", a.Format)
		}
		if a.Doctype != "" {
			return fmt.Errorf("doctype not permitted with format %q", a.Format)
		}
	case "mso_mdoc":
		if a.Doctype == "" {
			return fmt.Errorf("format %q requires doctype", a.Format)
		}
		if a.VCT != "" {
			return fmt.Errorf("vct not permitted with format %q", a.Format)
		}
	}
	return nil
}
