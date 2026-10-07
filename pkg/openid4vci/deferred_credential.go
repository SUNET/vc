package openid4vci

// DeferredCredentialRequest https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-deferred-credential-request
type DeferredCredentialRequest struct {
	TransactionID string `json:"transaction_id" validate:"required"`

	// CredentialResponseEncryption OPTIONAL. As defined for the Credential
	// Request (§8.2). §9.1 is explicit that this object is the one used for
	// the Deferred Credential Response "regardless of what was sent in the
	// initial Credential Request", which is what keeps key management
	// tractable across a long deferral - so it is read from this request and
	// never inherited.
	CredentialResponseEncryption *CredentialResponseEncryption `json:"credential_response_encryption,omitempty" validate:"omitempty"`
}
