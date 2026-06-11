package openid4vp

import (
	"encoding/json"
	"fmt"
	"slices"
)

type DCQL struct {
	// Credentials REQUIRED. A non-empty array of Credential Queries as defined in Section 6.1 that specify the requested Credentials.
	Credentials []CredentialQuery `json:"credentials" yaml:"credentials" validate:"required,min=1,dive,required"`

	// CredentialSets OPTIONAL. A non-empty array of Credential Set Queries as defined in Section 6.2 that specifies additional constraints on which of the requested Credentials to return.
	CredentialSets []CredentialSetQuery `json:"credential_sets,omitempty" yaml:"credential_sets,omitempty" validate:"omitnil,min=1,dive,required"`
}

// CredentialQuery is an object representing a request for a presentation of one or more matching Credentials.
type CredentialQuery struct {
	// ID REQUIRED. A string identifying the Credential in the response and, if provided, the constraints in credential_sets. The value MUST be a non-empty string consisting of alphanumeric, underscore (_), or hyphen (-) characters. Within the Authorization Request, the same id MUST NOT be present more than once.
	ID string `json:"id" yaml:"id" validate:"required"`

	// Format REQUIRED. A string that specifies the format of the requested Credential. Valid Credential Format Identifier values are defined in Appendix B.
	Format string `json:"format" yaml:"format" validate:"required"`

	// Multiple OPTIONAL. A boolean which indicates whether multiple Credentials can be returned for this Credential Query. If omitted, the default value is false.
	Multiple bool `json:"multiple,omitempty" yaml:"multiple,omitempty"`

	// Meta REQUIRED. An object defining additional properties requested by the Verifier that apply to the metadata and validity data of the Credential. The properties of this object are defined per Credential Format. Examples of those are in Appendix B.3.5 and Appendix B.2.3. If empty, no specific constraints are placed on the metadata or validity of the requested Credential.
	Meta MetaQuery `json:"meta" yaml:"meta" validate:"required"`

	// TrustedAuthorities OPTIONAL. A non-empty array of objects as defined in Section 6.1.1 that specifies expected authorities or trust frameworks that certify Issuers, that the Verifier will accept. Every Credential returned by the Wallet SHOULD match at least one of the conditions present in the corresponding trusted_authorities array if present.
	TrustedAuthorities []TrustedAuthority `json:"trusted_authorities,omitempty" yaml:"trusted_authorities,omitempty"`

	// RequireCryptographicHolderBinding OPTIONAL. A boolean which indicates whether the Verifier requires a Cryptographic Holder Binding proof. The default value is true, i.e., a Verifiable Presentation with Cryptographic Holder Binding is required. If set to false, the Verifier accepts a Credential without Cryptographic Holder Binding proof.
	RequireCryptographicHolderBinding bool `json:"require_cryptographic_holder_binding,omitempty" yaml:"require_cryptographic_holder_binding,omitempty"`

	// Claims OPTIONAL. A non-empty array of objects as defined in Section 6.3 that specifies claims in the requested Credential. Verifiers MUST NOT point to the same claim more than once in a single query. Wallets SHOULD ignore such duplicate claim queries.
	Claims []ClaimQuery `json:"claims,omitempty" yaml:"claims,omitempty"`

	// ClaimSet OPTIONAL. A non-empty array containing arrays of identifiers for elements in claims that specifies which combinations of claims for the Credential are requested. The rules for selecting claims to send are defined in Section 6.4.1.
	ClaimSet []string `json:"claim_sets,omitempty" yaml:"claim_sets,omitempty" validate:"omitnil,min=1,dive,required"`
}

type CredentialSetQuery struct {
	// Options REQUIRED A non-empty array, where each value in the array is a list of Credential Query identifiers representing one set of Credentials that satisfies the use case. The value of each element in the options array is a non-empty array of identifiers which reference elements in credentials.
	Options [][]string `json:"options" yaml:"options" validate:"required,min=1,dive,required,min=1,dive,required"`

	// Required OPTIONAL A boolean which indicates whether this set of Credentials is required to satisfy the particular use case at the Verifier. If omitted, the default value is true.
	Required bool `json:"required,omitempty" yaml:"required,omitempty"`

	// Purpose Can't find in spec, but in example from wwwallet
	Purpose string `json:"purpose,omitempty" yaml:"purpose,omitempty"`
}

// MetaQuery represents format-specific metadata constraints for credential queries.
// For SD-JWT VC format (dc+sd-jwt): use VCTValues
// For W3C VC format (ldp_vc): use TypeValues
type MetaQuery struct {
	// VCTValues for SD-JWT VC format (dc+sd-jwt).
	// A non-empty array of strings that specifies allowed values for the type of the requested Verifiable Credential.
	// All elements in the array MUST be valid type identifiers as defined in [I-D.ietf-oauth-sd-jwt-vc].
	// The Wallet MAY return Credentials that inherit from any of the specified types.
	VCTValues []string `json:"vct_values,omitempty" yaml:"vct_values,omitempty"`

	// TypeValues for W3C VC format (ldp_vc, jwt_vc_json).
	// A non-empty array of string arrays specifying the fully expanded types (IRIs) that the Verifier accepts.
	// Each top-level array specifies one alternative to match the fully expanded type values of the Verifiable Credential.
	// Each inner array specifies a set of fully expanded types that MUST be present in the credential's type property.
	TypeValues [][]string `json:"type_values,omitempty" yaml:"type_values,omitempty"`

	// DoctypeValue for ISO mdoc format (mso_mdoc).
	// String that specifies an allowed value for the doctype of the requested Verifiable Credential.
	DoctypeValue string `json:"doctype_value,omitempty" yaml:"doctype_value,omitempty"`
}

// VPFormatsSupported defines format-specific parameters for Verifier or Wallet metadata.
// Used in client_metadata and Wallet metadata to indicate supported formats and algorithms.
type VPFormatsSupported struct {
	// LDPVC is the configuration for W3C VC Data Integrity format (ldp_vc)
	LDPVC *LDPVCFormat `json:"ldp_vc,omitempty" yaml:"ldp_vc,omitempty"`

	// JWTVCJson is the configuration for JWT-based W3C VC format (jwt_vc_json)
	JWTVCJson *JWTVCFormat `json:"jwt_vc_json,omitempty" yaml:"jwt_vc_json,omitempty"`

	// SDJWT is the configuration for SD-JWT VC format (dc+sd-jwt)
	SDJWT *SDJWTVCFormat `json:"dc+sd-jwt,omitempty" yaml:"dc+sd-jwt,omitempty"`

	// MsoMdoc is the configuration for ISO mdoc format (mso_mdoc)
	MsoMdoc *MsoMdocFormat `json:"mso_mdoc,omitempty" yaml:"mso_mdoc,omitempty"`
}

// LDPVCFormat defines format-specific parameters for W3C VC Data Integrity (ldp_vc).
type LDPVCFormat struct {
	// ProofTypeValues is a non-empty array containing identifiers of proof types supported.
	// If present, the proof type of the presented VC/VP MUST match one of the array values.
	ProofTypeValues []string `json:"proof_type_values,omitempty" yaml:"proof_type_values,omitempty" doc_example:"[\"DataIntegrityProof\", \"Ed25519Signature2020\"]"`

	// CryptosuiteValues is a non-empty array containing identifiers of crypto suites supported.
	// Used when one of the algorithms in ProofTypeValues supports multiple crypto suites.
	CryptosuiteValues []string `json:"cryptosuite_values,omitempty" yaml:"cryptosuite_values,omitempty" doc_example:"[\"ecdsa-rdfc-2019\", \"ecdsa-sd-2023\", \"eddsa-rdfc-2022\", \"bbs-2023\"]"`
}

// JWTVCFormat defines format-specific parameters for JWT-based W3C VC (jwt_vc_json).
type JWTVCFormat struct {
	// AlgValues is a non-empty array containing identifiers of cryptographic algorithms supported.
	// If present, the alg JOSE header of the presented VC/VP MUST match one of the array values.
	AlgValues []string `json:"alg_values,omitempty" yaml:"alg_values,omitempty"`
}

// SDJWTVCFormat defines format-specific parameters for IETF SD-JWT VC (dc+sd-jwt).
type SDJWTVCFormat struct {
	// SDJWTAlgValues is a non-empty array containing cryptographic algorithm identifiers
	// supported for the Issuer-signed JWT of an SD-JWT.
	SDJWTAlgValues []string `json:"sd-jwt_alg_values,omitempty" yaml:"sd-jwt_alg_values,omitempty"`

	// KBJWTAlgValues is a non-empty array containing cryptographic algorithm identifiers
	// supported for a Key Binding JWT (KB-JWT).
	KBJWTAlgValues []string `json:"kb-jwt_alg_values,omitempty" yaml:"kb-jwt_alg_values,omitempty"`
}

// MsoMdocFormat defines format-specific parameters for ISO mdoc (mso_mdoc).
type MsoMdocFormat struct {
	// IssuerAuthAlgValues is a non-empty array containing cryptographic algorithm identifiers
	// supported for IssuerAuth COSE signatures.
	IssuerAuthAlgValues []int `json:"issuerauth_alg_values,omitempty" yaml:"issuerauth_alg_values,omitempty"`

	// DeviceAuthAlgValues is a non-empty array containing cryptographic algorithm identifiers
	// supported for DeviceAuth COSE signatures or MACs.
	DeviceAuthAlgValues []int `json:"deviceauth_alg_values,omitempty" yaml:"deviceauth_alg_values,omitempty"`
}

type TrustedAuthority struct {
	// REQUIRED. A string uniquely identifying the type of information about the issuer trust framework. Types defined by this specification are listed below.
	Type string `json:"type" yaml:"type" validate:"required,oneof=aki etsi_tl openid_federation"`

	// REQUIRED. A non-empty array of strings, where each string (value) contains information specific to the used Trusted Authorities Query type that allows the identification of an issuer, a trust framework, or a federation that an issuer belongs to.
	Values []string `json:"values" yaml:"values" validate:"required,min=1"`
}

type ClaimQuery struct {
	// Path REQUIRED The value MUST be a non-empty array representing a claims path pointer
	// that specifies the path to a claim within the Credential, as defined in Section 7.
	// Elements are strings (object keys) or nil (representing null for array element access).
	Path []*string `json:"-" yaml:"-" validate:"required,min=1"`
}

// MarshalJSON implements custom JSON marshaling for ClaimQuery.
// Nil path elements are serialized as JSON null (for DCQL array element access).
func (cq ClaimQuery) MarshalJSON() ([]byte, error) {
	path := make([]any, len(cq.Path))
	for i, p := range cq.Path {
		if p == nil {
			path[i] = nil
		} else {
			path[i] = *p
		}
	}
	return json.Marshal(struct {
		Path []any `json:"path"`
	}{Path: path})
}

// UnmarshalJSON implements custom JSON unmarshaling for ClaimQuery.
// JSON null path elements are deserialized as nil pointers; non-string/non-null
// elements cause an unmarshal error (Go's json package rejects them for *string).
func (cq *ClaimQuery) UnmarshalJSON(data []byte) error {
	var raw struct {
		Path []*string `json:"path"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if err := validateClaimPath(raw.Path); err != nil {
		return err
	}
	cq.Path = raw.Path
	return nil
}

// UnmarshalYAML implements custom YAML unmarshaling for ClaimQuery.
// YAML null path elements are deserialized as nil pointers; non-string/non-null
// elements cause an unmarshal error.
func (cq *ClaimQuery) UnmarshalYAML(unmarshal func(any) error) error {
	var raw struct {
		Path []*string `yaml:"path"`
	}
	if err := unmarshal(&raw); err != nil {
		return err
	}
	if err := validateClaimPath(raw.Path); err != nil {
		return err
	}
	cq.Path = raw.Path
	return nil
}

// validateClaimPath checks that the path is non-empty and that non-nil elements are not empty strings.
// Nil elements are valid (they represent JSON null for array element access).
func validateClaimPath(path []*string) error {
	if len(path) == 0 {
		return fmt.Errorf("claim path must not be empty")
	}
	for i, p := range path {
		if p != nil && *p == "" {
			return fmt.Errorf("claim path element at index %d must not be empty", i)
		}
	}
	return nil
}

// StringPath creates a []*string path from string arguments.
// This is a convenience for constructing ClaimQuery paths.
func StringPath(parts ...string) []*string {
	path := make([]*string, len(parts))
	for i := range parts {
		s := parts[i]
		path[i] = &s
	}
	return path
}

// ArrayElementPath creates a []*string path ending with nil (null) for array element access.
// Example: ArrayElementPath("nationalities") → ["nationalities", null]
func ArrayElementPath(parts ...string) []*string {
	path := make([]*string, len(parts)+1)
	for i := range parts {
		s := parts[i]
		path[i] = &s
	}
	path[len(parts)] = nil // null for array element access
	return path
}

//type ClaimQuery struct {
//	// ID REQUIRED if claim_sets is present in the Credential Query; OPTIONAL otherwise. A string identifying the particular claim. The value MUST be a non-empty string consisting of alphanumeric, underscore (_), or hyphen (-) characters. Within the particular claims array, the same id MUST NOT be present more than once.
//	ID string `json:"id,omitempty" validate:"omitempty,alphanumunicode"`
//
//	// Path REQUIRED The value MUST be a non-empty array representing a claims path pointer that specifies the path to a claim within the Credential, as defined in Section 7.
//	Path []string `json:"path" validate:"required,min=1,dive,required"`
//
//	// Values OPTIONAL A non-empty array of strings, integers or boolean values that specifies the expected values of the claim. If the values property is present, the Wallet SHOULD return the claim only if the type and value of the claim both match exactly for at least one of the elements in the array. Details of the processing rules are defined in Section 6.4.1.
//	Values []any `json:"values,omitempty" validate:"omitempty,min=1,dive,required"`
//}

// Credential format identifiers as defined in OpenID4VP Appendix B.
// Note: FormatLdpVC is defined in vc20_handler.go (vc20 build tag)
const (
	// FormatJwtVCJson is the format identifier for JWT-based W3C VC without JSON-LD.
	FormatJwtVCJson = "jwt_vc_json"
	// FormatSDJWTVC is the format identifier for IETF SD-JWT VC.
	FormatSDJWTVC = "dc+sd-jwt"
	// FormatMsoMdoc is the format identifier for ISO mdoc.
	FormatMsoMdoc = "mso_mdoc"
	// FormatLdpVCDCQL is the format identifier for W3C VC Data Integrity (used in DCQL).
	// Note: This duplicates FormatLdpVC from vc20_handler.go but is needed for non-vc20 builds.
	FormatLdpVCDCQL = "ldp_vc"
)

// IsW3CVCFormatIdentifier returns true if the format identifier is a W3C Verifiable Credential format (ldp_vc or jwt_vc_json).
func IsW3CVCFormatIdentifier(format string) bool {
	return format == "ldp_vc" || format == FormatJwtVCJson
}

// IsSDJWTFormatIdentifier returns true if the format identifier is SD-JWT VC format.
// Note: This is different from sdjwtvc.IsSDJWTFormat which checks the actual token format.
func IsSDJWTFormatIdentifier(format string) bool {
	return format == FormatSDJWTVC
}

// IsMdocFormat returns true if the format is ISO mdoc format.
func IsMdocFormat(format string) bool {
	return format == FormatMsoMdoc
}

// MatchTypeValues checks if a credential's types match any of the type_values alternatives.
// credentialTypes should be the fully expanded type IRIs from the credential.
// typeValues is the query's type_values constraint (array of string arrays).
// Returns true if the credential matches at least one of the alternatives.
func MatchTypeValues(credentialTypes []string, typeValues [][]string) bool {
	if len(typeValues) == 0 {
		return true // No constraints
	}

	// Check each alternative (outer array)
	for _, requiredTypes := range typeValues {
		if containsAll(credentialTypes, requiredTypes) {
			return true
		}
	}
	return false
}

// containsAll checks if all requiredTypes are present in credentialTypes.
func containsAll(credentialTypes []string, requiredTypes []string) bool {
	typeSet := make(map[string]bool)
	for _, t := range credentialTypes {
		typeSet[t] = true
	}

	for _, required := range requiredTypes {
		if !typeSet[required] {
			return false
		}
	}
	return true
}

// MatchCryptosuite checks if a cryptosuite is supported by the format configuration.
// Returns true if cryptosuiteValues is empty (no constraint) or contains the cryptosuite.
func MatchCryptosuite(cryptosuite string, cryptosuiteValues []string) bool {
	if len(cryptosuiteValues) == 0 {
		return true
	}
	return slices.Contains(cryptosuiteValues, cryptosuite)
}

// MatchProofType checks if a proof type is supported by the format configuration.
// Returns true if proofTypeValues is empty (no constraint) or contains the proofType.
func MatchProofType(proofType string, proofTypeValues []string) bool {
	if len(proofTypeValues) == 0 {
		return true
	}
	return slices.Contains(proofTypeValues, proofType)
}

// TrustedAuthorityType constants per OpenID4VP spec Section 6.1.1
const (
	// TrustedAuthorityTypeAKI is for Authority Key Identifier matching.
	// Value is base64url-encoded KeyIdentifier from AuthorityKeyIdentifier.
	TrustedAuthorityTypeAKI = "aki"

	// TrustedAuthorityTypeETSI is for ETSI Trusted List matching.
	// Value is the URL of the Trusted List (e.g., https://lotl.example.com).
	TrustedAuthorityTypeETSI = "etsi_tl"

	// TrustedAuthorityTypeOpenIDFederation is for OpenID Federation matching.
	// Value is the Entity Identifier of the Trust Anchor.
	TrustedAuthorityTypeOpenIDFederation = "openid_federation"
)

// TrustedAuthorityMatcher provides methods for matching credentials against trusted authorities.
// Implementations should integrate with trust frameworks (go-trust, ETSI TL, etc.).
type TrustedAuthorityMatcher interface {
	// MatchAKI checks if a credential's certificate chain contains a certificate
	// with the given Authority Key Identifier (base64url-encoded).
	MatchAKI(credentialCertChain [][]byte, aki string) bool

	// MatchETSI checks if a credential's issuer is present in the ETSI Trusted List.
	// The tlURL is the URL of the Trusted List or List of Trusted Lists.
	MatchETSI(credentialCertChain [][]byte, tlURL string) bool

	// MatchOpenIDFederation checks if a credential's issuer is part of an OpenID Federation
	// with the given Trust Anchor entity identifier.
	MatchOpenIDFederation(issuer string, trustAnchorEntityID string) bool
}

// MatchTrustedAuthorities checks if a credential matches any of the trusted authorities constraints.
// Returns true if trustedAuthorities is empty (no constraint) or the credential matches at least one.
// The matcher parameter provides the actual trust verification implementation.
// If matcher is nil, returns true (no validation performed).
func MatchTrustedAuthorities(
	trustedAuthorities []TrustedAuthority,
	credentialCertChain [][]byte,
	issuer string,
	matcher TrustedAuthorityMatcher,
) bool {
	// No constraints - accept all
	if len(trustedAuthorities) == 0 {
		return true
	}

	// No matcher provided - skip validation (trust decision made elsewhere)
	if matcher == nil {
		return true
	}

	// Check if credential matches ANY of the trusted authorities
	for _, ta := range trustedAuthorities {
		for _, value := range ta.Values {
			switch ta.Type {
			case TrustedAuthorityTypeAKI:
				if matcher.MatchAKI(credentialCertChain, value) {
					return true
				}
			case TrustedAuthorityTypeETSI:
				if matcher.MatchETSI(credentialCertChain, value) {
					return true
				}
			case TrustedAuthorityTypeOpenIDFederation:
				if matcher.MatchOpenIDFederation(issuer, value) {
					return true
				}
			}
		}
	}

	return false
}

// NewTrustedAuthorityAKI creates a TrustedAuthority for Authority Key Identifier matching.
func NewTrustedAuthorityAKI(akiValues ...string) TrustedAuthority {
	return TrustedAuthority{
		Type:   TrustedAuthorityTypeAKI,
		Values: akiValues,
	}
}

// NewTrustedAuthorityETSI creates a TrustedAuthority for ETSI Trusted List matching.
func NewTrustedAuthorityETSI(tlURLs ...string) TrustedAuthority {
	return TrustedAuthority{
		Type:   TrustedAuthorityTypeETSI,
		Values: tlURLs,
	}
}

// NewTrustedAuthorityOpenIDFederation creates a TrustedAuthority for OpenID Federation matching.
func NewTrustedAuthorityOpenIDFederation(trustAnchors ...string) TrustedAuthority {
	return TrustedAuthority{
		Type:   TrustedAuthorityTypeOpenIDFederation,
		Values: trustAnchors,
	}
}

// ValidateCredentialQuery validates that a CredentialQuery has the required fields
// for the specified format.
func ValidateCredentialQuery(query CredentialQuery) error {
	switch query.Format {
	case "ldp_vc", FormatJwtVCJson:
		// W3C VC format requires type_values
		if len(query.Meta.TypeValues) == 0 {
			return &DCQLValidationError{
				Field:   "meta.type_values",
				Message: "type_values is required for W3C VC format",
			}
		}
	case FormatSDJWTVC:
		// SD-JWT VC format requires vct_values
		if len(query.Meta.VCTValues) == 0 {
			return &DCQLValidationError{
				Field:   "meta.vct_values",
				Message: "vct_values is required for SD-JWT VC format",
			}
		}
	case FormatMsoMdoc:
		// ISO mdoc requires doctype_value
		if query.Meta.DoctypeValue == "" {
			return &DCQLValidationError{
				Field:   "meta.doctype_value",
				Message: "doctype_value is required for ISO mdoc format",
			}
		}
	default:
		// Unknown format - allow but don't validate
	}
	return nil
}

// DCQLValidationError represents a validation error in a DCQL query.
type DCQLValidationError struct {
	Field   string
	Message string
}

func (e *DCQLValidationError) Error() string {
	return "DCQL validation error on " + e.Field + ": " + e.Message
}

// NewVC20CredentialQuery creates a new CredentialQuery for W3C VC 2.0 Data Integrity format.
// typeValues should be an array of type alternatives, where each alternative is an array
// of fully expanded type IRIs that must all be present in the credential.
func NewVC20CredentialQuery(id string, typeValues [][]string, claims []ClaimQuery) CredentialQuery {
	return CredentialQuery{
		ID:     id,
		Format: "ldp_vc", // W3C VC Data Integrity format
		Meta: MetaQuery{
			TypeValues: typeValues,
		},
		Claims:                            claims,
		RequireCryptographicHolderBinding: true,
	}
}

// NewVC20VPFormatsSupported creates a VPFormatsSupported configuration for W3C VC 2.0
// Data Integrity format with the specified cryptosuites.
func NewVC20VPFormatsSupported(cryptosuites []string) VPFormatsSupported {
	return VPFormatsSupported{
		LDPVC: &LDPVCFormat{
			ProofTypeValues:   []string{"DataIntegrityProof"},
			CryptosuiteValues: cryptosuites,
		},
	}
}
