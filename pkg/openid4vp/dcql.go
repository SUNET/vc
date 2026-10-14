package openid4vp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"slices"

	"github.com/SUNET/vc/pkg/vc20/credential"
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

	// RequireCryptographicHolderBinding OPTIONAL. Spec default is true when omitted; nil pointer preserves that distinction from an explicit false.
	RequireCryptographicHolderBinding *bool `json:"require_cryptographic_holder_binding,omitempty" yaml:"require_cryptographic_holder_binding,omitempty"`

	// Claims OPTIONAL. A non-empty array of objects as defined in Section 6.3 that specifies claims in the requested Credential. Verifiers MUST NOT point to the same claim more than once in a single query. Wallets SHOULD ignore such duplicate claim queries.
	Claims []ClaimQuery `json:"claims,omitempty" yaml:"claims,omitempty"`

	// ClaimSet OPTIONAL. A non-empty array containing arrays of identifiers for elements in claims that specifies which combinations of claims for the Credential are requested. The rules for selecting claims to send are defined in Section 6.4.1.
	ClaimSet [][]string `json:"claim_sets,omitempty" yaml:"claim_sets,omitempty" validate:"omitnil,min=1,dive,required,min=1,dive,required"`

	// Req is the circuit_zk format's list of requested calculations.
	//
	// It replaces Claims rather than accompanying it: a circuit_zk
	// presentation discloses no issuer-signed attribute at all, so every
	// value a Verifier wants is the output of a function named here. A
	// query carrying both is one the planner rejects - which this does
	// not prevent, because sending it is how a wallet gets tested.
	Req []ReqItem `json:"req,omitempty" yaml:"req,omitempty"`

	// Extra carries members this build does not know about, flattened
	// alongside the known ones.
	//
	// The request shape is moving - the nym_auth rulebook, OpenID4VP and
	// the DC API all - and wallets of several generations will be in the
	// field at once. Without somewhere to put a member this code has never
	// heard of, talking to any of them means waiting for a release here.
	Extra map[string]any `json:"-" yaml:"-"`

	// Raw replaces this query entirely: when set, it is emitted as exactly
	// these bytes and every other field is ignored.
	//
	// Extra covers a shape that ADDS members. This covers one that changes
	// the type of a member already modelled - the rulebook's WIP example
	// makes "claims" an object where DCQL has an array, and a future
	// generation could do the same to "req" or "meta". A per-member
	// override for each of those is a field this struct grows every time a
	// specification moves; one raw escape hatch covers all of them and
	// needs no release here.
	//
	// It is deliberately all-or-nothing. A half-raw query would leave an
	// operator guessing which of the two sources a given member came from.
	Raw json.RawMessage `json:"-" yaml:"-"`
}

// MarshalYAML flattens Extra alongside the known members, so a query read
// from configuration can be written back out whole.
func (q CredentialQuery) MarshalYAML() (any, error) {
	type plain CredentialQuery
	encoded, err := json.Marshal(plain(q))
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := decodeExact(encoded, &m); err != nil {
		return nil, err
	}
	return mergeExtraYAML(m, q.Extra, declaredJSONKeys(reflect.TypeOf(CredentialQuery{})), "credential query")
}

// UnmarshalYAML captures every member other than the modelled ones.
//
// Without it a presentation request template - which pkg/configuration
// loads from YAML into an openid4vp.DCQL - could not carry a member this
// build does not model, which is the whole purpose of Extra.
//
// The known members go through a methodless alias so yaml.v2 applies the
// struct tags and reports a wrong type itself, rather than this coercing
// one. See the note above ReqItem.UnmarshalYAML for why nothing here
// passes through JSON on the way.
func (q *CredentialQuery) UnmarshalYAML(unmarshal func(any) error) error {
	type plain CredentialQuery
	var known plain
	if err := unmarshal(&known); err != nil {
		return fmt.Errorf("credential query: %w", err)
	}
	*q = CredentialQuery(known)

	extra, err := yamlExtra(unmarshal, "credential query",
		"id", "format", "multiple", "meta", "trusted_authorities",
		"require_cryptographic_holder_binding", "claims", "claim_sets", "req")
	if err != nil {
		return err
	}
	q.Extra = extra
	return nil
}

// MarshalJSON flattens Extra alongside the known members.
//
// With Extra empty this is byte-identical to the struct encoding it
// replaces, which TestCredentialQueryEncodingUnchanged pins: every format
// other than circuit_zk goes through here too, and none of them should be
// able to tell this method exists.
func (q CredentialQuery) MarshalJSON() ([]byte, error) {
	if q.Raw != nil {
		if q.Extra != nil {
			return nil, fmt.Errorf("credential query: raw and extra are both set, and raw would discard extra")
		}
		if !json.Valid(q.Raw) {
			return nil, fmt.Errorf("credential query: raw is not valid JSON")
		}
		return q.Raw, nil
	}
	type plain CredentialQuery // no methods, so no recursion
	return marshalWithExtra(plain(q), q.Extra, "credential query")
}

// UnmarshalJSON collects unknown members into Extra.
func (q *CredentialQuery) UnmarshalJSON(data []byte) error {
	type plain CredentialQuery
	var known plain
	if err := decodeExact(data, &known); err != nil {
		// A shape the model cannot hold is kept verbatim rather than
		// refused. Decoding has to be TOTAL for the escape hatch to be
		// worth anything: a request object is JSON-encoded into the HA
		// cache and read back by another node, so a raw query with - say -
		// an object at "claims" would be written out fine and then fail to
		// load anywhere but the node that built it.
		//
		// It also keeps the verifier's own promise. This serialiser does
		// not repair a request, and refusing to read back something it
		// just wrote would be a repair by other means.
		if !json.Valid(data) {
			return err
		}
		*q = CredentialQuery{Raw: append(json.RawMessage(nil), data...)}
		q.adoptRawRouting()
		return nil
	}
	*q = CredentialQuery(known)
	extra, err := unknownMembers(data,
		"id", "format", "multiple", "meta", "trusted_authorities",
		"require_cryptographic_holder_binding", "claims", "claim_sets", "req")
	if err != nil {
		return err
	}
	q.Extra = extra
	return nil
}

// adoptRawRouting copies the members the REST of the stack routes by out
// of the raw bytes and into the struct.
//
// Raw is authoritative for the wire, but it is not the only reader.
// UIInteraction copies ID into the authorization context's scopes and the
// response path looks a presentation up by it, so a query that arrives
// raw and keeps an empty ID is sent correctly and then cannot be matched
// to anything that comes back. Format is read the same way, by
// ValidateCredentialQuery and by every format decision after it.
//
// Best effort by design: each member is taken only if it is there and is
// a string. A query whose "id" is a number is a query this build has no
// opinion about, which is the whole reason it went down this path.
func (q *CredentialQuery) adoptRawRouting() {
	id, format := q.rawRouting()
	if id != "" {
		q.ID = id
	}
	if format != "" {
		q.Format = format
	}
}

// rawRouting reads id and format out of the raw bytes, which are the
// source of truth for both.
//
// Read here rather than trusted from the struct because the struct's
// copies are only populated by UnmarshalJSON. A query built in code -
// CredentialQuery{Raw: ...}, which is how the escape hatch is meant to be
// used directly - carries none, and an empty Format means SD-JWT to every
// reader, so a raw circuit_zk query would be refused for a missing
// vct_values it was never going to have.
func (q CredentialQuery) rawRouting() (id, format string) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(q.Raw, &members); err != nil {
		return "", "" // not an object at all; nothing to route by
	}
	for name, into := range map[string]*string{"id": &id, "format": &format} {
		var value string
		if err := json.Unmarshal(members[name], &value); err == nil {
			*into = value
		}
	}
	return id, format
}

// rawMeta re-reads just the meta member of a raw query, and reports
// whether it could.
//
// The typed decode of the whole query failed - that is why these bytes
// are raw - but the member that CARRIES THE CONSTRAINT usually survives
// intact: the WIP rulebook shape, for instance, only changes "claims".
// Re-reading it means a raw query is still judged by its format's rule
// rather than waved through, which is what keeps an unconstrained SD-JWT
// request from being signed and served just because some other member
// had a shape this build does not model.
func (q CredentialQuery) rawMeta() (MetaQuery, bool) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(q.Raw, &members); err != nil {
		return MetaQuery{}, false
	}
	raw, present := members["meta"]
	if !present {
		// Absent, not unreadable. An absent meta is an ABSENT CONSTRAINT,
		// which is exactly the case the format rules exist to refuse, so
		// this reports a zero MetaQuery as readable rather than giving up.
		return MetaQuery{}, true
	}
	var meta MetaQuery
	if err := json.Unmarshal(raw, &meta); err != nil {
		return MetaQuery{}, false
	}
	return meta, true
}

type CredentialSetQuery struct {
	// Options REQUIRED A non-empty array, where each value in the array is a list of Credential Query identifiers representing one set of Credentials that satisfies the use case. The value of each element in the options array is a non-empty array of identifiers which reference elements in credentials.
	Options [][]string `json:"options" yaml:"options" validate:"required,min=1,dive,required,min=1,dive,required"`

	// Required OPTIONAL. Spec default is true when omitted; nil pointer preserves that distinction from an explicit false.
	Required *bool `json:"required,omitempty" yaml:"required,omitempty"`
}

// IsRequired returns the effective value of Required, applying the OpenID4VP
// 1.0 §6.2 default (true) when the field was omitted.
func (q CredentialSetQuery) IsRequired() bool {
	if q.Required == nil {
		return true
	}
	return *q.Required
}

// RequiresCryptographicHolderBinding returns the effective value of
// RequireCryptographicHolderBinding, applying the OpenID4VP 1.0 §6.1
// default (true) when the field was omitted.
func (q CredentialQuery) RequiresCryptographicHolderBinding() bool {
	if q.RequireCryptographicHolderBinding == nil {
		return true
	}
	return *q.RequireCryptographicHolderBinding
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

	// DoctypeValue for ISO mdoc format (mso_mdoc) and ZK-mdoc format (mso_mdoc_zk).
	// String that specifies an allowed value for the doctype of the requested Verifiable Credential.
	DoctypeValue string `json:"doctype_value,omitempty" yaml:"doctype_value,omitempty"`

	// ZKSystemType for ZK-mdoc format (mso_mdoc_zk) only.
	// A non-empty array of ZK proof system/circuit variants the Verifier is
	// willing to accept (e.g. Longfellow circuits for different attribute
	// counts). See ZKSystemTypeSpec and dcql_zk.go.
	ZKSystemType []ZKSystemTypeSpec `json:"zk_system_type,omitempty" yaml:"zk_system_type,omitempty"`

	// PPIDContext for ZK-mdoc format (mso_mdoc_zk) only.
	// An optional verifier-supplied string that further scopes a requested
	// pairwise pseudonym (PPID) beyond the verifier's own identity - see
	// pkg/mdoc.ComputeZkVerifierContext.
	PPIDContext string `json:"ppid_context,omitempty" yaml:"ppid_context,omitempty"`
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

	// CircuitZk is the configuration for zero-knowledge circuit
	// presentations (circuit_zk): which proof systems and circuits a proof
	// may come from.
	CircuitZk *CircuitZkFormat `json:"circuit_zk,omitempty" yaml:"circuit_zk,omitempty"`

	// Extra carries format entries this build does not know about,
	// flattened alongside the known ones - so a Verifier can offer a
	// format identifier that postdates this code.
	Extra map[string]any `json:"-" yaml:"-"`
}

// MarshalJSON flattens Extra alongside the known format entries.
func (v VPFormatsSupported) MarshalJSON() ([]byte, error) {
	type plain VPFormatsSupported
	return marshalWithExtra(plain(v), v.Extra, "vp_formats_supported")
}

// UnmarshalJSON collects unknown format entries into Extra.
func (v *VPFormatsSupported) UnmarshalJSON(data []byte) error {
	type plain VPFormatsSupported
	var known plain
	if err := decodeExact(data, &known); err != nil {
		return err
	}
	*v = VPFormatsSupported(known)
	extra, err := unknownMembers(data, "ldp_vc", "jwt_vc_json", "dc+sd-jwt", "mso_mdoc", "circuit_zk")
	if err != nil {
		return err
	}
	v.Extra = extra
	return nil
}

// MarshalYAML flattens Extra alongside the known format entries.
//
// Needed as much as the JSON pair, and arguably more: this is the type
// verifier.preferred_vp_formats loads into, so the OPERATOR CONFIGURATION
// path is the one an unknown format identifier has to come in by. With
// JSON support alone the promise held only for metadata this build
// constructed itself, which is not where a format that postdates it
// arrives from.
func (v VPFormatsSupported) MarshalYAML() (any, error) {
	type plain VPFormatsSupported
	encoded, err := json.Marshal(plain(v))
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := decodeExact(encoded, &m); err != nil {
		return nil, err
	}
	return mergeExtraYAML(m, v.Extra, declaredJSONKeys(reflect.TypeOf(VPFormatsSupported{})), "vp_formats_supported")
}

// UnmarshalYAML captures format entries this build does not model.
func (v *VPFormatsSupported) UnmarshalYAML(unmarshal func(any) error) error {
	type plain VPFormatsSupported
	var known plain
	if err := unmarshal(&known); err != nil {
		return fmt.Errorf("vp_formats_supported: %w", err)
	}
	*v = VPFormatsSupported(known)

	extra, err := yamlExtra(unmarshal, "vp_formats_supported",
		"ldp_vc", "jwt_vc_json", "dc+sd-jwt", "mso_mdoc", "circuit_zk")
	if err != nil {
		return err
	}
	v.Extra = extra
	return nil
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
	// ID REQUIRED if claim_sets is present in the Credential Query; OPTIONAL otherwise.
	// A string identifying the particular claim. The value MUST be a non-empty string
	// consisting of alphanumeric, underscore (_), or hyphen (-) characters.
	// Within the particular claims array, the same id MUST NOT be present more than once.
	ID string `json:"-" yaml:"-"`

	// Path REQUIRED The value MUST be a non-empty array representing a claims path pointer
	// that specifies the path to a claim within the Credential, as defined in Section 7.
	// Elements are strings (object keys) or nil (representing null for array element access).
	Path []*string `json:"-" yaml:"-" validate:"required,min=1"`

	// Values OPTIONAL A non-empty array of strings, integers or boolean values that
	// specifies the expected values of the claim. If present, the Wallet SHOULD return
	// the claim only if the type and value of the claim both match exactly for at least
	// one of the elements in the array. See OpenID4VP Section 6.3 and 6.4.1.
	Values []any `json:"-" yaml:"-" validate:"omitnil,min=1"`
}

// MarshalJSON implements custom JSON marshaling for ClaimQuery.
// Nil path elements are serialized as JSON null (for DCQL array element access).
// A non-nil Values slice is validated against OpenID4VP §6.3; use nil to omit.
func (cq ClaimQuery) MarshalJSON() ([]byte, error) {
	if err := validateClaimPath(cq.Path); err != nil {
		return nil, err
	}
	if cq.Values != nil {
		if err := validateClaimValues(cq.Values, true); err != nil {
			return nil, err
		}
	}
	path := make([]any, len(cq.Path))
	for i, p := range cq.Path {
		if p == nil {
			path[i] = nil
		} else {
			path[i] = *p
		}
	}
	type wire struct {
		ID     string `json:"id,omitempty"`
		Path   []any  `json:"path"`
		Values []any  `json:"values,omitempty"`
	}
	return json.Marshal(wire{ID: cq.ID, Path: path, Values: cq.Values})
}

// UnmarshalJSON implements custom JSON unmarshaling for ClaimQuery.
// JSON null path elements are deserialized as nil pointers; non-string/non-null
// elements cause an unmarshal error (Go's json package rejects them for *string).
func (cq *ClaimQuery) UnmarshalJSON(data []byte) error {
	var raw struct {
		ID     string          `json:"id"`
		Path   []*string       `json:"path"`
		Values json.RawMessage `json:"values"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if err := validateClaimPath(raw.Path); err != nil {
		return err
	}
	var values []any
	if len(raw.Values) > 0 {
		if bytes.Equal(bytes.TrimSpace(raw.Values), []byte("null")) {
			return fmt.Errorf(`claim "values" must not be null`)
		}
		if err := json.Unmarshal(raw.Values, &values); err != nil {
			return fmt.Errorf(`claim "values" must be an array of strings, integers, or booleans: %w`, err)
		}
	}
	if err := validateClaimValues(values, len(raw.Values) > 0); err != nil {
		return err
	}
	cq.ID = raw.ID
	cq.Path = raw.Path
	cq.Values = values
	return nil
}

// MarshalYAML implements gopkg.in/yaml.v2's Marshaler interface for ClaimQuery.
// Mirrors MarshalJSON: the ClaimQuery fields carry yaml:"-" tags to route
// through this method, so without it yaml.Marshal would emit an empty mapping
// and drop id/path/values.
func (cq ClaimQuery) MarshalYAML() (any, error) {
	if err := validateClaimPath(cq.Path); err != nil {
		return nil, err
	}
	if cq.Values != nil {
		if err := validateClaimValues(cq.Values, true); err != nil {
			return nil, err
		}
	}
	path := make([]any, len(cq.Path))
	for i, p := range cq.Path {
		if p == nil {
			path[i] = nil
		} else {
			path[i] = *p
		}
	}
	return struct {
		ID     string `yaml:"id,omitempty"`
		Path   []any  `yaml:"path"`
		Values []any  `yaml:"values,omitempty"`
	}{ID: cq.ID, Path: path, Values: cq.Values}, nil
}

// UnmarshalYAML implements custom YAML unmarshaling for ClaimQuery.
// YAML null path elements are deserialized as nil pointers; non-string/non-null
// elements cause an unmarshal error.
func (cq *ClaimQuery) UnmarshalYAML(unmarshal func(any) error) error {
	var raw struct {
		ID   string    `yaml:"id"`
		Path []*string `yaml:"path"`
	}
	if err := unmarshal(&raw); err != nil {
		return err
	}
	if err := validateClaimPath(raw.Path); err != nil {
		return err
	}
	// Second pass into a generic map so we can distinguish an absent "values"
	// key from an explicit YAML null — yaml.v2 unmarshals both into the same
	// zero value when the target field type is []any.
	var check map[string]any
	if err := unmarshal(&check); err != nil {
		return err
	}
	var values []any
	rawValues, present := check["values"]
	if present {
		if rawValues == nil {
			return fmt.Errorf(`claim "values" must not be null`)
		}
		arr, ok := rawValues.([]any)
		if !ok {
			return fmt.Errorf(`claim "values" must be an array of strings, integers, or booleans`)
		}
		values = arr
	}
	if err := validateClaimValues(values, present); err != nil {
		return err
	}
	cq.ID = raw.ID
	cq.Path = raw.Path
	cq.Values = values
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

// validateClaimValues enforces the OpenID4VP Section 6.3 rule that "values" must be
// a non-empty array of strings, integers, or booleans when present. JSON decoding
// widens numeric values into float64, so integer-valued floats are accepted — but
// only within the IEEE-754 safe integer range (±(2^53-1)); larger magnitudes may
// have been silently rounded by the decoder and can no longer be trusted to
// "match exactly" per the spec.
// present tells the validator that the key existed on the wire so an empty array
// can be rejected (an absent key is legal — "values" is OPTIONAL).
func validateClaimValues(values []any, present bool) error {
	if !present {
		return nil
	}
	if len(values) == 0 {
		return fmt.Errorf(`claim "values" must not be empty when present`)
	}
	for i, v := range values {
		switch t := v.(type) {
		case string, bool, int, int32, int64, uint, uint32, uint64:
		case float32:
			if err := checkIntegralFloat(float64(t), i); err != nil {
				return err
			}
		case float64:
			if err := checkIntegralFloat(t, i); err != nil {
				return err
			}
		default:
			return fmt.Errorf("claim values[%d] must be a string, integer, or boolean", i)
		}
	}
	return nil
}

func checkIntegralFloat(f float64, i int) error {
	const maxSafeInt = float64(1<<53 - 1)
	if math.IsNaN(f) || math.IsInf(f, 0) || f < -maxSafeInt || f > maxSafeInt || f != math.Trunc(f) {
		return fmt.Errorf("claim values[%d] must be a string, integer, or boolean", i)
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

	// BaseVCTypeIRI is the expanded form of the type every W3C VC carries.
	// A type_values alternative naming only this constrains nothing.
	BaseVCTypeIRI = "https://www.w3.org/2018/credentials#VerifiableCredential"
	// FormatVCLDJSON is the other spelling this repo issues W3C VC Data
	// Integrity under - see handlers_issuer.go, which routes it to issueVC20
	// alongside ldp_vc.
	FormatVCLDJSON = "vc+ld+json"
)

// IsW3CVCFormatIdentifier returns true if the format identifier is a W3C
// Verifiable Credential format (ldp_vc, vc+ld+json or jwt_vc_json).
//
// vc+ld+json belongs here because this repo issues it as one: handlers_issuer.go
// routes it to issueVC20 alongside ldp_vc. Leaving it out meant a query in that
// format skipped the type_values requirement in ValidateCredentialQuery that
// the other two are held to, so an unconstrained W3C query passed validation.
func IsW3CVCFormatIdentifier(format string) bool {
	return format == FormatLdpVCDCQL || format == FormatVCLDJSON || format == FormatJwtVCJson
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
	// A raw query is judged by its own bytes, not by the empty struct the
	// failed typed decode left behind.
	//
	// The escape hatch is for a member whose SHAPE this build does not
	// model; it is not a way around the constraint rules, and it is not
	// specific to one format. Reading format and meta back out of the raw
	// bytes keeps both true at once: an SD-JWT query with no vct_values is
	// still refused here even though it arrived raw, and a circuit_zk one
	// still falls to the permissive default below, as every format this
	// build does not constrain does.
	if query.Raw != nil {
		if !json.Valid(query.Raw) {
			return &DCQLValidationError{
				Field:   "raw",
				Message: "a raw credential query must be valid JSON",
			}
		}
		// An UNREADABLE meta is judged as an EMPTY one, not waved through.
		//
		// "Cannot read the constraint" and "there is no constraint" are
		// the same thing to everyone downstream: either way nothing here
		// has established what the request is limited to. Returning nil
		// on the first and refusing the second would let
		// {"format":"vc+sd-jwt","meta":"not an object"} be signed and
		// served with no vct_values - the very case this check exists for,
		// reached by making the member harder to read rather than by
		// omitting it.
		//
		// Substituting the zero value rather than naming the formats that
		// have rules keeps the two in step by construction: a zero
		// MetaQuery satisfies no constraint rule in the switch below, and
		// passes the permissive default exactly where there is no rule to
		// fail. A format that grows one later is covered without anything
		// here being updated.
		// From the BYTES, not from the struct's copies of them: those are
		// populated by UnmarshalJSON, and a query built in code has none.
		id, format := query.rawRouting()
		meta, readable := query.rawMeta()

		query = CredentialQuery{ID: id, Format: format, Meta: meta}
		if !readable {
			if err := ValidateCredentialQuery(query); err != nil {
				// Reported as what it is. "vct_values is required" would
				// send an operator looking for a member that may well be
				// in the bytes, inside the meta this could not read.
				return &DCQLValidationError{
					Field:   "meta",
					Message: fmt.Sprintf("meta is a shape this build cannot read, so the %s constraint it would have to satisfy cannot be established: %v", formatOrDefault(query.Format), err),
				}
			}
			return nil
		}
	}
	switch query.Format {
	// Not FormatJwtVCJson: UIInteraction calls this on the live ingress, and
	// the rest of the stack refuses that format - nothing issues it and the
	// verifier reads a compact JWT-VC as SD-JWT. Accepting it here would let
	// it in through the one door still open.
	case FormatLdpVCDCQL, FormatVCLDJSON:
		// W3C VC format requires type_values, and every alternative must
		// actually constrain: MatchTypeValues reads an empty alternative as
		// satisfied by any credential, and one satisfied alternative answers
		// the whole constraint - so [[]] is an unconstrained request wearing
		// a constraint's shape.
		for i, alternative := range query.Meta.TypeValues {
			// EVERY member has to be a fully expanded IRI, not just one.
			// type_values are matched as expanded IRIs (OpenID4VP 1.0
			// B.3.2), the verifier drops relative ones from the credential
			// side for the same reason, and MatchTypeValues requires a
			// credential to carry ALL of an alternative's types - so an
			// alternative holding one good IRI and one compact term
			// validates, is sent, and can never match. A query that cannot
			// be satisfied is not a constraint, it is an outage wearing a
			// constraint's shape. Config load refuses these too; this is
			// the path templates and API callers arrive by.
			for j, member := range alternative {
				// Strict: see credential.IsAbsoluteIRI. A colon alone does
				// not make a reference absolute.
				if member != "" && credential.IsAbsoluteIRI(member) {
					continue
				}
				return &DCQLValidationError{
					Field:   fmt.Sprintf("meta.type_values[%d][%d]", i, j),
					Message: fmt.Sprintf("type_values members are matched as fully expanded IRIs (OpenID4VP 1.0 B.3.2), so %q can never match a credential", member),
				}
			}
			// And at least one of them has to NARROW. Base-only is the
			// same defect as empty, one step along: every W3C credential
			// carries VerifiableCredential, so an alternative naming only
			// it is satisfied by all of them. The config path
			// (CredentialMetadata.w3cTypeValues) already refuses that; an
			// API-supplied query has to be held to the same rule, or the
			// request over-discloses without ever looking unconstrained.
			narrowing := slices.ContainsFunc(alternative, func(t string) bool {
				return t != BaseVCTypeIRI
			})
			if !narrowing {
				return &DCQLValidationError{
					Field:   fmt.Sprintf("meta.type_values[%d]", i),
					Message: "each type_values alternative must name at least one fully expanded IRI beyond " + BaseVCTypeIRI + "; a base-only alternative matches every W3C credential",
				}
			}
		}
		if len(query.Meta.TypeValues) == 0 {
			return &DCQLValidationError{
				Field:   "meta.type_values",
				Message: "type_values is required for W3C VC format",
			}
		}
	// "vc+sd-jwt" is the legacy spelling this repo still issues, and "" is
	// Format's own default. DCQLMetaQuery, the UI builder and the verifier's
	// format check all classify both as SD-JWT; leaving either to the
	// permissive default below meant such a query passed validation with no
	// constraint at all. Every place that decides what a format MEANS has to
	// agree with every place that decides whether it is CONSTRAINED.
	case FormatSDJWTVC, "vc+sd-jwt", "":
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
	case FormatMsoMdocZk:
		return validateMsoMdocZkQuery(query)
	// Refused explicitly, NOT left to the default below. Both are advertised
	// in issuer metadata and neither is requestable: nothing issues them, and
	// the verifier reads a compact JWT-VC as SD-JWT, so it would verify one
	// under the wrong credential model. UIInteraction validates here on the
	// live ingress, and "allow but do not validate" would wave them through
	// with no constraint at all.
	case FormatJwtVCJson, "jwt_vc_json-ld":
		return &DCQLValidationError{
			Field:   "format",
			Message: fmt.Sprintf("format %q is advertised but not requestable: nothing issues it and there is no verification path for it", query.Format),
		}
	default:
		// Unknown format - allow but don't validate
	}
	return nil
}

// formatOrDefault names a format for an error message, spelling out the
// empty one rather than printing "" - which reads as a missing format
// when it is in fact the SD-JWT default.
func formatOrDefault(format string) string {
	if format == "" {
		return FormatSDJWTVC + " (the default for an absent format)"
	}
	return format
}

// validateMsoMdocZkQuery validates the ZK-mdoc (mso_mdoc_zk)-specific
// fields of a CredentialQuery, split out of ValidateCredentialQuery to
// keep that function's per-format switch flat (this format alone needs a
// nested per-entry loop over zk_system_type, unlike every other format).
func validateMsoMdocZkQuery(query CredentialQuery) error {
	// ZK-mdoc requires doctype_value, same as plain mso_mdoc.
	if query.Meta.DoctypeValue == "" {
		return &DCQLValidationError{
			Field:   "meta.doctype_value",
			Message: "doctype_value is required for ZK-mdoc format",
		}
	}
	// ...plus a non-empty zk_system_type array declaring which ZK
	// systems/circuits the verifier accepts, each entry of which must
	// itself carry the "id"/"system" fields ZKSystemTypeSpec requires
	// (matching/circuit resolution depends on both being present - see
	// MatchZKSystemType and pkg/mdoc/zkcircuit.Client.FetchCircuit).
	if len(query.Meta.ZKSystemType) == 0 {
		return &DCQLValidationError{
			Field:   "meta.zk_system_type",
			Message: "zk_system_type is required for ZK-mdoc format",
		}
	}
	for i, spec := range query.Meta.ZKSystemType {
		if spec.ID == "" {
			return &DCQLValidationError{
				Field:   fmt.Sprintf("meta.zk_system_type[%d].id", i),
				Message: "id is required for each zk_system_type entry",
			}
		}
		if spec.System == "" {
			return &DCQLValidationError{
				Field:   fmt.Sprintf("meta.zk_system_type[%d].system", i),
				Message: "system is required for each zk_system_type entry",
			}
		}
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
		Format: FormatLdpVCDCQL,
		Meta: MetaQuery{
			TypeValues: typeValues,
		},
		Claims:                            claims,
		RequireCryptographicHolderBinding: new(true),
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
