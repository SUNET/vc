package model

import (
	"fmt"
	"maps"
	"time"

	"github.com/SUNET/vc/pkg/credential/primitives"
)

// DataSources groups all data source configurations for credential issuance.
// Each key under a data source is a credential type.
type DataSources struct {
	// Datastore configures credential types backed by a pre-loaded datastore (e.g. MongoDB)
	Datastore DatastoreConfig `yaml:"datastore,omitempty"`

	// Assertion configures credential types backed by authentication assertions
	// (SAML attributes or OIDC claims)
	Assertion AssertionConfig `yaml:"assertion,omitempty"`

	// ExternalAPI configures credential types backed by an external API
	// Each credential references a named remote defined in APIGW.Remotes
	ExternalAPI ExternalAPIConfig `yaml:"external_api,omitempty"`

	// Presentation configures credential types whose data is derived from
	// another credential the wallet presents via OpenID4VP during OpenID4VCI.
	Presentation PresentationConfig `yaml:"presentation,omitempty"`
}

// DatastoreConfig groups datastore credential scopes and optional data import settings.
type DatastoreConfig struct {
	// Scopes maps credential scope names to their datastore configuration
	Scopes map[string]DatastoreScope `yaml:"scopes,omitempty" validate:"omitempty,dive" doc_key:"credential scope"`

	// Import configures automatic data import from JSON files at startup.
	// When configured, APIGW reads JSON files and imports them into the
	// datastore on first startup (skipped if data already exists).
	Import *DatastoreImport `yaml:"import,omitempty"`
}

// DatastoreImport configures automatic import of JSON fixture data into the datastore.
type DatastoreImport struct {
	// FilePaths lists JSON files to import into the datastore.
	// Each JSON file should contain a map of person IDs to CompleteDocument objects.
	// Import is skipped if the datastore already contains data.
	FilePaths []string `yaml:"file_paths" validate:"required,min=1" doc_example:"[\"./bootstrapping/pid.json\", \"./bootstrapping/ehic.json\"]"`

	// Users limits which person IDs to import. If empty, all persons are imported.
	Users []string `yaml:"users,omitempty" doc_example:"[\"100\", \"102\"]"`
}

// IdentityMappingImport configures automatic import of identity mappings at startup.
type IdentityMappingImport struct {
	// FilePaths lists JSON files containing identity mappings to import.
	// Each JSON file should contain a map of person IDs to arrays of IdentityMapping objects.
	// Import is skipped if the identity mappings collection already contains data.
	FilePaths []string `yaml:"file_paths" validate:"required,min=1" doc_example:"[\"./bootstrapping/identity_mappings.json\"]"`

	// Users limits which person IDs to import. If empty, all persons are imported.
	Users []string `yaml:"users,omitempty" doc_example:"[\"100\", \"102\"]"`
}

// DatastoreScope configures a credential type backed by the datastore.
type DatastoreScope struct {
	// AuthProvider is the auth provider for this credential type
	// (openid4vp, saml, oidc, or preauth). Use preauth to restrict issuance
	// to pre-authorized credential offers only; wallet-initiated PAR/authorize
	// requests for such a scope are rejected.
	AuthProvider string `yaml:"auth_provider" validate:"required,oneof=openid4vp saml oidc preauth"`

	// AuthenticSource names the identity-mapping namespace used to resolve the
	// authenticated user to an authentic_source_person_id for datastore
	// identity lookups (oidc, saml, openid4vp). Identity mappings are scoped to
	// an authentic source (SUNET/vc#507 made the namespace mandatory), so this
	// must match the namespace the mappings were imported under. Not used for
	// preauth, where the pre-authorized offer already carries the identifier.
	AuthenticSource string `yaml:"authentic_source,omitempty" doc_example:"\"SUNET\""`

	// AuthClaims lists the normalized claim names used for datastore identity lookup
	// when auth_provider is saml or oidc. Not used for openid4vp (use AuthScopes instead).
	// Must be empty when auth_provider is preauth.
	// These names must match the BSON field names under "identities." in the datastore.
	// Use attribute_mappings (in auth_providers) to normalize provider-specific attribute
	// names (e.g. SAML urn:oid:2.5.4.42, eIDAS date_of_birth) to these canonical names.
	// Available identity fields: given_name, family_name, birth_date, birth_place,
	// authentic_source_person_id, personal_administrative_number.
	AuthClaims []string `yaml:"auth_claims,omitempty" doc_example:"[given_name, family_name, birth_date]"`

	// AuthScopes maps credential scope keys to their per-scope authentication config.
	// Used only for openid4vp: the wallet must present a credential matching any one
	// of the listed scopes (OR logic). Each entry specifies which claims to extract
	// from that particular credential type.
	AuthScopes map[string]AuthScopeEntry `yaml:"auth_scopes,omitempty"`

	// OIDCRequestParams configures additional parameters to include in the OIDC authorization request.
	// Used to pass per-request values to the OP - see OIDCRequestParams for
	// where those values come from, and for why they are not a statement
	// about the authentic source.
	//
	// Only meaningful when auth_provider is oidc - there is no authorization
	// request to add parameters to otherwise - and rejected at startup on a
	// scope with any other provider. See validateOIDCOnlyScopeFields.
	OIDCRequestParams *OIDCRequestParams `yaml:"oidc_request_params,omitempty"`

	// IssuancePolicy defines SPOCP rules that must be satisfied by the OIDC claims for credential issuance.
	// If configured, a SPOCP query is built from the returned claims and evaluated against these rules.
	// A query that does not match any rule results in a hard deny.
	//
	// Evaluated in the OIDC callback and nowhere else, so it is rejected at
	// startup on a scope whose auth_provider is not oidc. Accepting it there
	// would be the worst outcome available for a security control: the
	// configuration reads as a gate, validates, starts, and issues every
	// credential through the SAML or pre-authorized path without ever
	// consulting it. See validateOIDCOnlyScopeFields.
	IssuancePolicy *IssuancePolicy `yaml:"issuance_policy,omitempty"`

	// Derivations are generic post-verification steps that compute
	// additional claims from the source data (see credential.ApplyDerivations).
	Derivations []primitives.Derivation `yaml:"derivations,omitempty" validate:"omitempty,dive" doc_key:"derivation index"`
}

// AuthScopeEntry configures per-scope authentication requirements for OpenID4VP.
// Each entry represents one acceptable credential type the wallet can present.
type AuthScopeEntry struct {
	// AuthClaims lists the identity claims to extract from this credential type.
	AuthClaims []string `yaml:"auth_claims" validate:"required,min=1" doc_example:"[given_name, family_name, birth_date]"`
}

// AuthScopeNames returns the list of scope keys from AuthScopes.
func (d *DatastoreScope) AuthScopeNames() []string {
	names := make([]string, 0, len(d.AuthScopes))
	for k := range d.AuthScopes {
		names = append(names, k)
	}
	return names
}

// ExtractIdentityClaims extracts identity field values from a claims map using
// the provided required claim names. The claim names are used directly as BSON
// field names in the datastore query (e.g. "given_name" → identities.given_name).
// Returns an error if any required claim is missing or not a string value.
func ExtractIdentityClaims(claims map[string]any, required []string) (map[string]string, error) {
	result := make(map[string]string, len(required))
	var missing []string
	for _, claimName := range required {
		v, ok := claims[claimName]
		if !ok {
			missing = append(missing, claimName)
			continue
		}
		s, ok := v.(string)
		if !ok {
			missing = append(missing, claimName)
			continue
		}
		result[claimName] = s
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("required identity claims missing or not string: %v", missing)
	}
	return result, nil
}

// AssertionConfig groups assertion credential scopes.
type AssertionConfig struct {
	// Scopes maps credential scope names to their assertion configuration
	Scopes map[string]AssertionScope `yaml:"scopes,omitempty" validate:"omitempty,dive" doc_key:"credential scope"`
}

// AssertionScope configures a credential type backed by authentication assertions.
// The data comes directly from the SAML attributes or OIDC claims.
type AssertionScope struct {
	// AuthProvider is the auth provider for this credential type (saml or oidc)
	AuthProvider string `yaml:"auth_provider" validate:"required,oneof=saml oidc"`

	// OIDCRequestParams configures additional parameters to include in the OIDC authorization request.
	// Used to pass per-request values to the OP - see OIDCRequestParams for
	// where those values come from, and for why they are not a statement
	// about the authentic source.
	//
	// Only meaningful when auth_provider is oidc - there is no authorization
	// request to add parameters to otherwise - and rejected at startup on a
	// scope with any other provider. See validateOIDCOnlyScopeFields.
	OIDCRequestParams *OIDCRequestParams `yaml:"oidc_request_params,omitempty"`

	// IssuancePolicy defines SPOCP rules that must be satisfied by the OIDC claims for credential issuance.
	// If configured, a SPOCP query is built from the returned claims and evaluated against these rules.
	// A query that does not match any rule results in a hard deny.
	//
	// Evaluated in the OIDC callback and nowhere else, so it is rejected at
	// startup on a scope whose auth_provider is not oidc. Accepting it there
	// would be the worst outcome available for a security control: the
	// configuration reads as a gate, validates, starts, and issues every
	// credential through the SAML or pre-authorized path without ever
	// consulting it. See validateOIDCOnlyScopeFields.
	IssuancePolicy *IssuancePolicy `yaml:"issuance_policy,omitempty"`

	// Defaults holds claim values injected into the assertion document for
	// credential-level fields the authentication assertion cannot supply
	// (e.g. issuing_authority, issuing_country, date_of_expiry). Merged
	// after attribute_mapping — real attributes always win.
	Defaults map[string]any `yaml:"defaults,omitempty" doc_key:"claim path"`

	// ExpiryDuration, if set, computes date_of_expiry at issuance time as
	// now+duration (formatted as ISO YYYY-MM-DD) and overrides any static
	// date_of_expiry in Defaults. Prevents freshly issued credentials from
	// shipping pre-expired when a static date is left un-rotated. Uses Go
	// duration syntax; example: "8760h" for one year.
	ExpiryDuration string `yaml:"expiry_duration,omitempty" validate:"omitempty" doc_example:"\"8760h\""`

	// Derivations are generic post-verification steps that compute
	// additional claims from the assertion (see credential.ApplyDerivations).
	Derivations []primitives.Derivation `yaml:"derivations,omitempty" validate:"omitempty,dive" doc_key:"derivation index"`
}

// ResolveDefaults returns Defaults with date_of_expiry populated from
// ExpiryDuration when set, and date_of_issuance populated from now.
// Injecting now keeps the callers testable.
func (a AssertionScope) ResolveDefaults(now time.Time) (map[string]any, error) {
	out := make(map[string]any, len(a.Defaults)+2)
	maps.Copy(out, a.Defaults)
	if a.ExpiryDuration != "" {
		d, err := time.ParseDuration(a.ExpiryDuration)
		if err != nil {
			return nil, fmt.Errorf("invalid expiry_duration %q: %w", a.ExpiryDuration, err)
		}
		if d <= 0 {
			return nil, fmt.Errorf("expiry_duration %q must be positive", a.ExpiryDuration)
		}
		out["date_of_expiry"] = now.Add(d).Format("2006-01-02")
	}
	out["date_of_issuance"] = now.Format("2006-01-02")
	return out, nil
}

// ExternalAPIConfig groups external API credential scopes.
type ExternalAPIConfig struct {
	// Scopes maps credential scope names to their external API configuration
	Scopes map[string]ExternalAPIScope `yaml:"scopes,omitempty" validate:"omitempty,dive" doc_key:"credential scope"`
}

// ExternalAPIScope configures a credential type backed by an external API.
type ExternalAPIScope struct {
	// Remote is the name of a remote defined in Remotes
	Remote string `yaml:"remote" validate:"required"`

	// AuthProvider is the auth provider to identify the user (saml or oidc)
	AuthProvider string `yaml:"auth_provider" validate:"required,oneof=saml oidc"`

	// AttributeMapping defines how to map API response data to credential claims
	AttributeMapping AttributeMapping `yaml:"attribute_mapping,omitempty" doc_key:"attribute"`

	// OIDCRequestParams configures additional parameters to include in the OIDC authorization request.
	// Used to pass per-request values to the OP - see OIDCRequestParams for
	// where those values come from, and for why they are not a statement
	// about the authentic source.
	//
	// Only meaningful when auth_provider is oidc - there is no authorization
	// request to add parameters to otherwise - and rejected at startup on a
	// scope with any other provider. See validateOIDCOnlyScopeFields.
	OIDCRequestParams *OIDCRequestParams `yaml:"oidc_request_params,omitempty"`

	// IssuancePolicy defines SPOCP rules that must be satisfied by the OIDC claims for credential issuance.
	// If configured, a SPOCP query is built from the returned claims and evaluated against these rules.
	// A query that does not match any rule results in a hard deny.
	//
	// Evaluated in the OIDC callback and nowhere else, so it is rejected at
	// startup on a scope whose auth_provider is not oidc. Accepting it there
	// would be the worst outcome available for a security control: the
	// configuration reads as a gate, validates, starts, and issues every
	// credential through the SAML or pre-authorized path without ever
	// consulting it. See validateOIDCOnlyScopeFields.
	IssuancePolicy *IssuancePolicy `yaml:"issuance_policy,omitempty"`

	// Derivations are generic post-verification steps that compute
	// additional claims from the API response (see credential.ApplyDerivations).
	Derivations []primitives.Derivation `yaml:"derivations,omitempty" validate:"omitempty,dive" doc_key:"derivation index"`
}

// PresentationConfig groups presentation-derived credential scopes.
type PresentationConfig struct {
	// Scopes maps credential scope names to their presentation configuration.
	Scopes map[string]PresentationScope `yaml:"scopes,omitempty" validate:"omitempty,dive" doc_key:"credential scope"`
}

// PresentationScope configures a credential type whose data is derived from
// another credential presented by the wallet via OpenID4VP during OpenID4VCI.
type PresentationScope struct {
	// FromScope names the credential scope the wallet must present (e.g. "eduid").
	// The presented credential is verified against the issuer trust chain before
	// its claims are consumed.
	FromScope string `yaml:"from_scope" validate:"required" doc_example:"\"eduid\""`

	// AuthProvider is fixed to "openid4vp" for now; kept as a field for
	// symmetry with the other data sources and so future providers can be
	// added without a config-shape change.
	AuthProvider string `yaml:"auth_provider" validate:"required,oneof=openid4vp" default:"openid4vp"`

	// RequiredClaims maps a claim path on the presented credential to an
	// allow-list of exact-match values. Empty list = presence-only (any
	// value passes). Populated list = the claim's value must equal one of
	// the listed strings (or, when the claim is an array, at least one
	// array element must match). Every key must be present on the
	// presented credential's verified claims; missing keys fail issuance.
	RequiredClaims map[string][]string `yaml:"required_claims" validate:"required,min=1" doc_key:"claim path"`

	// Defaults holds claim values injected into the derived credential
	// document for fields the presented credential does not carry
	// (e.g. issuing_authority, issuing_country).
	Defaults map[string]any `yaml:"defaults,omitempty" doc_key:"claim path"`

	// ExpiryDuration, if set, computes date_of_expiry at issuance time as
	// now+duration (formatted as ISO YYYY-MM-DD). Same semantics as
	// AssertionScope.ExpiryDuration.
	ExpiryDuration string `yaml:"expiry_duration,omitempty" doc_example:"\"8760h\""`

	// Derivations are generic post-verification steps that compute additional
	// claims from the presented credential's own claims
	// (see credential.ApplyDerivations).
	Derivations []primitives.Derivation `yaml:"derivations,omitempty" validate:"omitempty,dive" doc_key:"derivation index"`
}

// ResolveDefaults returns Defaults with date_of_expiry populated from
// ExpiryDuration when set, and date_of_issuance populated from now.
func (p PresentationScope) ResolveDefaults(now time.Time) (map[string]any, error) {
	out := make(map[string]any, len(p.Defaults)+2)
	maps.Copy(out, p.Defaults)
	if p.ExpiryDuration != "" {
		d, err := time.ParseDuration(p.ExpiryDuration)
		if err != nil {
			return nil, fmt.Errorf("invalid expiry_duration %q: %w", p.ExpiryDuration, err)
		}
		if d <= 0 {
			return nil, fmt.Errorf("expiry_duration %q must be positive", p.ExpiryDuration)
		}
		out["date_of_expiry"] = now.Add(d).Format("2006-01-02")
	}
	out["date_of_issuance"] = now.Format("2006-01-02")
	return out, nil
}

// Remote defines an external API connection.
type Remote struct {
	// Type is the API protocol type
	Type RemoteType `yaml:"type" validate:"required,oneof=eduapi ooapi"`

	// BaseURL is the base URL of the API endpoint
	BaseURL string `yaml:"base_url" validate:"required,url" doc_example:"\"https://api.ladok.se/eduapi\""`

	// TokenURL is the OAuth 2.0 token endpoint for Client Credentials Grant
	TokenURL string `yaml:"token_url" validate:"required,url" doc_example:"\"https://api.ladok.se/oauth2/token\""`

	// ClientID is the OAuth 2.0 client identifier
	ClientID string `yaml:"client_id" validate:"required"`

	// ClientSecret is the OAuth 2.0 client secret
	ClientSecret string `yaml:"client_secret" validate:"required"`

	// Scopes are the OAuth 2.0 scopes to request
	Scopes []string `yaml:"scopes,omitempty"`

	// Timeout is the HTTP client timeout
	Timeout time.Duration `yaml:"timeout" default:"10s"`
}

// DataSourceType identifies which data source a credential type belongs to.
type DataSourceType string

const (
	DataSourceDatastore    DataSourceType = "datastore"
	DataSourceAssertion    DataSourceType = "assertion"
	DataSourceExternalAPI  DataSourceType = "external_api"
	DataSourcePresentation DataSourceType = "presentation"
)

// RemoteType identifies the protocol type of an external API connection.
type RemoteType string

const (
	RemoteTypeEduAPI RemoteType = "eduapi"
	RemoteTypeOOAPI  RemoteType = "ooapi"
)

// CredentialSource describes where a credential's data comes from and how the user authenticates.
type CredentialSource struct {
	DataSource      DataSourceType
	AuthProvider    string
	RemoteName      string // only for external_api
	AuthenticSource string // identity-mapping namespace, only for datastore
}

// LookupCredentialSources finds all data sources where a credential type is configured.
// A credential type can appear in multiple data sources with different auth providers.
// Returns an error if the credential type is not found in any data source.
func (ds *DataSources) LookupCredentialSources(credentialType string) ([]CredentialSource, error) {
	if ds == nil {
		return nil, fmt.Errorf("credential type %q has no data source configured", credentialType)
	}

	var sources []CredentialSource

	if cred, ok := ds.Datastore.Scopes[credentialType]; ok {
		sources = append(sources, CredentialSource{
			DataSource:      DataSourceDatastore,
			AuthProvider:    cred.AuthProvider,
			AuthenticSource: cred.AuthenticSource,
		})
	}

	if cred, ok := ds.Assertion.Scopes[credentialType]; ok {
		sources = append(sources, CredentialSource{
			DataSource:   DataSourceAssertion,
			AuthProvider: cred.AuthProvider,
		})
	}

	if cred, ok := ds.ExternalAPI.Scopes[credentialType]; ok {
		sources = append(sources, CredentialSource{
			DataSource:   DataSourceExternalAPI,
			AuthProvider: cred.AuthProvider,
			RemoteName:   cred.Remote,
		})
	}

	if cred, ok := ds.Presentation.Scopes[credentialType]; ok {
		sources = append(sources, CredentialSource{
			DataSource:   DataSourcePresentation,
			AuthProvider: cred.AuthProvider,
		})
	}

	if len(sources) == 0 {
		return nil, fmt.Errorf("credential type %q has no data source configured", credentialType)
	}

	return sources, nil
}

// ResolveDataSource returns the data source for a credential type given the auth
// provider that was used. A credential can exist in multiple data sources but
// only one will have the matching auth provider.
func (ds *DataSources) ResolveDataSource(credentialType, authProvider string) (CredentialSource, error) {
	sources, err := ds.LookupCredentialSources(credentialType)
	if err != nil {
		return CredentialSource{}, err
	}

	for _, src := range sources {
		if src.AuthProvider == authProvider {
			return src, nil
		}
	}

	return CredentialSource{}, fmt.Errorf(
		"credential type %q has no data source configured for auth provider %q", credentialType, authProvider,
	)
}

// OIDCRequestParams configures additional parameters to include in the OIDC authorization request.
// These allow per-request values to be injected into the authentication flow.
//
// NOT AN AUTHENTIC-SOURCE ASSERTION, despite where the values nominally come
// from. The operator decides WHICH parameters exist and where a template may
// appear; the value substituted into one is whatever the PAR caller sent in
// PARRequest.DynamicParams, and nothing binds that to a business system - PAR
// authenticates the wallet/client, not the origin of a claim about an
// organisation. So a caller authorized to make PAR requests chooses what this
// service ASKS the OP to assert.
//
// That is bounded on both sides. It is bounded here because a caller can only
// supply values for placeholders the operator wrote: they cannot add a
// parameter, override a reserved one, or inject structure into the claims
// JSON (resolveOIDCRequestParams escapes substitutions as JSON string content
// and refuses an unresolved placeholder). And it is bounded downstream because
// whether the OP honours the request is the OP's decision, and vc gates
// issuance on the claims the OP ASSERTED, never on these values - see the
// policy evaluation in handlers_oidcrp.go, which deliberately does not fall
// back to them.
//
// The rule that follows: do not use a dynamic parameter as a security input.
// Treat it as a hint to the OP about what to ask for, and require the answer
// to come back in the token.
//
// Templated values ("{{.org_id}}") are supplied by the caller that starts the
// flow, and only the PAR/VCI path carries them (PARRequest.DynamicParams).
// A scope configured with a template therefore CANNOT be started through
// POST /oidcrp/initiate: that endpoint has no dynamic-parameter field, so
// initiation fails with a template error naming the missing key rather than
// sending the literal "{{.org_id}}" to the OP. Configure templates only for
// scopes driven over PAR/VCI. See OIDCRPInitiateRequest for why this is a
// decision (SUNET/vc#380) rather than a missing feature.
type OIDCRequestParams struct {
	// ACRValues requests specific authentication context class references from the OP.
	// Supports Go template syntax for dynamic values: "{{.variable_name}}"
	ACRValues string `yaml:"acr_values,omitempty" doc_example:"\"urn:example:loa3\""`

	// Claims is a JSON string conforming to OIDC Core §5.5 claims request parameter.
	// Supports Go template syntax for dynamic values: "{{.variable_name}}"
	//
	// Dynamic values are escaped as JSON string content, so a value can only
	// affect the string it is written into and never the surrounding
	// structure. The rendered result must be valid JSON or flow initiation
	// fails, which also catches a template that was malformed as written.
	//
	// A caller value may FILL a string in and nothing else. It may not
	// decide which branch of the template runs - {{if .org_id}} lets the
	// caller choose what the request asks for without the value ever
	// appearing in it - and it may not sit outside a string or name a
	// member. All three are refused at startup.
	//
	// A placeholder must sit INSIDE a JSON string. The escaping makes a
	// value safe within the string it is written into; written outside one
	// - "value": {{.org_id}} - the same escaping inserts the caller's text
	// as raw JSON, so a value like `true,"essential":true` adds members the
	// operator never wrote and still parses. A placeholder used as an
	// object KEY lets the caller choose which claim is requested. Both are
	// refused at startup.
	//
	// DO NOT template the "value" of a claim the issuance policy reads. The
	// value member asks the OP to assert a SPECIFIC value, and the caller
	// that fills the template is the wallet - PAR authenticates it, not the
	// origin of a statement about an organisation. An OP that honours the
	// request hands the caller's own choice back in the token, where the
	// policy reads it as the OP's word. That configuration is refused at
	// startup; see checkPolicyClaimsAreNotCallerTemplated. Requesting the
	// claim without a value - "org_id": null - asks the OP what it knows,
	// which is the question worth gating on.
	Claims string `yaml:"claims,omitempty" doc_example:"\"{\\\"id_token\\\":{\\\"org_id\\\":null}}\""`

	// ExtraScopes are additional OAuth2 scopes to request beyond the default OIDC RP scopes.
	ExtraScopes []string `yaml:"extra_scopes,omitempty" doc_example:"[\"organization\", \"address\"]"`

	// CustomParams are arbitrary key-value pairs to add as query parameters to the authorization request.
	// Keys are static; values support Go template syntax for dynamic substitution.
	//
	// A TEMPLATED custom parameter is refused on a scope that has an
	// issuance_policy. These are arbitrary by design, so nothing here can
	// know what an OP does with one, and an OP that treats a parameter as a
	// hint about the subject can echo it into any claim - there is no claim
	// to name and so no narrower rule to write. A fixed value is the
	// operator's and stays allowed.
	CustomParams map[string]string `yaml:"custom_params,omitempty"`
}

// IssuancePolicy defines SPOCP rules for credential issuance authorization.
// After OIDC authentication completes, a SPOCP query is built from the returned
// claims and evaluated against these rules. If no rule matches, issuance is denied.
//
// A policy is rules PLUS a query_template. Rules alone are refused at startup:
// SPOCP matches dimensions by POSITION, so a rule cannot be read at all without
// knowing which dimensions the query carries and in what order. Any example
// showing one without the other does not describe a configuration this service
// will start with.
//
// The claims it reads have to be ones the OP asserts of its own accord.
// oidc_request_params may ask the OP for a claim, but templating a VALUE for
// one this policy reads is refused at startup: the caller that fills the
// template is the wallet, and an OP that honours the request would hand the
// caller's own choice back as its word. See OIDCRequestParams.Claims.
//
// A complete one, for a rule requiring an acr with a given prefix and any
// org_id:
//
// ```yaml
//
//	issuance_policy:
//	  query_template:
//	    - dimension: acr
//	      claim: acr
//	    - dimension: org_id
//	      claim: org_id
//	  rules:
//	    - "(credential (scope org_credential)(acr (* prefix urn:example:loa))(org_id))"
//
// ```
//
// The rule's dimensions after (scope ...) are acr then org_id, in the order
// query_template lists them. "scope" is auto-populated with the credential type
// name and is never listed in query_template. "(org_id)" with no value means
// any value.
type IssuancePolicy struct {
	// Rules are inline SPOCP S-expression rules (human-readable advanced form).
	// Example: "(credential (scope org_credential)(acr (* prefix urn:example:loa))(org_id))"
	// -- which is only half a configuration: rules without a query_template
	// are refused at startup, so see the worked example on issuance_policy
	// above for the query_template that rule needs.
	// When QueryTemplate is set, each rule is validated at load time against
	// the "credential" tag and the ("scope", <QueryTemplate dimensions>)
	// shape -- a rule with the wrong number/order of dimensions fails
	// startup instead of silently never matching at evaluation time. A
	// dimension may be omitted (e.g. "(org_id)") to mean "any value".
	Rules []string `yaml:"rules,omitempty" doc_example:"[\"(credential (scope org_credential)(acr (* prefix urn:example:loa))(org_id))\"]"`

	// RulesFile is an optional path to a file containing SPOCP rules (one per line).
	// Rules from this file are loaded in addition to the inline Rules list,
	// and validated the same way when QueryTemplate is set.
	RulesFile string `yaml:"rules_file,omitempty"`

	// QueryTemplate defines how to build the SPOCP query from OIDC claims.
	// The outer tag is always "credential". Each entry maps a SPOCP dimension name
	// to the OIDC claim name whose value should populate it. The order of entries
	// determines the positional order of dimensions in the SPOCP query, which must
	// match the order used in the rules.
	// Special dimension "scope" is auto-populated with the credential type name.
	//
	// Required whenever rules or rules_file is set. It used to be optional,
	// with a fallback that emitted one dimension per claim the token happened
	// to carry, in name order - but SPOCP matches by position, so a rule
	// naming two claims only matched when those two sorted ahead of every
	// other claim present. Against a real ID token (which always carries aud,
	// iss, nonce, sub and usually auth_time) that fallback denied every
	// request, so a policy written for it was a blanket deny that looked like
	// a working configuration.
	QueryTemplate []QueryDimension `yaml:"query_template,omitempty" validate:"omitempty,dive" doc_example:"[{dimension: acr, claim: acr}, {dimension: org_id, claim: org_id}]"`
}

// QueryDimension maps a SPOCP dimension name to the OIDC claim whose value populates it.
// Ordered slices of QueryDimension ensure deterministic query construction.
type QueryDimension struct {
	// Dimension is the SPOCP dimension name this entry populates. Required
	// whenever the entry exists: an entry with no dimension has nothing to
	// place the claim under, so it can only ever widen the rule shape into
	// one no rule matches. "scope" is reserved - it is auto-populated with
	// the credential type name.
	//
	// Constrained to a bare identifier (letter first, then letters, digits,
	// underscore or hyphen). A dimension name is written into the S-expression
	// a rule has to match by name, so anything with whitespace or punctuation
	// in it is either unwritable in a rule or writable in more than one way -
	// and " scope" would slip past the reserved-name and duplicate checks,
	// which compare the string as given, while still colliding with the
	// auto-populated scope dimension at query time.
	Dimension string `yaml:"dimension" validate:"required,spocp_dimension" doc_example:"\"acr\""`

	// Claim is the OIDC claim whose value populates the dimension, in
	// dot-notation for nested claims. Required for the same reason: a
	// dimension with no claim renders empty in every query.
	Claim string `yaml:"claim" validate:"required" doc_example:"\"identity.given_name\""`
}

// ScopePolicyConfig holds the per-scope issuance policy and OIDC request params.
type ScopePolicyConfig struct {
	OIDCRequestParams *OIDCRequestParams
	IssuancePolicy    *IssuancePolicy
}

// LookupScopePolicyConfig returns the issuance policy and OIDC request params
// configured for a credential scope under the given auth provider. Returns
// nil when the scope has no entry for that provider.
//
// The provider is part of the lookup, not an afterthought. One credential
// scope may legitimately be configured in several data sources with different
// auth providers - that is exactly what ResolveDataSource exists to
// disambiguate - and both of these settings only ever apply to the OIDC path.
// Taking the first data source that happened to list the scope meant an OIDC
// flow could pick up the entry belonging to the scope's SAML or pre-authorized
// configuration, or find none where the OIDC one had a policy, and so skip the
// gate it was supposed to apply. Which data source answers is now decided by
// the provider the flow actually authenticated with.
//
// The data sources are consulted in the same order as
// LookupCredentialSources, which is what ResolveDataSource and the auth
// provider Selector pick from: datastore, then assertion, then external_api.
// The two orders have to agree. They did not - this one tried assertion first -
// and since nothing forbids the same scope and provider appearing in two data
// sources, a flow could be issued from the datastore entry while its policy and
// request parameters were read off the assertion one. validateScopeProviderUniqueness
// now refuses that configuration outright, so the order decides nothing; it is
// kept aligned anyway, because a rule enforced in one place and contradicted in
// another is how the first version of this went wrong.
func (ds *DataSources) LookupScopePolicyConfig(scope, authProvider string) *ScopePolicyConfig {
	if ds == nil {
		return nil
	}

	if s, ok := ds.Datastore.Scopes[scope]; ok && s.AuthProvider == authProvider {
		return &ScopePolicyConfig{
			OIDCRequestParams: s.OIDCRequestParams,
			IssuancePolicy:    s.IssuancePolicy,
		}
	}

	if s, ok := ds.Assertion.Scopes[scope]; ok && s.AuthProvider == authProvider {
		return &ScopePolicyConfig{
			OIDCRequestParams: s.OIDCRequestParams,
			IssuancePolicy:    s.IssuancePolicy,
		}
	}

	if s, ok := ds.ExternalAPI.Scopes[scope]; ok && s.AuthProvider == authProvider {
		return &ScopePolicyConfig{
			OIDCRequestParams: s.OIDCRequestParams,
			IssuancePolicy:    s.IssuancePolicy,
		}
	}

	return nil
}

// DerivationsFor returns the Derivations list configured on whichever scope
// (datastore, assertion, external_api, or presentation) owns the given
// credential type. Returns nil if the scope is unknown or has no derivations.
// The lookup order mirrors LookupCredentialSources.
//
// Prefer DerivationsForSource when the caller knows which data source is in
// use — a credential type may exist in multiple data sources with different
// derivation lists, and this fallback picks by fixed map order.
func (ds *DataSources) DerivationsFor(credentialType string) []primitives.Derivation {
	if ds == nil {
		return nil
	}
	if cred, ok := ds.Datastore.Scopes[credentialType]; ok && len(cred.Derivations) > 0 {
		return cred.Derivations
	}
	if cred, ok := ds.Assertion.Scopes[credentialType]; ok && len(cred.Derivations) > 0 {
		return cred.Derivations
	}
	if cred, ok := ds.ExternalAPI.Scopes[credentialType]; ok && len(cred.Derivations) > 0 {
		return cred.Derivations
	}
	if cred, ok := ds.Presentation.Scopes[credentialType]; ok && len(cred.Derivations) > 0 {
		return cred.Derivations
	}
	return nil
}

// DerivationsForSource returns the Derivations list configured on the scope
// owned by the given data source. This is the source-aware variant of
// DerivationsFor: when a credential type is configured in multiple data
// sources, only the derivations of the source that was actually used should
// run. Returns nil if the scope is unknown for that source or has no
// derivations. An empty source falls back to DerivationsFor.
func (ds *DataSources) DerivationsForSource(credentialType string, source DataSourceType) []primitives.Derivation {
	if ds == nil {
		return nil
	}
	switch source {
	case DataSourceDatastore:
		if cred, ok := ds.Datastore.Scopes[credentialType]; ok {
			return cred.Derivations
		}
	case DataSourceAssertion:
		if cred, ok := ds.Assertion.Scopes[credentialType]; ok {
			return cred.Derivations
		}
	case DataSourceExternalAPI:
		if cred, ok := ds.ExternalAPI.Scopes[credentialType]; ok {
			return cred.Derivations
		}
	case DataSourcePresentation:
		if cred, ok := ds.Presentation.Scopes[credentialType]; ok {
			return cred.Derivations
		}
	case "":
		return ds.DerivationsFor(credentialType)
	}
	return nil
}
