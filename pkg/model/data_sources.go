package model

import (
	"fmt"
	"time"
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
}

// DatastoreConfig groups datastore credential scopes and optional data import settings.
type DatastoreConfig struct {
	// Scopes maps credential scope names to their datastore configuration
	Scopes map[string]DatastoreScope `yaml:"scopes,omitempty" doc_key:"credential scope"`

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
	// AuthProvider is the auth provider for this credential type (openid4vp, saml, or oidc)
	AuthProvider string `yaml:"auth_provider" validate:"required,oneof=openid4vp saml oidc"`

	// AuthClaims lists the normalized claim names used for datastore identity lookup
	// when auth_provider is saml or oidc. Not used for openid4vp (use AuthScopes instead).
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
	Scopes map[string]AssertionScope `yaml:"scopes,omitempty" doc_key:"credential scope"`
}

// AssertionScope configures a credential type backed by authentication assertions.
// The data comes directly from the SAML attributes or OIDC claims.
type AssertionScope struct {
	// AuthProvider is the auth provider for this credential type (saml or oidc)
	AuthProvider string `yaml:"auth_provider" validate:"required,oneof=saml oidc"`
}

// ExternalAPIConfig groups external API credential scopes.
type ExternalAPIConfig struct {
	// Scopes maps credential scope names to their external API configuration
	Scopes map[string]ExternalAPIScope `yaml:"scopes,omitempty" doc_key:"credential scope"`
}

// ExternalAPIScope configures a credential type backed by an external API.
type ExternalAPIScope struct {
	// Remote is the name of a remote defined in Remotes
	Remote string `yaml:"remote" validate:"required"`

	// AuthProvider is the auth provider to identify the user (saml or oidc)
	AuthProvider string `yaml:"auth_provider" validate:"required,oneof=saml oidc"`

	// AttributeMapping defines how to map API response data to credential claims
	AttributeMapping AttributeMapping `yaml:"attribute_mapping,omitempty" doc_key:"attribute"`
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
	DataSourceDatastore   DataSourceType = "datastore"
	DataSourceAssertion   DataSourceType = "assertion"
	DataSourceExternalAPI DataSourceType = "external_api"
)

// RemoteType identifies the protocol type of an external API connection.
type RemoteType string

const (
	RemoteTypeEduAPI RemoteType = "eduapi"
	RemoteTypeOOAPI  RemoteType = "ooapi"
)

// CredentialSource describes where a credential's data comes from and how the user authenticates.
type CredentialSource struct {
	DataSource   DataSourceType
	AuthProvider string
	RemoteName   string // only for external_api
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
			DataSource:   DataSourceDatastore,
			AuthProvider: cred.AuthProvider,
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
