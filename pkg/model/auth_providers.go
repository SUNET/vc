package model

const (
	AuthProviderSAML      = "saml"
	AuthProviderOIDC      = "oidc"
	AuthProviderOpenID4VP = "openid4vp"
	AuthProviderDatastore = "datastore"
	// AuthProviderPreAuth marks a credential scope that must be issued only
	// via a pre-authorized credential offer (e.g. DatastorePreAuthOffer);
	// wallet-initiated PAR/authorize flows are rejected for such scopes.
	AuthProviderPreAuth = "preauth"
)
