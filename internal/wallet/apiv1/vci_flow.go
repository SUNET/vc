package apiv1

import (
	"fmt"
	"slices"

	"github.com/SUNET/vc/internal/wallet/config"
	"github.com/SUNET/vc/pkg/openid4vci"
)

// vciFlow is the state one execution of a VCI scenario carries from the
// Credential Offer that started it to the Token Endpoint that ends it.
//
// It exists because the obvious place to keep that state - the scenario
// configuration - is shared. RunScenario hands executeScenario a copy of
// the Scenario struct, but config.VCIScenario is reached through a
// pointer, so the copy and the original are the same scenario. Two
// concurrent runs of one scenario name therefore write to one
// VCIScenario: a PKCE verifier minted by one run is the verifier the
// other redeems its code with, and neither succeeds.
//
// Sequential runs had the matching problem. An offer-derived issuer_state
// written back to the configuration outlived the run that fetched it, so
// the next run presented a handle the Issuer had already consumed instead
// of the fresh one its own offer carried.
type vciFlow struct {
	// issuerState is the handle presented at the Authorization Challenge
	// Endpoint: the one the scenario configured, or the one this run's
	// offer carried.
	issuerState string

	// issuerStateIsConfigured records that issuerState came from the
	// scenario rather than from an offer. A configured handle is a
	// deliberate instruction to drive a particular case and an offer must
	// not quietly replace it.
	issuerStateIsConfigured bool

	// preAuthorizedCode is the pre-authorized code this run redeems,
	// configured or offer-derived.
	preAuthorizedCode string

	// codeVerifier is the PKCE verifier this run minted, held from
	// wherever the code was obtained to the Token Endpoint that redeems
	// it.
	codeVerifier string

	// scope is what this run asks to be issued: the scenario's, or the
	// one the Issuer advertises for the credential configuration being
	// requested.
	scope string

	// authorizationServer is the Authorization Server named by each GRANT
	// that named one, kept per grant rather than as a single value.
	//
	// OpenID4VCI 1.0 puts the member on both grants, and an offer may
	// carry both grants naming different servers - the Issuer is
	// describing two different ways to be authorized, not one. Collapsing
	// them means whichever grant happened to be parsed last decides where
	// the other grant's secret is sent.
	authorizationServerByGrant map[string]string
}

// The grant names, as OpenID4VCI 1.0 §4.1.1 spells them.
const (
	grantAuthorizationCode = "authorization_code"
	grantPreAuthorizedCode = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
)

// defaultWalletRedirectURI is where this wallet says to send the Holder
// back to when a scenario does not say.
//
// One constant, reached through one helper, because the value has to be
// IDENTICAL everywhere it is sent. An Authorization Server registers a
// client against a fixed set of redirect URIs and refuses anything else,
// so a challenge that omitted the parameter while the token request sent
// this value was refused at whichever end validated first - and the
// omission read as "this client has no redirect_uri", which is not a
// thing a registered client can be.
const defaultWalletRedirectURI = "http://localhost:8080/callback"

// redirectURIFor is the redirect_uri every leg of a run must send.
func redirectURIFor(vci *config.VCIScenario) string {
	if vci.RedirectURI != "" {
		return vci.RedirectURI
	}
	return defaultWalletRedirectURI
}

// newVCIFlow seeds a run from what the scenario configured.
func newVCIFlow(vci *config.VCIScenario) *vciFlow {
	return &vciFlow{
		issuerState:             vci.IssuerState,
		issuerStateIsConfigured: vci.IssuerState != "",
		preAuthorizedCode:       vci.PreAuthorizedCode,
		scope:                   vci.Scope,
	}
}

// adoptAdvertisedScope takes the scope the Issuer publishes for the
// credential configuration this run is asking for, when the scenario did
// not name one itself.
//
// An Authorization Challenge Request with no scope and no issuer_state
// describes no authorization at all and is refused, so a scenario that
// named only a credential_configuration_id could not open an exchange -
// including when the wallet took that path because the Issuer's metadata
// said Interactive Authorization is the only one it accepts, which is a
// case the scenario never asked for and cannot be expected to configure
// around.
//
// OpenID4VCI 1.0 §12.2.3 publishes this exact mapping in
// credential_configurations_supported, so there is nothing to guess.
func (f *vciFlow) adoptAdvertisedScope(metadata *openid4vci.CredentialIssuerMetadataParameters, credentialConfigurationID string) {
	if f.scope != "" || credentialConfigurationID == "" || metadata == nil {
		return
	}
	if config, ok := metadata.CredentialConfigurationsSupported[credentialConfigurationID]; ok {
		f.scope = config.Scope
	}
}

// adoptOfferGrants takes the handles a Credential Offer's grants carry.
//
// Both delivery shapes end up here. A credential_offer_uri is fetched and
// a credential_offer is read inline, and the draft gives them identical
// contents - so an inline offer that reached the Authorization Challenge
// Endpoint without its issuer_state, as this wallet's did, was treated as
// a fresh request and refused for having no scope.
func (f *vciFlow) adoptOfferGrants(grants map[string]any) {
	if grants == nil {
		return
	}

	if grant, ok := grants[grantPreAuthorizedCode].(map[string]any); ok {
		if code, ok := grant["pre-authorized_code"].(string); ok && code != "" {
			f.preAuthorizedCode = code
		}
		f.adoptGrantAuthorizationServer(grantPreAuthorizedCode, grant)
	}

	// OpenID4VCI 1.0 defines issuer_state for the Authorization Endpoint;
	// this wallet also presents it at the Authorization Challenge
	// Endpoint, which is the extension reported as openid/OpenID4VCI#815 -
	// without it, an issuance prepared by an Issuer cannot use Interactive
	// Authorization at all.
	if grant, ok := grants[grantAuthorizationCode].(map[string]any); ok {
		if state, ok := grant["issuer_state"].(string); ok && state != "" && !f.issuerStateIsConfigured {
			f.issuerState = state
		}
		f.adoptGrantAuthorizationServer(grantAuthorizationCode, grant)
	}
}

// adoptGrantAuthorizationServer records WHICH Authorization Server a grant
// named, against that grant.
//
// An Issuer is allowed to advertise several, and the secret a grant
// carries - a one-shot issuer_state, a pre-authorized code - belongs to
// exactly one of them. Keeping the secret while dropping the server sends
// it to an endpoint that has never heard of it.
func (f *vciFlow) adoptGrantAuthorizationServer(grantName string, grant map[string]any) {
	server, ok := grant["authorization_server"].(string)
	if !ok || server == "" {
		return
	}
	if f.authorizationServerByGrant == nil {
		f.authorizationServerByGrant = map[string]string{}
	}
	f.authorizationServerByGrant[grantName] = server
}

// selectedGrant is the grant this run will actually redeem.
//
// The same condition runVCIScenario branches on: a pre-authorized code,
// configured or offered, is redeemed in preference to anything else.
func (f *vciFlow) selectedGrant() string {
	if f.preAuthorizedCode != "" {
		return grantPreAuthorizedCode
	}
	return grantAuthorizationCode
}

// authorizationServerFor is the Authorization Server this run talks to.
//
// The grant being redeemed decides when it named one, because that is
// where its secret lives. Otherwise the Issuer's first advertised server,
// as before.
//
// A named server that the Issuer does not advertise is refused rather
// than followed. The offer is the least trustworthy input in this flow -
// it arrives as a QR code - and following it to an Authorization Server
// the Issuer never vouched for is how a wallet is talked into sending a
// handle, and then a DPoP proof, somewhere of an attacker's choosing.
// The Issuer's own metadata is the authority on which servers are its.
func (f *vciFlow) authorizationServerFor(metadata *openid4vci.CredentialIssuerMetadataParameters, issuerURL string) (string, error) {
	advertised := []string(nil)
	if metadata != nil {
		advertised = metadata.AuthorizationServers
	}

	// The server named by the grant being REDEEMED. An offer carrying both
	// grants is describing two ways to be authorized, and they may well
	// live on different servers; taking the authorization-code grant's
	// server while redeeming the pre-authorized code sends that code to a
	// token endpoint it is not a secret for.
	if named := f.authorizationServerByGrant[f.selectedGrant()]; named != "" {
		if !slices.Contains(advertised, named) {
			return "", fmt.Errorf(
				"the credential offer's %s grant names authorization server %q, which the issuer does not advertise (it advertises %v)",
				f.selectedGrant(), named, advertised)
		}
		return named, nil
	}

	if len(advertised) > 0 {
		return advertised[0], nil
	}
	return issuerURL, nil
}
