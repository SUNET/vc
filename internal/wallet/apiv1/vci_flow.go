package apiv1

import (
	"github.com/SUNET/vc/internal/wallet/config"
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
}

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

	if grant, ok := grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"].(map[string]any); ok {
		if code, ok := grant["pre-authorized_code"].(string); ok && code != "" {
			f.preAuthorizedCode = code
		}
	}

	// OpenID4VCI 1.0 defines issuer_state for the Authorization Endpoint;
	// this wallet also presents it at the Authorization Challenge
	// Endpoint, which is the extension reported as openid/OpenID4VCI#815 -
	// without it, an issuance prepared by an Issuer cannot use Interactive
	// Authorization at all.
	if grant, ok := grants["authorization_code"].(map[string]any); ok {
		if state, ok := grant["issuer_state"].(string); ok && state != "" && !f.issuerStateIsConfigured {
			f.issuerState = state
		}
	}
}
