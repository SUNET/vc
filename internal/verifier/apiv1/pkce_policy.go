package apiv1

import (
	"github.com/SUNET/vc/internal/verifier/db"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/oauth2"
)

// tokenEndpointAuthNone is the token_endpoint_auth_method of a public
// client - one that holds no client secret.
const tokenEndpointAuthNone = "none"

// pkceRequired reports whether this client must send a code_challenge.
//
// One rule for every client, which is the point: enforcement used to depend
// on how the client was created. A dynamically registered client was always
// required to use PKCE - the `requirePKCE := req.CodeChallengeMethod != ""`
// that looked like an opt-in could not be false, because the field carries
// `default:"S256"` and bindings apply defaults before binding. A static
// client was never required to and could not be configured to, because the
// db.Client built from YAML never set the flag (SUNET/vc#757).
//
// Three steps, in order:
//
//  1. A public client always needs PKCE. Without a client secret it is the
//     only thing binding an authorization code to whoever requested it, so
//     RFC 9700 2.1.1 requires it and nothing here can waive it. Checked
//     before the stored flag, so a db.Client built somewhere that forgets
//     to set RequirePKCE still cannot produce an unprotected public client.
//  2. For a client configured in YAML, the flag is the whole answer:
//     getClientByID has already run staticClientRequiresPKCE over it,
//     including an operator's explicit exemption for that one client - a
//     three-state decision a plain bool on db.Client cannot carry.
//  3. For a dynamically registered client, RequirePKCE pins it on. The
//     flag can only tighten; there is no stored value that turns PKCE off,
//     because a client asking to be exempt is a client certifying its own
//     security posture.
//  4. Otherwise the OP's policy, which defaults to true.
//
// Step 4 is what makes require_pkce reach dynamic clients and not only the
// ones written in YAML. Registration stores no policy of its own, so an
// operator relaxing the policy relaxes it for both kinds alike.
func (c *Client) pkceRequired(client *db.Client, isStatic bool) bool {
	if client.TokenEndpointAuthMethod == tokenEndpointAuthNone {
		return true
	}
	if isStatic {
		return client.RequirePKCE
	}
	if client.RequirePKCE {
		return true
	}
	return opRequiresPKCE(c.cfg)
}

// opRequiresPKCE is the OP-wide policy.
func opRequiresPKCE(cfg *model.Cfg) bool {
	if cfg == nil || cfg.Verifier == nil || cfg.Verifier.Outbound.OIDCProvider == nil {
		return true
	}
	return model.BoolVal(cfg.Verifier.Outbound.OIDCProvider.RequirePKCE, true)
}

// staticClientRequiresPKCE resolves the policy for a client configured in
// YAML, which has no registration request to carry the decision.
//
// Precedence: a public client always; then the client's own require_pkce,
// which can exempt one laggard without relaxing the policy for the rest;
// then the OP's.
func staticClientRequiresPKCE(static model.StaticOIDCClient, cfg *model.Cfg) bool {
	if static.TokenEndpointAuthMethod == tokenEndpointAuthNone {
		return true
	}
	if static.RequirePKCE != nil {
		return *static.RequirePKCE
	}
	return opRequiresPKCE(cfg)
}

// pkceMethodSupported reports whether this is a code_challenge_method the
// OP will honour.
//
// Only S256. CreateCodeChallenge returns the verifier unchanged for every
// other value, so an unrecognised method - and an OMITTED one, which RFC
// 7636 4.3 defines as "plain" - was silently downgraded to plain, where the
// challenge IS the verifier and anyone who sees the code can redeem it.
// Discovery has only ever advertised ["S256"]; this makes the authorization
// endpoint enforce what the metadata promises, as RFC 9700 2.1.1 requires.
func pkceMethodSupported(method string) bool {
	return method == oauth2.CodeChallengeMethodS256
}
