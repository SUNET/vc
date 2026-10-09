package apiv1

import (
	"github.com/SUNET/vc/internal/verifier/db"
	"github.com/SUNET/vc/pkg/model"
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
// The floor is a public client. Without a client secret, PKCE is the only
// thing binding an authorization code to whoever requested it, so RFC 9700
// 2.1.1 requires it and no configuration here can waive it. Checked before
// the stored flag, so a db.Client built somewhere that forgets to set
// RequirePKCE still cannot produce an unprotected public client.
func pkceRequired(client *db.Client) bool {
	if client.TokenEndpointAuthMethod == tokenEndpointAuthNone {
		return true
	}
	return client.RequirePKCE
}

// staticClientRequiresPKCE resolves the policy for a client configured in
// YAML, which has no registration request to carry the decision.
//
// Precedence: a public client always; then the client's own require_pkce;
// then the OP's require_pkce, which defaults to true.
func staticClientRequiresPKCE(static model.StaticOIDCClient, op *model.OIDCOP) bool {
	if static.TokenEndpointAuthMethod == tokenEndpointAuthNone {
		return true
	}
	if static.RequirePKCE != nil {
		return *static.RequirePKCE
	}
	if op == nil {
		return true
	}
	return model.BoolVal(op.RequirePKCE, true)
}
