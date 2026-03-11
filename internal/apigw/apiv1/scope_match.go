package apiv1

import (
	"fmt"
	"vc/pkg/model"
)

// matchScope finds the first scope that has a corresponding credential constructor
// in the configuration. Returns the matched scope and its credential constructor.
// This avoids blindly picking Scopes[0] when multiple scopes may be present.
func (c *Client) matchScope(scopes []string) (string, *model.CredentialConstructor, error) {
	for _, s := range scopes {
		if cc := c.cfg.GetCredentialConstructor(s); cc != nil {
			return s, cc, nil
		}
	}
	return "", nil, fmt.Errorf("no matching credential constructor for scopes: %v", scopes)
}
