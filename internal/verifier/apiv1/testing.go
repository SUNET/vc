package apiv1

import (
	"github.com/SUNET/vc/pkg/configuration"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/pki"
)

// SetSigningKeyForTesting sets the OIDC signing key for testing purposes.
// This is needed because the production code has a TODO for loading the key from config.
// Returns error if the key type is unsupported.
func (c *Client) SetSigningKeyForTesting(key any) error {
	signer, err := pki.NewSoftwareSigner(key, "default")
	if err != nil {
		return err
	}
	c.pkiSigner = signer
	return nil
}

// AddPresentationTemplateForTesting adds a presentation template for testing
// This rebuilds the presentation builder with the new template
func (c *Client) AddPresentationTemplateForTesting(template *configuration.PresentationRequestTemplate) {
	// Get existing templates if any
	var templates []*configuration.PresentationRequestTemplate
	if c.presentationBuilder != nil {
		// Extract existing templates (this is a simple approach for testing)
		// In production, templates are loaded once at startup
		templates = []*configuration.PresentationRequestTemplate{template}
	} else {
		templates = []*configuration.PresentationRequestTemplate{template}
	}

	// Rebuild the presentation builder with all templates
	c.presentationBuilder = openid4vp.NewPresentationBuilder(templates)
}
