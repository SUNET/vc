//go:build !saml

package httpserver

import "context"

// SAMLSPService is a stub type when SAML is not enabled
type SAMLSPService interface {
	Close(ctx context.Context) error
}
