//go:build !saml

package httpserver

import "context"

// SAMLService is a stub type when SAML is not enabled
type SAMLService interface {
	Close(ctx context.Context) error
}
