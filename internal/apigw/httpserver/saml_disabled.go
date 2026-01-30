//go:build !saml

package httpserver

// SAMLService is a stub type when SAML is not enabled
type SAMLService interface {
	Close(ctx any) error
}
