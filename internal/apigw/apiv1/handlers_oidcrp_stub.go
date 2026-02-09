//go:build !oidcrp

package apiv1

import (
	"context"
)

// Stub types when OIDC RP is not enabled
type OIDCRPInitiateRequest struct{}
type OIDCRPInitiateResponse struct{}
type OIDCRPCallbackRequest struct{}
type OIDCRPCallbackResponse struct{}

// OIDCRPInitiate is a no-op when OIDC RP is not enabled
func (c *Client) OIDCRPInitiate(ctx context.Context, req *OIDCRPInitiateRequest, oidcrpService any) (*OIDCRPInitiateResponse, error) {
	return nil, nil
}

// OIDCRPCallback is a no-op when OIDC RP is not enabled
func (c *Client) OIDCRPCallback(ctx context.Context, req *OIDCRPCallbackRequest, oidcrpService any) (*OIDCRPCallbackResponse, error) {
	return nil, nil
}
