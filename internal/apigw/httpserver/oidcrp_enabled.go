package httpserver

import (
	"vc/internal/apigw/oidcrp"
)

// OIDCRPService is the actual OIDC RP service when OIDC RP is enabled
type OIDCRPService = *oidcrp.Service
