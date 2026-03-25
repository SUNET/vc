package httpserver

import (
	"github.com/SUNET/vc/internal/apigw/oidcrp"
)

// OIDCRPService is the actual OIDC RP service when OIDC RP is enabled
type OIDCRPService = *oidcrp.Service
