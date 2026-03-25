package httpserver

import (
	"github.com/SUNET/vc/internal/apigw/samlsp"
)

// SAMLSPService is the actual SAML service when SAML is enabled
type SAMLSPService = *samlsp.Service
