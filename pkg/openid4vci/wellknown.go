package openid4vci

import "github.com/SUNET/vc/pkg/oauth2/wellknown"

// WellKnownURL is kept for existing importers; use wellknown.URL.
func WellKnownURL(entity, suffix string) string {
	return wellknown.URL(entity, suffix)
}
