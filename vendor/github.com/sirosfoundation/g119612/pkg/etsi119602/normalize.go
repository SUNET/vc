package etsi119602

import (
	"strings"
)

// NormalizeStatusURI normalizes a service status URI by ensuring consistent
// scheme (http) and removing trailing slashes. This addresses the issue where
// ETSI TSLs use varying forms of the same URI:
//
//   - "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"
//   - "https://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted/"
//   - "https://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"
//
// All normalize to "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted".
func NormalizeStatusURI(uri string) string {
	return normalizeETSIURI(uri)
}

// NormalizeServiceTypeURI normalizes a service type URI using the same rules.
func NormalizeServiceTypeURI(uri string) string {
	return normalizeETSIURI(uri)
}

// StatusEquals compares two service status URIs after normalization.
func StatusEquals(a, b string) bool {
	return normalizeETSIURI(a) == normalizeETSIURI(b)
}

// normalizeETSIURI normalizes an ETSI URI by:
//  1. Trimming whitespace
//  2. Normalizing https:// to http:// for ETSI URIs
//  3. Removing trailing slashes
func normalizeETSIURI(uri string) string {
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return uri
	}

	// Normalize scheme for ETSI URIs (canonical form uses http://)
	if strings.HasPrefix(uri, "https://uri.etsi.org/") {
		uri = "http://" + uri[len("https://"):]
	}

	// Remove trailing slash(es)
	uri = strings.TrimRight(uri, "/")

	return uri
}
