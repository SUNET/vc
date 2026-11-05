package registry

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"

	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

// ClientIDScheme identifies an OpenID4VP client_id_scheme whose semantics
// require the presented certificate to be cryptographically or structurally
// bound to the claimed identity value, rather than merely chaining to some
// trusted CA. Per OpenID4VP, the client_id itself carries the claim that
// must be checked against the certificate's content:
//   - x509_san_dns: client_id is a DNS name that MUST appear as a dNSName
//     Subject Alternative Name in the presented leaf certificate.
//   - x509_san_uri: client_id is a URI that MUST appear as a
//     uniformResourceIdentifier SAN in the presented leaf certificate.
//   - x509_hash: client_id is the SHA-256 digest (hex or base64url encoded)
//     of the presented leaf certificate's DER encoding.
//
// Verifying chain-of-trust to a root CA (system pool, TSL, or LoTE) proves a
// certificate was validly issued; it says nothing about whether it belongs
// to the identity being claimed. VerifyLeafBinding closes that gap and MUST
// be called by any registry that grants trust via a certificate pool that
// isn't already scoped to a single, already-identified entity's own certs.
type ClientIDScheme string

const (
	ClientIDSchemeX509SANDNS ClientIDScheme = "x509_san_dns"
	ClientIDSchemeX509SANURI ClientIDScheme = "x509_san_uri"
	ClientIDSchemeX509Hash   ClientIDScheme = "x509_hash"
)

// clientIDSchemes lists the recognized non-HTTP(S) client_id_scheme prefixes
// that carry a certificate-binding claim, in a fixed order so
// ParseClientIDScheme is deterministic.
var clientIDSchemes = []ClientIDScheme{
	ClientIDSchemeX509SANDNS,
	ClientIDSchemeX509SANURI,
	ClientIDSchemeX509Hash,
}

// ParseClientIDScheme splits a raw (pre-normalization) OpenID4VP client_id /
// AuthZEN Subject.ID value into its client_id_scheme prefix and bare value.
// Use OriginalSubjectID to recover the pre-normalization form when the
// request has passed through RegistryManager.Evaluate, which rewrites
// Subject.ID (e.g. "x509_san_dns:host" -> "https://host") for whitelist
// matching purposes.
//
// Examples:
//
//	"x509_san_dns:example.com"        -> (ClientIDSchemeX509SANDNS, "example.com", true)
//	"x509_san_uri:https://rp.example" -> (ClientIDSchemeX509SANURI, "https://rp.example", true)
//	"x509_hash:deadbeef..."           -> (ClientIDSchemeX509Hash, "deadbeef...", true)
//	"https://example.com"             -> ("", "", false)
//	"did:web:example.com"             -> ("", "", false)
func ParseClientIDScheme(id string) (scheme ClientIDScheme, value string, ok bool) {
	for _, s := range clientIDSchemes {
		prefix := string(s) + ":"
		if strings.HasPrefix(id, prefix) {
			return s, strings.TrimPrefix(id, prefix), true
		}
	}
	return "", "", false
}

// VerifyLeafBinding checks that leaf is bound to the claimed identity for the
// given client_id_scheme. Returns nil when bound, otherwise an error
// describing the mismatch (safe to surface in a deny reason - it does not
// leak anything the caller didn't already present).
//
// Callers should treat an unrecognized scheme as a hard deny, not as "no
// check needed": only the three schemes above have OpenID4VP-defined
// certificate-binding semantics, so there is no way to verify that an
// arbitrary other identifier (e.g. a did: value) is bound to a presented x5c
// chain at all.
func VerifyLeafBinding(scheme ClientIDScheme, value string, leaf *x509.Certificate) error {
	switch scheme {
	case ClientIDSchemeX509SANDNS:
		if !DNSSANMatches(value, leaf.DNSNames) {
			return fmt.Errorf("client_id %q does not match any DNS SAN in the presented certificate (dns_sans=%v)", value, leaf.DNSNames)
		}
		return nil

	case ClientIDSchemeX509SANURI:
		if !URISANMatches(value, leaf.URIs) {
			return fmt.Errorf("client_id %q does not match any URI SAN in the presented certificate", value)
		}
		return nil

	case ClientIDSchemeX509Hash:
		digest := sha256.Sum256(leaf.Raw)
		hexDigest := hex.EncodeToString(digest[:])
		b64Digest := base64.RawURLEncoding.EncodeToString(digest[:])
		if !strings.EqualFold(value, hexDigest) && value != b64Digest {
			return fmt.Errorf("client_id hash %q does not match the SHA-256 digest of the presented certificate", value)
		}
		return nil

	default:
		return fmt.Errorf("unrecognized client_id_scheme %q: cannot verify certificate binding", scheme)
	}
}

// DNSSANMatches reports whether clientID matches one of dnsNames, per
// OpenID4VP's x509_san_dns semantics with RFC 6125 single-label wildcard
// support: "*.example.com" matches "sub.example.com" but not "example.com" or
// "deep.sub.example.com". Comparison is ASCII case-insensitive, as DNS names
// are; nothing else is folded, so a non-ASCII clientID (a U-label) never
// matches: an internationalised name must be presented as its A-label.
func DNSSANMatches(clientID string, dnsNames []string) bool {
	for _, dnsName := range dnsNames {
		if equalASCIIFold(dnsName, clientID) {
			return true
		}
		if strings.HasPrefix(dnsName, "*.") {
			suffix := dnsName[1:]     // *.example.com -> .example.com
			baseDomain := dnsName[2:] // *.example.com -> example.com
			if len(clientID) > len(suffix) && equalASCIIFold(clientID[len(clientID)-len(suffix):], suffix) && !equalASCIIFold(clientID, baseDomain) {
				// Ensure only a single label before the suffix (no nested subdomains).
				prefix := clientID[:len(clientID)-len(suffix)]
				if !strings.Contains(prefix, ".") {
					return true
				}
			}
		}
	}
	return false
}

// equalASCIIFold reports whether a and b are equal when only ASCII letters are
// case-folded. Unlike strings.EqualFold it never folds non-ASCII characters
// (U+212A KELVIN SIGN would otherwise equal "k").
func equalASCIIFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if x >= 'A' && x <= 'Z' {
			x += 'a' - 'A'
		}
		if y >= 'A' && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

// URISANMatches reports whether clientID matches one of the certificate's
// URI SANs, per OpenID4VP's x509_san_uri semantics (exact match).
func URISANMatches(clientID string, uris []*url.URL) bool {
	for _, u := range uris {
		if u != nil && u.String() == clientID {
			return true
		}
	}
	return false
}

// OriginalSubjectIDContextKey is the EvaluationRequest.Context key under
// which RegistryManager.Evaluate stashes the pre-normalization Subject.ID
// before rewriting it via NormalizeSubjectID. Unexported deliberately -
// callers should go through OriginalSubjectID rather than reading the
// context map directly.
const originalSubjectIDContextKey = "_original_subject_id"

// OriginalSubjectID returns req.Subject.ID as it was originally received,
// before any RegistryManager normalization (e.g. "x509_san_dns:host" ->
// "https://host"). Falls back to req.Subject.ID unchanged when the request
// never passed through RegistryManager.Evaluate (e.g. a registry's own unit
// tests calling Evaluate directly), so existing scheme-prefixed test
// fixtures keep working unmodified.
func OriginalSubjectID(req *authzen.EvaluationRequest) string {
	if req.Context != nil {
		if v, ok := req.Context[originalSubjectIDContextKey].(string); ok && v != "" {
			return v
		}
	}
	return req.Subject.ID
}

// StashOriginalSubjectID records id (the pre-normalization Subject.ID) on
// req.Context under the key OriginalSubjectID reads from. Called by
// RegistryManager.Evaluate before it rewrites req.Subject.ID.
func StashOriginalSubjectID(req *authzen.EvaluationRequest, id string) {
	if req.Context == nil {
		req.Context = make(map[string]interface{})
	}
	req.Context[originalSubjectIDContextKey] = id
}
