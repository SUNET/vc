package contextstore

import (
	"embed"
	"fmt"
)

//go:embed data/*.jsonld
var contextFS embed.FS

// TokenStatusListContextURL is the JSON-LD context that defines
// TokenStatusListEntry, the credentialStatus shape a W3C VC 2.0 credential
// issued by vc uses to reference an IETF Token Status List entry.
//
// THIS VALUE IS A PLACEHOLDER AND MUST BE REPLACED BEFORE ANY CREDENTIAL
// USING IT IS ISSUED OUTSIDE TESTING.
//
// draft-ietf-oauth-status-list defines bindings for JOSE (Section 6.2) and
// COSE (Section 6.3) only - there is no binding to the W3C Verifiable
// Credentials Data Model, and W3C's own credentialStatus vocabulary
// describes BitstringStatusList, a different mechanism. So this shape is
// necessarily vc's own, and the IRI it lives under is a naming decision
// that has not been made yet.
//
// It deliberately sits under the RFC 2606 ".invalid" TLD, which is
// guaranteed never to resolve. vc's own stack is unaffected - the document
// is embedded here and served from the bundle, so issuance, canonicalization
// and verification all work offline - but nobody can deploy this believing a
// third-party verifier will dereference it. Changing the two constants below
// and the IRIs in data/token-status-list-v1.jsonld is the whole change when
// the namespace is chosen.
const TokenStatusListContextURL = "https://ns.invalid/vc/token-status-list/v1"

// TokenStatusListEntryType is the credentialStatus type value defined by
// TokenStatusListContextURL.
//
// It matters that this term is DEFINED by a context the verifier resolves:
// vc signs VC 2.0 with Data Integrity over canonicalized RDF, and a term no
// context defines expands to a relative IRI and is dropped from the
// canonical form. A credentialStatus written with undefined terms would
// therefore not be covered by the proof at all - it could be stripped or
// rewritten and the signature would still verify.
const TokenStatusListEntryType = "TokenStatusListEntry"

var contextMap = map[string]string{
	"https://www.w3.org/ns/credentials/v2":   "data/credentials-v2.jsonld",
	"https://www.w3.org/2018/credentials/v1": "data/credentials-v1.jsonld",
	TokenStatusListContextURL:                "data/token-status-list-v1.jsonld",
}

// GetContext returns the content of a well-known context
func GetContext(url string) ([]byte, error) {
	filename, ok := contextMap[url]
	if !ok {
		return nil, fmt.Errorf("context not found: %s", url)
	}
	return contextFS.ReadFile(filename)
}

// GetAllContexts returns all embedded contexts
func GetAllContexts() map[string][]byte {
	result := make(map[string][]byte)
	for url, filename := range contextMap {
		data, err := contextFS.ReadFile(filename)
		if err == nil {
			result[url] = data
		}
	}
	return result
}
