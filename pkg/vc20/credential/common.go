package credential

import "github.com/piprate/json-gold/ld"

const (
	// ContextV2 is the URL for the W3C Verifiable Credentials Data Model v2.0 context
	ContextV2 = "https://www.w3.org/ns/credentials/v2"

	// ProofTypeDataIntegrity is the type for Data Integrity Proofs
	ProofTypeDataIntegrity = "DataIntegrityProof"
)

// NewJSONLDOptions creates a new JsonLdOptions with the global document loader configured
func NewJSONLDOptions(base string) *ld.JsonLdOptions {
	opts := ld.NewJsonLdOptions(base)
	opts.DocumentLoader = GetGlobalLoader()
	return opts
}
