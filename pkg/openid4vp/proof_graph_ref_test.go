package openid4vp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestProofGraphIsResolvedByReference: a root proof that survived a round trip
// through RDF is a REFERENCE to a named graph sitting beside the document, and
// an expanded credential carrying an embedded secured credential has more than
// one such graph. Accepting the FIRST one let top-level array order decide
// which proof the claims reported - and array order is not signed - so a
// document could be reordered until Claims["proof"] named the NESTED issuer's
// proof while rootProofCandidates verified the root's.
//
// Same defect as the one already fixed for the credential node itself, one
// field over.
func TestProofGraphIsResolvedByReference(t *testing.T) {
	proofGraph := func(id, method string) map[string]any {
		return map[string]any{
			"@id": id,
			"@graph": []any{
				map[string]any{
					"@type": []any{"https://w3id.org/security#DataIntegrityProof"},
					"https://w3id.org/security#verificationMethod": []any{
						map[string]any{"@id": method},
					},
				},
			},
		}
	}

	credential := map[string]any{
		"@id":   "https://example.org/credential",
		"@type": []any{"https://www.w3.org/2018/credentials#VerifiableCredential"},
		"https://www.w3.org/2018/credentials#issuer": []any{
			map[string]any{"@id": "did:example:issuer"},
		},
		"https://w3id.org/security#proof": []any{
			map[string]any{"@id": "https://example.org/root-proof"},
		},
	}

	// The NESTED credential's proof graph listed first, which is all an
	// attacker controls here.
	expanded := []any{
		proofGraph("https://example.org/nested-proof", "did:example:somebody-else#key-1"),
		proofGraph("https://example.org/root-proof", "did:example:issuer#key-1"),
		credential,
	}

	handler := &VC20Handler{}
	result, err := handler.extractCredentialFromExpanded(expanded)
	require.NoError(t, err)

	encoded, err := json.Marshal(result["proof"])
	require.NoError(t, err)
	require.Contains(t, string(encoded), "did:example:issuer#key-1",
		"the proof reported is the one the root's reference NAMES")
	require.NotContains(t, string(encoded), "somebody-else",
		"not whichever named graph the array happens to list first")
}

// TestProofGraphRefWithNoMatchReportsNothing: reporting the wrong proof is the
// failure being removed; saying nothing is not.
func TestProofGraphRefWithNoMatchReportsNothing(t *testing.T) {
	expanded := []any{
		map[string]any{
			"@id": "https://example.org/some-other-graph",
			"@graph": []any{
				map[string]any{"@type": []any{"https://w3id.org/security#DataIntegrityProof"}},
			},
		},
		map[string]any{
			"@id":   "https://example.org/credential",
			"@type": []any{"https://www.w3.org/2018/credentials#VerifiableCredential"},
			"https://www.w3.org/2018/credentials#issuer": []any{
				map[string]any{"@id": "did:example:issuer"},
			},
			"https://w3id.org/security#proof": []any{
				map[string]any{"@id": "https://example.org/a-graph-that-is-not-here"},
			},
		},
	}

	handler := &VC20Handler{}
	result, err := handler.extractCredentialFromExpanded(expanded)
	require.NoError(t, err)
	require.NotContains(t, result, "proof",
		"an unresolvable reference reports no proof rather than someone else's")
}

// TestProofGraphFragmentsAreMerged: valid expanded JSON-LD may split one proof
// node across several members carrying the same @id, and the cryptosuite
// merges them before verifying. Taking the first member here let UNSIGNED
// member order decide which fields were reported, so a proof could verify
// while the claims omitted whatever the later fragments carried.
func TestProofGraphFragmentsAreMerged(t *testing.T) {
	const proofID = "https://example.org/the-proof"

	expanded := []any{
		map[string]any{
			"@id": "https://example.org/root-proof",
			"@graph": []any{
				// One node, written as two members.
				map[string]any{
					"@id":   proofID,
					"@type": []any{"https://w3id.org/security#DataIntegrityProof"},
					"https://w3id.org/security#cryptosuite": []any{
						map[string]any{"@value": "eddsa-rdfc-2022"},
					},
				},
				map[string]any{
					"@id": proofID,
					"https://w3id.org/security#verificationMethod": []any{
						map[string]any{"@id": "did:example:issuer#key-1"},
					},
				},
			},
		},
		map[string]any{
			"@id":   "https://example.org/credential",
			"@type": []any{"https://www.w3.org/2018/credentials#VerifiableCredential"},
			"https://www.w3.org/2018/credentials#issuer": []any{
				map[string]any{"@id": "did:example:issuer"},
			},
			"https://w3id.org/security#proof": []any{
				map[string]any{"@id": "https://example.org/root-proof"},
			},
		},
	}

	handler := &VC20Handler{}
	result, err := handler.extractCredentialFromExpanded(expanded)
	require.NoError(t, err)

	proof, isNode := result["proof"].(map[string]any)
	require.True(t, isNode)
	require.Equal(t, "eddsa-rdfc-2022", proof["cryptosuite"],
		"the first fragment's fields are reported")
	require.Equal(t, "did:example:issuer#key-1", proof["verificationMethod"],
		"and so are the later fragment's, rather than whichever came first")
}
