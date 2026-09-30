package openid4vp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/vc20/credential"
	eddsaSuite "github.com/SUNET/vc/pkg/vc20/crypto/eddsa"

	"github.com/stretchr/testify/require"
)

// TestVPBuilderEdDSAPresentationVerifies covers the path a real presentation
// takes: VPBuilder signs, returns COMPACT JSON, and a verifier re-parses
// those bytes.
//
// Every presentation this builder produces carries a credential, and that
// is the case eddsa-rdfc-2022 could not verify in ANY serialization - not
// re-parsed, not even straight from Sign's return value - because Verify
// called NormalizeVerifiableCredentialGraph() and Sign did not, so the
// verifiableCredential graph was rewritten between signing and checking.
//
// The suite's own TestSignAndVerify_VerifiablePresentation passes on the old
// code because its presentation carries an EMPTY verifiableCredential array.
// A presentation with nothing in it was the exception, not the rule.
//
// Suite-level verification only. Holder binding - checking the
// presentation's own proof against this session's nonce and verifier - is
// what SUNET/vc#685 adds; on main VC20Handler.VerifyAndExtract verifies the
// credential it extracts, not the holder's presentation proof.
func TestVPBuilderEdDSAPresentationVerifies(t *testing.T) {
	holderPub, holderKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, issuerKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	const unsignedVC = `{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {"id": "did:example:subject"}
	}`

	for name, embedded := range map[string][][]byte{
		// Both, because they exercise different amounts of the graph: the
		// signed one adds a second proof node to the document, which is what
		// the proof-removal half of the fix is about.
		"unsigned embedded credential": {[]byte(unsignedVC)},
		"signed embedded credential":   {signedEdDSACredential(t, issuerKey, unsignedVC)},
	} {
		t.Run(name, func(t *testing.T) {
			vpBytes, buildErr := NewVPBuilder().BuildVC20Presentation(embedded, holderKey, &VPBuildOptions{
				HolderDID:          "did:example:holder",
				VerificationMethod: "did:example:holder#key-1",
				Nonce:              "test-nonce",
				Domain:             "https://verifier.example.com",
				Cryptosuite:        CryptosuiteEdDSA2022,
				Created:            time.Now().UTC(),
			})
			require.NoError(t, buildErr)

			// The builder emits compact JSON; re-parsing those bytes is what
			// a verifier does, and it is where the old code diverged.
			var compact map[string]any
			require.NoError(t, json.Unmarshal(vpBytes, &compact),
				"the builder's output is a compact JSON object")
			require.Contains(t, compact, "verifiableCredential")

			reparsed, parseErr := credential.NewRDFCredentialFromJSON(vpBytes, nil)
			require.NoError(t, parseErr)

			require.NoError(t, eddsaSuite.NewSuite().Verify(reparsed, holderPub),
				"a presentation this builder produced must verify")
		})
	}
}

// TestVPBuilderEdDSAPresentationRejectsTampering keeps the round trip from
// passing for the wrong reason.
func TestVPBuilderEdDSAPresentationRejectsTampering(t *testing.T) {
	holderPub, holderKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	vpBytes, err := NewVPBuilder().BuildVC20Presentation(
		[][]byte{[]byte(`{"@context":"https://www.w3.org/ns/credentials/v2","type":["VerifiableCredential"],"issuer":"did:example:issuer","credentialSubject":{"id":"did:example:original-subject"}}`)},
		holderKey,
		&VPBuildOptions{
			HolderDID:          "did:example:holder",
			VerificationMethod: "did:example:holder#key-1",
			Nonce:              "test-nonce",
			Domain:             "https://verifier.example.com",
			Cryptosuite:        CryptosuiteEdDSA2022,
			Created:            time.Now().UTC(),
		},
	)
	require.NoError(t, err)

	tampered := bytes.ReplaceAll(vpBytes, []byte("original-subject"), []byte("someone-else"))
	require.NotEqual(t, string(vpBytes), string(tampered), "the tamper must change the document")

	reparsed, err := credential.NewRDFCredentialFromJSON(tampered, nil)
	require.NoError(t, err)
	require.Error(t, eddsaSuite.NewSuite().Verify(reparsed, holderPub))
}

// signedEdDSACredential returns a credential carrying its issuer's proof.
func signedEdDSACredential(t *testing.T, issuerKey ed25519.PrivateKey, raw string) []byte {
	t.Helper()

	cred, err := credential.NewRDFCredentialFromJSON([]byte(raw), nil)
	require.NoError(t, err)

	signed, err := eddsaSuite.NewSuite().Sign(cred, issuerKey, &eddsaSuite.SignOptions{
		VerificationMethod: "did:example:issuer#key-1",
		ProofPurpose:       "assertionMethod",
		Created:            time.Now().UTC(),
	})
	require.NoError(t, err)

	out, err := signed.ToCompactJSON()
	require.NoError(t, err)
	return out
}

// TestVPBuilderEdDSASelectsTheHolderProof pins the PROPERTY end to end: a
// presentation carrying a signed credential has two proofs, and the one
// verified has to be the presentation's own - checked by the key that must
// NOT work as well as the one that must.
//
// Honest about what it cannot do: it passes with the unqualified search
// too, because json-gold happens to order a real VPBuilder document so that
// the holder's proof is reached first. That is exactly why relying on the
// ordering was wrong, and why the selection is pinned where the ambiguity
// can be forced - common.TestFindProofNodeInGraphs_SelectsTheRootsGraph
// builds the graph with the ISSUER's proof first and fails without it.
func TestVPBuilderEdDSASelectsTheHolderProof(t *testing.T) {
	holderPub, holderKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	issuerPub, issuerKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	vpBytes, err := NewVPBuilder().BuildVC20Presentation(
		[][]byte{signedEdDSACredential(t, issuerKey, `{
			"@context": "https://www.w3.org/ns/credentials/v2",
			"type": ["VerifiableCredential"],
			"issuer": "did:example:issuer",
			"credentialSubject": {"id": "did:example:subject"}
		}`)},
		holderKey,
		&VPBuildOptions{
			HolderDID:          "did:example:holder",
			VerificationMethod: "did:example:holder#key-1",
			Nonce:              "test-nonce",
			Domain:             "https://verifier.example.com",
			Cryptosuite:        CryptosuiteEdDSA2022,
			Created:            time.Now().UTC(),
		},
	)
	require.NoError(t, err)

	// Both proofs really are in the document.
	var vp map[string]any
	require.NoError(t, json.Unmarshal(vpBytes, &vp))
	require.Contains(t, vp, "proof", "the presentation's own proof")
	embedded, err := json.Marshal(vp["verifiableCredential"])
	require.NoError(t, err)
	require.Contains(t, string(embedded), "proofValue", "and the issuer's")

	reparsed, err := credential.NewRDFCredentialFromJSON(vpBytes, nil)
	require.NoError(t, err)
	require.NoError(t, eddsaSuite.NewSuite().Verify(reparsed, holderPub),
		"the presentation's own proof is the one verified")

	reparsed, err = credential.NewRDFCredentialFromJSON(vpBytes, nil)
	require.NoError(t, err)
	require.Error(t, eddsaSuite.NewSuite().Verify(reparsed, issuerPub),
		"the embedded credential's issuer key must not verify the presentation")
}

// TestVPBuilderEdDSARefusesAMisplacedProof is the forgery this selection
// exists to stop, and it is not theoretical.
//
// Verify removes EVERY proof when hashing, so moving a proof from the
// presentation onto the embedded credential leaves the canonical form - and
// therefore the hash - unchanged. Someone holding a legitimately signed
// presentation can move the holder's proof down onto the credential, delete
// the presentation's own proof, and offer a document the holder never
// signed in that shape. "Verify whichever proof is in there" accepts it with
// the holder's key.
//
// So a document that attaches no proof to ITSELF is refused, whatever it
// carries further down.
func TestVPBuilderEdDSARefusesAMisplacedProof(t *testing.T) {
	holderPub, holderKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	vpBytes, err := NewVPBuilder().BuildVC20Presentation(
		[][]byte{[]byte(`{
			"@context": "https://www.w3.org/ns/credentials/v2",
			"type": ["VerifiableCredential"],
			"issuer": "did:example:issuer",
			"credentialSubject": {"id": "did:example:subject"}
		}`)},
		holderKey,
		&VPBuildOptions{
			HolderDID:          "did:example:holder",
			VerificationMethod: "did:example:holder#key-1",
			Nonce:              "test-nonce",
			Domain:             "https://verifier.example.com",
			Cryptosuite:        CryptosuiteEdDSA2022,
			Created:            time.Now().UTC(),
		},
	)
	require.NoError(t, err)

	// Sanity: as issued, it verifies.
	asIssued, err := credential.NewRDFCredentialFromJSON(vpBytes, nil)
	require.NoError(t, err)
	require.NoError(t, eddsaSuite.NewSuite().Verify(asIssued, holderPub))

	// Now move the holder's proof onto the embedded credential and remove
	// the presentation's own.
	var vp map[string]any
	require.NoError(t, json.Unmarshal(vpBytes, &vp))
	holderProof, ok := vp["proof"]
	require.True(t, ok, "the presentation must start out with its own proof")
	delete(vp, "proof")

	embedded, ok := vp["verifiableCredential"].([]any)
	require.True(t, ok)
	require.Len(t, embedded, 1)
	credentialNode, ok := embedded[0].(map[string]any)
	require.True(t, ok, "the builder embeds the credential as an object")
	credentialNode["proof"] = holderProof

	moved, err := json.Marshal(vp)
	require.NoError(t, err)

	reparsed, err := credential.NewRDFCredentialFromJSON(moved, nil)
	require.NoError(t, err)
	require.Error(t, eddsaSuite.NewSuite().Verify(reparsed, holderPub),
		"a proof that is not the document's own must not verify it")
}

// mockVC20KeyResolverByMethod answers per verification method, so a test can
// say which method resolves to which key rather than returning one key for
// everything.
type mockVC20KeyResolverByMethod struct {
	keys map[string]crypto.PublicKey
}

func (m *mockVC20KeyResolverByMethod) ResolveKey(_ context.Context, vm string) (crypto.PublicKey, error) {
	key, ok := m.keys[vm]
	if !ok {
		return nil, fmt.Errorf("no key for %q", vm)
	}
	return key, nil
}

// TestVerifyAndExtractReportsTheProofThatVerified: the suite tries every
// root proof, while extractProof hands the handler the FIRST one in the
// array. Describing that one let an attacker prepend an invalid proof
// naming the real verification method with a forged proofPurpose and
// created: the suite verified the genuine proof further along, and the
// result reported the forged one's fields as verified.
func TestVerifyAndExtractReportsTheProofThatVerified(t *testing.T) {
	issuerPub, issuerKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	const unsignedVC = `{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {"id": "did:example:subject"}
	}`

	signed := signedEdDSACredential(t, issuerKey, unsignedVC)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(signed, &doc))
	genuine, ok := doc["proof"].(map[string]any)
	require.True(t, ok, "the fixture must carry exactly one proof to prepend in front of")
	require.Equal(t, "assertionMethod", genuine["proofPurpose"])

	// The forgery: same verificationMethod, so the handler resolves the real
	// key off it; everything else is the attacker's, and the proofValue is
	// not a signature at all.
	forged := map[string]any{
		"type":               genuine["type"],
		"cryptosuite":        genuine["cryptosuite"],
		"proofPurpose":       "authentication",
		"verificationMethod": genuine["verificationMethod"],
		"created":            "2001-01-01T00:00:00Z",
		"proofValue":         "z2DXFtnG8nHVsBv5SyJTgGBJYiFTRTpLKqWjDfMVSfdcKYjPfA6QLB7yFCJNtxYJ5aVzAAHNbLbEBL2fxPGZWKbvZ",
	}
	doc["proof"] = []any{forged, genuine}

	tampered, err := json.Marshal(doc)
	require.NoError(t, err)

	handler, err := NewVC20Handler(WithVC20KeyResolver(&mockVC20KeyResolverByMethod{
		keys: map[string]crypto.PublicKey{"did:example:issuer#key-1": issuerPub},
	}))
	require.NoError(t, err)

	result, err := handler.VerifyAndExtract(t.Context(), string(tampered))
	require.NoError(t, err, "the genuine proof is still there, so the document verifies")
	require.Equal(t, "assertionMethod", result.ProofPurpose,
		"the reported purpose must be the verified proof's, not the one in front of it")
	require.NotEqual(t, 2001, result.ProofCreated.Year(),
		"nor its created")
}

// TestVerifyAndExtractAcceptsACompactVerificationMethod: a compact document
// may define a prefix and write "ex:key-1" as its verificationMethod. The
// resolver was handed that spelling while the suite reads the absolute IRI
// off the RDF, so the check that the proof which VERIFIED names the method
// the key was resolved from could never match - a valid credential was
// rejected even with the right key.
func TestVerifyAndExtractAcceptsACompactVerificationMethod(t *testing.T) {
	issuerPub, issuerKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	const absoluteMethod = "https://example.org/keys#key-1"
	const prefixed = `{
		"@context": ["https://www.w3.org/ns/credentials/v2",
			{"ex": "https://example.org/keys#"}],
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {"id": "did:example:subject"}
	}`

	cred, err := credential.NewRDFCredentialFromJSON([]byte(prefixed), nil)
	require.NoError(t, err)
	signed, err := eddsaSuite.NewSuite().Sign(cred, issuerKey, &eddsaSuite.SignOptions{
		VerificationMethod: absoluteMethod,
		ProofPurpose:       "assertionMethod",
		Created:            time.Now().UTC(),
	})
	require.NoError(t, err)
	compact, err := signed.ToCompactJSON()
	require.NoError(t, err)

	// Rewritten to the COMPACT spelling, which expands to the same IRI
	// under this document's own context - so the RDF the signature covers
	// is unchanged and only the JSON spelling differs. Signing with the
	// prefix directly would not produce this document: Sign writes a v2-only
	// @context into the proof node, under which "ex:key-1" is a relative
	// reference and drops out of the proof's RDF entirely.
	var doc map[string]any
	require.NoError(t, json.Unmarshal(compact, &doc))
	proof, ok := doc["proof"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, absoluteMethod, proof["verificationMethod"])
	delete(proof, "@context")
	proof["verificationMethod"] = "ex:key-1"

	rewritten, err := json.Marshal(doc)
	require.NoError(t, err)

	// The resolver answers for the ABSOLUTE identifier, which is what a key
	// belongs to and what the RDF form carries.
	resolver := &mockVC20KeyResolverByMethod{
		keys: map[string]crypto.PublicKey{absoluteMethod: issuerPub},
	}
	handler, err := NewVC20Handler(WithVC20KeyResolver(resolver))
	require.NoError(t, err)

	result, err := handler.VerifyAndExtract(t.Context(), string(rewritten))
	require.NoError(t, err, "a compact verificationMethod names the same key as its expansion")
	require.Equal(t, absoluteMethod, result.VerificationMethod)
}

// TestVerifyAndExtractAcceptsAProofLocalPrefix: a nested proof may carry its
// own @context that adds terms, and the method is written under THAT active
// context. Expanding under the document's root context alone resolves a
// proof-local prefix wrongly, or not at all, and the credential is rejected
// even with the right key.
func TestVerifyAndExtractAcceptsAProofLocalPrefix(t *testing.T) {
	issuerPub, issuerKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	const absoluteMethod = "https://example.org/keys#key-1"
	const plain = `{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {"id": "did:example:subject"}
	}`

	cred, err := credential.NewRDFCredentialFromJSON([]byte(plain), nil)
	require.NoError(t, err)
	signed, err := eddsaSuite.NewSuite().Sign(cred, issuerKey, &eddsaSuite.SignOptions{
		VerificationMethod: absoluteMethod,
		ProofPurpose:       "assertionMethod",
		Created:            time.Now().UTC(),
	})
	require.NoError(t, err)
	compact, err := signed.ToCompactJSON()
	require.NoError(t, err)

	// The prefix is defined on the PROOF, not on the document - and the
	// document's own context stays as it was, so nothing but the proof's
	// local context can resolve "ex:key-1".
	var doc map[string]any
	require.NoError(t, json.Unmarshal(compact, &doc))
	require.Equal(t, "https://www.w3.org/ns/credentials/v2", doc["@context"],
		"the document must NOT define the prefix, or this proves nothing")
	proof, ok := doc["proof"].(map[string]any)
	require.True(t, ok)
	proof["@context"] = []any{
		"https://www.w3.org/ns/credentials/v2",
		map[string]any{"ex": "https://example.org/keys#"},
	}
	proof["verificationMethod"] = "ex:key-1"

	rewritten, err := json.Marshal(doc)
	require.NoError(t, err)

	handler, err := NewVC20Handler(WithVC20KeyResolver(&mockVC20KeyResolverByMethod{
		keys: map[string]crypto.PublicKey{absoluteMethod: issuerPub},
	}))
	require.NoError(t, err)

	result, err := handler.VerifyAndExtract(t.Context(), string(rewritten))
	require.NoError(t, err, "a proof-local prefix names the same key as its expansion")
	require.Equal(t, absoluteMethod, result.VerificationMethod)
}
