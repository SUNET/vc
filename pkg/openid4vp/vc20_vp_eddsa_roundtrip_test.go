package openid4vp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/vc20/credential"
	ecdsaSuite "github.com/SUNET/vc/pkg/vc20/crypto/ecdsa"
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
// can be forced - eddsa.TestVerifyRefusesAProofMovedOntoACustomLinkedCredential
// moves the proof onto a credential the presentation carries and fails
// without it.
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
// Verify USED TO remove every proof when hashing, so moving a proof from the
// presentation onto the embedded credential left the canonical form - and
// therefore the hash - unchanged. Someone holding a legitimately signed
// presentation could move the holder's proof down onto the credential,
// delete the presentation's own proof, and offer a document the holder never
// signed in that shape, which "verify whichever proof is in there" accepted
// with the holder's key.
//
// A document that attaches no proof to ITSELF is refused now, whatever it
// carries further down - and the hash is scoped to the root's own proofs, so
// a moved proof stays in the secured document and would not verify even if
// it were selected.
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

// signedExampleDocument signs a minimal credential written against
// documentContext with method as its verificationMethod, and returns the
// signed document as a map ready to rewrite by hand.
//
// The proof is always made over the ABSOLUTE method IRI; the tests below then
// change only the JSON SPELLING of it, so what they exercise is the handler's
// context handling rather than a different signature.
func signedExampleDocument(t *testing.T, documentContext any, method string, key ed25519.PrivateKey) map[string]any {
	t.Helper()

	document, err := json.Marshal(map[string]any{
		"@context":          documentContext,
		"type":              []any{"VerifiableCredential"},
		"issuer":            "did:example:issuer",
		"credentialSubject": map[string]any{"id": "did:example:subject"},
	})
	require.NoError(t, err)

	cred, err := credential.NewRDFCredentialFromJSON(document, nil)
	require.NoError(t, err)

	signed, err := eddsaSuite.NewSuite().Sign(cred, key, &eddsaSuite.SignOptions{
		VerificationMethod: method,
		ProofPurpose:       "assertionMethod",
		Created:            time.Now().UTC(),
	})
	require.NoError(t, err)

	compact, err := signed.ToCompactJSON()
	require.NoError(t, err)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(compact, &doc))
	return doc
}

// rootProofOf returns the document's own proof object, failing the test if the
// document carries anything else - a proof SET would make "the proof" unclear
// and the rewriting these tests do meaningless.
func rootProofOf(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	proof, ok := doc["proof"].(map[string]any)
	require.True(t, ok, "the signed document must carry exactly one root proof")
	return proof
}

// verifyWithResolvedMethod runs VerifyAndExtract over a hand-rewritten
// document, with a resolver that answers for exactly one verification method -
// the absolute identifier, which is what a key belongs to and what the RDF
// form carries.
func verifyWithResolvedMethod(t *testing.T, doc map[string]any, method string, pub crypto.PublicKey) (*VC20VerificationResult, error) {
	t.Helper()

	rewritten, err := json.Marshal(doc)
	require.NoError(t, err)

	handler, err := NewVC20Handler(WithVC20KeyResolver(&mockVC20KeyResolverByMethod{
		keys: map[string]crypto.PublicKey{method: pub},
	}))
	require.NoError(t, err)

	return handler.VerifyAndExtract(t.Context(), string(rewritten))
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

	doc := signedExampleDocument(t, []any{
		"https://www.w3.org/ns/credentials/v2",
		map[string]any{"ex": "https://example.org/keys#"},
	}, absoluteMethod, issuerKey)

	// Rewritten to the COMPACT spelling, which expands to the same IRI
	// under this document's own context - so the RDF the signature covers
	// is unchanged and only the JSON spelling differs. Signing with the
	// prefix directly would not produce this document: Sign writes a v2-only
	// @context into the proof node, under which "ex:key-1" is a relative
	// reference and drops out of the proof's RDF entirely.
	proof := rootProofOf(t, doc)
	require.Equal(t, absoluteMethod, proof["verificationMethod"])
	delete(proof, "@context")
	proof["verificationMethod"] = "ex:key-1"

	result, err := verifyWithResolvedMethod(t, doc, absoluteMethod, issuerPub)
	require.NoError(t, err, "a compact verificationMethod names the same key as its expansion")
	require.Equal(t, absoluteMethod, result.VerificationMethod)
}

// TestVerifyAndExtractAcceptsAProofLocalPrefix: a nested proof may carry its
// own @context that adds terms, and the method is written under THAT active
// context. Expanding under the document's root context alone resolves a
// proof-local prefix wrongly, or not at all, and the credential is rejected
// even with the right key.
//
// What pins this is now the expansion rootProofCandidates does, not
// expandVerificationMethod - reading the proof off the raw JSON instead fails
// this test, which is the shape the handler had before root-proof selection
// moved to the expanded document.
func TestVerifyAndExtractAcceptsAProofLocalPrefix(t *testing.T) {
	issuerPub, issuerKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	const absoluteMethod = "https://example.org/keys#key-1"

	doc := signedExampleDocument(t, "https://www.w3.org/ns/credentials/v2", absoluteMethod, issuerKey)

	// The prefix is defined on the PROOF, not on the document - and the
	// document's own context stays as it was, so nothing but the proof's
	// local context can resolve "ex:key-1".
	require.Equal(t, "https://www.w3.org/ns/credentials/v2", doc["@context"],
		"the document must NOT define the prefix, or this proves nothing")
	proof := rootProofOf(t, doc)
	proof["@context"] = []any{
		"https://www.w3.org/ns/credentials/v2",
		map[string]any{"ex": "https://example.org/keys#"},
	}
	proof["verificationMethod"] = "ex:key-1"

	result, err := verifyWithResolvedMethod(t, doc, absoluteMethod, issuerPub)
	require.NoError(t, err, "a proof-local prefix names the same key as its expansion")
	require.Equal(t, absoluteMethod, result.VerificationMethod)
}

// TestVerifyAndExtractHonoursTheProofsContextOrder: context processing is
// ORDERED, and a proof's context may re-apply a URL the document already
// carries in order to put a term back. Joining the two into one array and
// dropping the repeat - which is what avoiding json-gold's "recursive
// context inclusion" error by de-duplicating did - silently leaves the
// earlier definition standing, and the method is then resolved under the
// wrong identifier.
//
// Nesting the proof's context inside the document's, as the document itself
// does, gets the order and the repeats right without this code knowing the
// rules. (The other half of the same story, a null RESET, cannot be built
// on the VC 2.0 context: its terms are @protected and json-gold refuses to
// nullify them.)
func TestVerifyAndExtractHonoursTheProofsContextOrder(t *testing.T) {
	issuerPub, issuerKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	const absoluteMethod = "https://example.org/keys#key-1"
	const rightPrefix = "https://example.org/right-prefix"
	const wrongPrefix = "https://example.org/wrong-prefix"

	// Registered locally so expansion is offline. Both define "ex"; which
	// one wins is decided entirely by the order they are applied in.
	credential.GetGlobalLoader().AddContext(rightPrefix, `{"@context":{"ex":"https://example.org/keys#"}}`)
	credential.GetGlobalLoader().AddContext(wrongPrefix, `{"@context":{"ex":"https://example.org/elsewhere#"}}`)

	doc := signedExampleDocument(t, []any{
		"https://www.w3.org/ns/credentials/v2", rightPrefix,
	}, absoluteMethod, issuerKey)

	// The proof applies the wrong definition and then puts the right one
	// back. Flattened into the document's context and de-duplicated, the
	// trailing entry is dropped as a repeat and "ex" means the wrong thing.
	proof := rootProofOf(t, doc)
	proof["@context"] = []any{"https://www.w3.org/ns/credentials/v2", wrongPrefix, rightPrefix}
	proof["verificationMethod"] = "ex:key-1"

	result, err := verifyWithResolvedMethod(t, doc, absoluteMethod, issuerPub)
	require.NoError(t, err, "the proof's own context ordering decides what ex means")
	require.Equal(t, absoluteMethod, result.VerificationMethod)
}

// TestVerifyAndExtractReportsTheECDSAProofThatVerified is the ECDSA half of
// TestVerifyAndExtractReportsTheProofThatVerified: that suite tries every
// root proof too, so the handler must build its result from the one that
// verified rather than from extractProof's first-in-the-array.
func TestVerifyAndExtractReportsTheECDSAProofThatVerified(t *testing.T) {
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cred, err := credential.NewRDFCredentialFromJSON([]byte(`{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {"id": "did:example:subject"}
	}`), nil)
	require.NoError(t, err)

	signed, err := ecdsaSuite.NewSuite().Sign(t.Context(), cred, issuerKey, &ecdsaSuite.SignOptions{
		VerificationMethod: "did:example:issuer#key-1",
		ProofPurpose:       "assertionMethod",
		Created:            time.Now().UTC(),
	})
	require.NoError(t, err)
	compact, err := signed.ToCompactJSON()
	require.NoError(t, err)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(compact, &doc))
	genuine, ok := doc["proof"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "assertionMethod", genuine["proofPurpose"])

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
		keys: map[string]crypto.PublicKey{"did:example:issuer#key-1": &issuerKey.PublicKey},
	}))
	require.NoError(t, err)

	result, err := handler.VerifyAndExtract(t.Context(), string(tampered))
	require.NoError(t, err, "the genuine proof is still there, so the document verifies")
	require.Equal(t, "assertionMethod", result.ProofPurpose,
		"the reported purpose must be the verified proof's, not the one in front of it")
	require.NotEqual(t, 2001, result.ProofCreated.Year())
}

// TestVerifyAndExtractHonoursATypeScopedContext: a type-scoped context is
// only active on a node carrying the type it is scoped to. A probe that
// omits the proof's type therefore expands the method under a different
// active context than the document does, and resolves the wrong key or
// none - while the proof itself remains cryptographically valid.
func TestVerifyAndExtractHonoursATypeScopedContext(t *testing.T) {
	issuerPub, issuerKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	const absoluteMethod = "https://example.org/keys#key-1"
	const scoped = "https://example.org/type-scoped-context"

	// "ex" is defined ONLY inside the scope of this proof type, so a node
	// that does not carry the type cannot resolve "ex:key-1" at all.
	//
	// The alias is a new name rather than DataIntegrityProof itself: that
	// term is @protected in the VC 2.0 context and json-gold refuses to
	// redefine it. It expands to the same IRI, so the RDF - and therefore
	// the signature - is unchanged.
	credential.GetGlobalLoader().AddContext(scoped, `{"@context":{
		"ProofOfMine": {
			"@id": "https://w3id.org/security#DataIntegrityProof",
			"@context": {"ex": "https://example.org/keys#"}
		}
	}}`)

	cred, err := credential.NewRDFCredentialFromJSON([]byte(`{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {"id": "did:example:subject"}
	}`), nil)
	require.NoError(t, err)

	signed, err := eddsaSuite.NewSuite().Sign(cred, issuerKey, &eddsaSuite.SignOptions{
		VerificationMethod: absoluteMethod,
		ProofPurpose:       "assertionMethod",
		Created:            time.Now().UTC(),
	})
	require.NoError(t, err)
	compact, err := signed.ToCompactJSON()
	require.NoError(t, err)

	var doc map[string]any
	require.NoError(t, json.Unmarshal(compact, &doc))
	proof, ok := doc["proof"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "DataIntegrityProof", proof["type"])
	proof["@context"] = []any{"https://www.w3.org/ns/credentials/v2", scoped}
	// BOTH types. The alias carries the scoped context that defines "ex";
	// DataIntegrityProof carries the VC 2.0 scoped context that defines
	// cryptosuite, proofValue and the rest, and dropping it would leave the
	// proof with nothing but a type.
	proof["type"] = []any{"DataIntegrityProof", "ProofOfMine"}
	proof["verificationMethod"] = "ex:key-1"

	rewritten, err := json.Marshal(doc)
	require.NoError(t, err)

	handler, err := NewVC20Handler(WithVC20KeyResolver(&mockVC20KeyResolverByMethod{
		keys: map[string]crypto.PublicKey{absoluteMethod: issuerPub},
	}))
	require.NoError(t, err)

	result, err := handler.VerifyAndExtract(t.Context(), string(rewritten))
	require.NoError(t, err, "the proof's type is what activates the context that defines ex")
	require.Equal(t, absoluteMethod, result.VerificationMethod)
	require.Equal(t, "DataIntegrityProof", result.ProofType,
		"a proof carrying several types is still reported as the one this suite produced")
}

// TestExpandVerificationMethodHonoursAnExplicitNullProofContext: in JSON-LD
// an explicit "@context": null RESETS the inherited context rather than
// leaving it in place, so a method compacted under a prefix the DOCUMENT
// defines is not resolvable on that proof. Treating null as an absent
// context expanded it anyway and handed the resolver an identifier the
// proof does not name.
//
// The identifier the resolver is asked for is the one the PROOF names,
// which under a reset is the compact form itself - and that is what the
// suite reads off the RDF too, so the two still agree.
//
// Tested on the expansion directly rather than through VerifyAndExtract,
// and the reason is worth recording: under the VC 2.0 context this shape
// cannot be built at all. Its terms are @protected, so json-gold refuses
// the reset - "invalid context nullification" - and the document fails to
// parse whatever this code does. A test through the handler would pass
// either way.
func TestExpandVerificationMethodHonoursAnExplicitNullProofContext(t *testing.T) {
	handler, err := NewVC20Handler()
	require.NoError(t, err)

	// A plain context, so the reset itself is legal - no protected terms.
	credMap := map[string]any{
		"@context": []any{map[string]any{"ex": "https://example.org/keys#"}},
	}

	t.Run("no context on the proof inherits the document's", func(t *testing.T) {
		expanded, err := handler.expandVerificationMethod(credMap,
			map[string]any{"verificationMethod": "ex:key-1"}, "ex:key-1")
		require.NoError(t, err)
		require.Equal(t, "https://example.org/keys#key-1", expanded)
	})

	t.Run("an explicit null resets it", func(t *testing.T) {
		expanded, err := handler.expandVerificationMethod(credMap,
			map[string]any{"@context": nil, "verificationMethod": "ex:key-1"}, "ex:key-1")
		require.NoError(t, err)
		require.Equal(t, "ex:key-1", expanded,
			"ex is not active on a proof whose context was reset, so the method is the IRI the proof names")
	})
}

// TestVerifyAndExtractTriesEveryRootProof: Sign appends rather than
// replaces, so a document signed by two parties carries two root proofs,
// each naming its OWN verification method. Resolving the first one's key
// and dispatching on the first one's cryptosuite meant a valid later proof
// was always checked with the wrong key.
func TestVerifyAndExtractTriesEveryRootProof(t *testing.T) {
	firstPub, firstKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	secondPub, secondKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	const unsigned = `{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {"id": "did:example:subject"}
	}`

	cred, err := credential.NewRDFCredentialFromJSON([]byte(unsigned), nil)
	require.NoError(t, err)
	once, err := eddsaSuite.NewSuite().Sign(cred, firstKey, &eddsaSuite.SignOptions{
		VerificationMethod: "did:example:first#key-1",
		ProofPurpose:       "assertionMethod",
		Created:            time.Now().UTC(),
	})
	require.NoError(t, err)
	twice, err := eddsaSuite.NewSuite().Sign(once, secondKey, &eddsaSuite.SignOptions{
		VerificationMethod: "did:example:second#key-1",
		ProofPurpose:       "assertionMethod",
		Created:            time.Now().UTC(),
	})
	require.NoError(t, err)

	compact, err := twice.ToCompactJSON()
	require.NoError(t, err)

	// The fixture is only worth something if BOTH proofs are really there.
	var doc map[string]any
	require.NoError(t, json.Unmarshal(compact, &doc))
	proofs, ok := doc["proof"].([]any)
	require.True(t, ok, "two signatures, two root proofs")
	require.Len(t, proofs, 2)

	// A resolver that knows ONLY the second signer's key. Reaching it means
	// the handler got past the first proof.
	handler, err := NewVC20Handler(WithVC20KeyResolver(&mockVC20KeyResolverByMethod{
		keys: map[string]crypto.PublicKey{"did:example:second#key-1": secondPub},
	}))
	require.NoError(t, err)

	result, err := handler.VerifyAndExtract(t.Context(), string(compact))
	require.NoError(t, err, "the second signer's proof is as much the document's own as the first")
	require.Equal(t, "did:example:second#key-1", result.VerificationMethod)

	// And the first signer's key still verifies its own proof.
	firstOnly, err := NewVC20Handler(WithVC20KeyResolver(&mockVC20KeyResolverByMethod{
		keys: map[string]crypto.PublicKey{"did:example:first#key-1": firstPub},
	}))
	require.NoError(t, err)
	result, err = firstOnly.VerifyAndExtract(t.Context(), string(compact))
	require.NoError(t, err)
	require.Equal(t, "did:example:first#key-1", result.VerificationMethod)
}

// TestVerifyAndExtractSurvivesAMalformedExtraProof: every root proof is
// removed from the document a signature covers, so APPENDING a proof does not
// disturb one already there. An appended proof that cannot be compacted must
// therefore not stop the genuine proof from being tried - aborting candidate
// collection on it turns a write anyone can make into a way to deny
// verification outright.
//
// The shape needs a round trip through RDF to exist at all: proofs become
// NAMED GRAPHS there, and a proof carrying a nested node becomes a graph
// holding two subjects rather than one proof. A verifier is handed documents
// in that form, so this is reachable, not theoretical.
func TestVerifyAndExtractSurvivesAMalformedExtraProof(t *testing.T) {
	issuerPub, issuerKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	const method = "did:example:issuer#key-1"
	doc := signedExampleDocument(t, "https://www.w3.org/ns/credentials/v2", method, issuerKey)
	genuine := rootProofOf(t, doc)

	// A proof whose graph will hold a second subject once serialized, placed
	// FIRST so a loop that stops at the first failure never reaches the
	// genuine one.
	malformed := map[string]any{
		"type":        "DataIntegrityProof",
		"cryptosuite": "eddsa-rdfc-2022",
		"@included": map[string]any{
			"id":                            "https://example.org/extra",
			"https://example.org/vocab#any": "a second subject in the proof graph",
		},
	}
	doc["proof"] = []any{malformed, genuine}

	compact, err := json.Marshal(doc)
	require.NoError(t, err)
	parsed, err := credential.NewRDFCredentialFromJSON(compact, nil)
	require.NoError(t, err)
	flattened, err := json.Marshal(parsed)
	require.NoError(t, err)

	// The malformed candidate really is uncompactable, or this proves nothing.
	reparsed, err := credential.NewRDFCredentialFromJSON(flattened, nil)
	require.NoError(t, err)
	expanded, _, err := reparsed.RootProofs()
	require.NoError(t, err)
	require.Len(t, expanded, 2)
	var uncompactable int
	for _, entry := range expanded {
		if _, err := credential.CompactRootProof(entry); err != nil {
			uncompactable++
		}
	}
	require.Equal(t, 1, uncompactable, "exactly one candidate must be uncompactable")

	handler, err := NewVC20Handler(WithVC20KeyResolver(&mockVC20KeyResolverByMethod{
		keys: map[string]crypto.PublicKey{method: issuerPub},
	}))
	require.NoError(t, err)

	_, err = handler.VerifyAndExtract(t.Context(), string(flattened))
	require.NoError(t, err, "the genuine proof is still there, so the document verifies")
}

// TestVerifyAndExtractRefusesAnUnboundedProofSet: the candidate list is read
// off the document, so its length is the sender's choice, and trying one
// candidate costs a JSON-LD canonicalization and a signature check - work done
// before anything about the document has been authenticated. A document
// claiming more proofs than any real proof set is refused rather than worked
// through.
func TestVerifyAndExtractRefusesAnUnboundedProofSet(t *testing.T) {
	issuerPub, issuerKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	const method = "did:example:issuer#key-1"
	doc := signedExampleDocument(t, "https://www.w3.org/ns/credentials/v2", method, issuerKey)
	genuine := rootProofOf(t, doc)

	// One genuine proof, and more copies than the handler will work through.
	proofs := []any{genuine}
	for i := 0; i < credential.MaxRootProofs; i++ {
		filler := map[string]any{}
		for k, v := range genuine {
			filler[k] = v
		}
		filler["created"] = fmt.Sprintf("200%d-01-01T00:00:00Z", i%10)
		filler["domain"] = fmt.Sprintf("https://example.org/%d", i)
		proofs = append(proofs, filler)
	}
	doc["proof"] = proofs

	_, err = verifyWithResolvedMethod(t, doc, method, issuerPub)
	require.ErrorContains(t, err, "more than the 32 this will verify",
		"a document may not make a verifier do unbounded work")
}

// TestVerifyAndExtractRefusesAnExpandedPresentation: an expanded presentation
// used to verify the HOLDER's proof - the one the document attaches to itself -
// while reporting the issuer, subject and trust decision of the embedded
// credential, whose own proof was never checked. The VP unwrap at step 3 could
// not see it either, because the map built from the expanded form never says
// VerifiablePresentation.
func TestVerifyAndExtractRefusesAnExpandedPresentation(t *testing.T) {
	holderPub, holderKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, issuerKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// A credential signed by the ISSUER, carried in a presentation signed by
	// the HOLDER - and only the holder's key is resolvable.
	credential0 := signedExampleDocument(t, "https://www.w3.org/ns/credentials/v2", "did:example:issuer#key-1", issuerKey)

	presentation, err := credential.NewRDFCredentialFromJSON(mustJSON(t, map[string]any{
		"@context":             "https://www.w3.org/ns/credentials/v2",
		"type":                 []any{"VerifiablePresentation"},
		"verifiableCredential": []any{credential0},
	}), nil)
	require.NoError(t, err)

	signedVP, err := eddsaSuite.NewSuite().Sign(presentation, holderKey, &eddsaSuite.SignOptions{
		VerificationMethod: "did:example:holder#key-1",
		ProofPurpose:       "authentication",
		Created:            time.Now().UTC(),
	})
	require.NoError(t, err)

	// EXPANDED form - a flattened array, which is what ToJSON produces.
	expanded, err := signedVP.ToJSON()
	require.NoError(t, err)
	var asArray []any
	require.NoError(t, json.Unmarshal(expanded, &asArray),
		"the expanded form must really be an array, or this exercises the compact path")

	handler, err := NewVC20Handler(WithVC20KeyResolver(&mockVC20KeyResolverByMethod{
		keys: map[string]crypto.PublicKey{"did:example:holder#key-1": holderPub},
	}))
	require.NoError(t, err)

	_, err = handler.VerifyAndExtract(t.Context(), string(expanded))
	require.ErrorContains(t, err, "expanded JSON-LD is not accepted",
		"the holder's proof must not stand in for the issuer's")
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	return encoded
}

// TestVerifyAndExtractReportsTheRootOfAnExpandedDocument: a flattened document
// may hold several VerifiableCredential nodes - one nested under
// credentialSubject, say - and top-level array ORDER is not signed. Reporting
// the first one in that order let a holder move a nested credential to the
// front and have its issuer and claims reported, while the proof that actually
// verified belonged to the outer credential.
func TestVerifyAndExtractReportsTheRootOfAnExpandedDocument(t *testing.T) {
	issuerPub, issuerKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	const method = "did:example:issuer#key-1"
	outer, err := credential.NewRDFCredentialFromJSON([]byte(`{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:outer-issuer",
		"credentialSubject": {
			"id": "did:example:holder",
			"https://example.org/vocab#attachment": {
				"type": ["VerifiableCredential"],
				"id": "https://example.org/credentials/nested",
				"issuer": "did:example:nested-issuer",
				"credentialSubject": {"id": "did:example:holder"}
			}
		}
	}`), nil)
	require.NoError(t, err)

	signed, err := eddsaSuite.NewSuite().Sign(outer, issuerKey, &eddsaSuite.SignOptions{
		VerificationMethod: method,
		ProofPurpose:       "assertionMethod",
		Created:            time.Now().UTC(),
	})
	require.NoError(t, err)

	flattened, err := signed.ToJSON()
	require.NoError(t, err)
	var asArray []any
	require.NoError(t, json.Unmarshal(flattened, &asArray))

	// Put the NESTED credential first, which array order permits and no
	// signature covers.
	nestedFirst := make([]any, 0, len(asArray))
	for _, entry := range asArray {
		if node, isNode := entry.(map[string]any); isNode {
			if id, _ := node["@id"].(string); id == "https://example.org/credentials/nested" {
				nestedFirst = append([]any{node}, nestedFirst...)
				continue
			}
		}
		nestedFirst = append(nestedFirst, entry)
	}
	require.Equal(t, "https://example.org/credentials/nested",
		nestedFirst[0].(map[string]any)["@id"],
		"the nested credential must really be first, or this proves nothing")

	reordered, err := json.Marshal(nestedFirst)
	require.NoError(t, err)

	handler, err := NewVC20Handler(WithVC20KeyResolver(&mockVC20KeyResolverByMethod{
		keys: map[string]crypto.PublicKey{method: issuerPub},
	}))
	require.NoError(t, err)

	result, err := handler.VerifyAndExtract(t.Context(), string(reordered))
	require.NoError(t, err)
	require.Equal(t, "did:example:outer-issuer", result.Issuer,
		"the issuer reported must be the one whose proof verified")
}

// TestVerifyAndExtractAcceptsASplitExpandedRoot: expanded JSON-LD may carry
// one node's properties across SEVERAL top-level entries, which RDF conversion
// merges back into one node. Counting those as separate candidates reported
// more than one unreferenced node and refused a document that reads perfectly
// well - and a named graph counted as a candidate too, which every
// round-tripped document has.
func TestVerifyAndExtractAcceptsASplitExpandedRoot(t *testing.T) {
	issuerPub, issuerKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	const method = "did:example:issuer#key-1"
	cred, err := credential.NewRDFCredentialFromJSON([]byte(`{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"id": "https://example.org/credentials/split",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {"id": "did:example:subject"}
	}`), nil)
	require.NoError(t, err)

	signed, err := eddsaSuite.NewSuite().Sign(cred, issuerKey, &eddsaSuite.SignOptions{
		VerificationMethod: method,
		ProofPurpose:       "assertionMethod",
		Created:            time.Now().UTC(),
	})
	require.NoError(t, err)

	flattened, err := signed.ToJSON()
	require.NoError(t, err)
	var entries []any
	require.NoError(t, json.Unmarshal(flattened, &entries))

	// SPLIT the credential node in two, which expansion permits and RDF
	// conversion merges back.
	split := make([]any, 0, len(entries)+1)
	for _, entry := range entries {
		node, isNode := entry.(map[string]any)
		if !isNode {
			split = append(split, entry)
			continue
		}
		id, _ := node["@id"].(string)
		if id != "https://example.org/credentials/split" {
			split = append(split, entry)
			continue
		}
		moved := map[string]any{"@id": id}
		for _, key := range []string{"https://www.w3.org/2018/credentials#issuer"} {
			if value, present := node[key]; present {
				moved[key] = value
				delete(node, key)
			}
		}
		require.Len(t, moved, 2, "a property must actually move, or nothing is split")
		split = append(split, node, moved)
	}

	reserialized, err := json.Marshal(split)
	require.NoError(t, err)

	handler, err := NewVC20Handler(WithVC20KeyResolver(&mockVC20KeyResolverByMethod{
		keys: map[string]crypto.PublicKey{method: issuerPub},
	}))
	require.NoError(t, err)

	result, err := handler.VerifyAndExtract(t.Context(), string(reserialized))
	require.NoError(t, err, "a node split across entries is still one node")
	require.Equal(t, "did:example:issuer", result.Issuer)
}

// TestVerifyAndExtractAcceptsACredentialCarryingAPresentation: refusing an
// expanded document because SOMETHING in it is a presentation rejects a
// credential that carries one as evidence - a perfectly verifiable document
// whose own proof is the issuer's. Root selection says which node the proofs
// belong to, so the root is the node to ask about.
func TestVerifyAndExtractAcceptsACredentialCarryingAPresentation(t *testing.T) {
	issuerPub, issuerKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	const method = "did:example:issuer#key-1"
	cred, err := credential.NewRDFCredentialFromJSON([]byte(`{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"id": "https://example.org/credentials/outer",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {
			"id": "did:example:subject",
			"https://example.org/vocab#evidence": {
				"id": "https://example.org/presentations/carried",
				"type": ["VerifiablePresentation"],
				"holder": "did:example:holder"
			}
		}
	}`), nil)
	require.NoError(t, err)

	signed, err := eddsaSuite.NewSuite().Sign(cred, issuerKey, &eddsaSuite.SignOptions{
		VerificationMethod: method,
		ProofPurpose:       "assertionMethod",
		Created:            time.Now().UTC(),
	})
	require.NoError(t, err)

	flattened, err := signed.ToJSON()
	require.NoError(t, err)
	var asArray []any
	require.NoError(t, json.Unmarshal(flattened, &asArray),
		"the expanded form must be an array, or this exercises the compact path")

	handler, err := NewVC20Handler(WithVC20KeyResolver(&mockVC20KeyResolverByMethod{
		keys: map[string]crypto.PublicKey{method: issuerPub},
	}))
	require.NoError(t, err)

	result, err := handler.VerifyAndExtract(t.Context(), string(flattened))
	require.NoError(t, err, "a credential that CARRIES a presentation is still a credential")
	require.Equal(t, "did:example:issuer", result.Issuer)
}
