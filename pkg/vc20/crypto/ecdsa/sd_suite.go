package ecdsa

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"strings"
	"time"

	"github.com/SUNET/vc/pkg/vc20/credential"

	"github.com/fxamacker/cbor/v2"
	"github.com/multiformats/go-multibase"
	"github.com/piprate/json-gold/ld"
)

const (
	CryptosuiteSd2023 = "ecdsa-sd-2023"

	// CBOR tags for ECDSA-SD proofs (W3C spec Section 3.5.2 and 3.5.7)
	cborTagBaseProof    = 23808 // 0xd9 0x5d 0x00 - Base proof header
	cborTagDerivedProof = 23809 // 0xd9 0x5d 0x01 - Derived proof header
)

// SdSuite implements the ECDSA Selective Disclosure Cryptosuite v1.0
type SdSuite struct{}

// refuseAnOverfullProofSet refuses to add a proof to a document that already
// carries as many as verification will read.
func refuseAnOverfullProofSet(cred *credential.RDFCredential) error {
	existing, _, err := cred.RootProofs()
	if err != nil {
		return fmt.Errorf("failed to read the document's own proofs: %w", err)
	}
	if len(existing) >= credential.MaxRootProofs {
		return fmt.Errorf("the document already attaches %d proofs to itself, and %d is the most this will verify", len(existing), credential.MaxRootProofs)
	}
	return nil
}

// rootScopedWithoutProof returns the document an SD proof secures: this
// document with the ROOT's own proofs removed and every nested proof left in
// place, so a nested credential's own proof is content the signature covers.
//
// It applies credential.CheckRootSurvivesFlattening first, for the same
// reason the rdfc suites do: a document that names one root as written and
// another once serialized through RDF can be re-rooted by its holder, and
// removing the NEW root's proof then reproduces a different unsecured
// document than the signer meant to secure.
func rootScopedWithoutProof(cred *credential.RDFCredential) (*credential.RDFCredential, error) {
	if err := cred.CheckRootSurvivesFlattening(); err != nil {
		return nil, err
	}
	_, withoutRootProof, err := cred.RootProofs()
	if err != nil {
		return nil, fmt.Errorf("failed to get the document the proof secures: %w", err)
	}
	return withoutRootProof, nil
}

// NewSdSuite creates a new ECDSA SD cryptosuite
func NewSdSuite() *SdSuite {
	return &SdSuite{}
}

// SdSignOptions contains options for signing with selective disclosure
type SdSignOptions struct {
	VerificationMethod string
	ProofPurpose       string
	Created            time.Time
	Domain             string
	Challenge          string
	MandatoryPointers  []string // JSON pointers to mandatory fields
}

// Sign creates a Base Proof for the credential
func (s *SdSuite) Sign(cred *credential.RDFCredential, key *ecdsa.PrivateKey, opts *SdSignOptions) (*credential.RDFCredential, error) {
	if cred == nil {
		return nil, fmt.Errorf("credential is nil")
	}
	if key == nil {
		return nil, fmt.Errorf("private key is nil")
	}
	if opts == nil {
		return nil, fmt.Errorf("sign options are nil")
	}

	// Rooted FIRST, so hashing, any JSON-pointer selection and the append
	// all read the same document. A bare @graph container is ABOUT nothing;
	// rooting it late left the proof on the wrapper rather than on the node
	// that was hashed. See credential.RootedCredential.
	cred, err := credential.RootedCredential(cred)
	if err != nil {
		return nil, err
	}

	// 1. Generate HMAC key
	hmacKey := make([]byte, 32)
	if _, err := rand.Read(hmacKey); err != nil {
		return nil, fmt.Errorf("failed to generate HMAC key: %w", err)
	}

	// 2. Transform document to N-Quads - the document this proof SECURES,
	// which is this document with the ROOT's own proofs removed and every
	// nested proof deliberately left where it is.
	//
	// The earlier reasoning here was that a credential carries no proof but
	// its own, so root-scoped and whole-graph removal came to the same
	// thing. Nothing enforces that: a credentialSubject, an evidence entry
	// or an @included node may itself be a secured credential. Removing
	// every proof in the graph left those quads outside the base
	// signature, so a nested proof could be stripped or swapped without
	// invalidating it - the same scope defect the rdfc suites had. See
	// credential.RootProofs.
	// The same cap the rdfc suites get from UnsecuredDocumentHash, and only
	// on the SIGNING path: verification must still accept a document that
	// carries the full MaxRootProofs. Without it SD appends a 33rd proof,
	// returns success, and hands back a document sdRootProofs refuses
	// before checking any signature.
	if err := refuseAnOverfullProofSet(cred); err != nil {
		return nil, err
	}

	credWithoutProof, err := rootScopedWithoutProof(cred)
	if err != nil {
		return nil, err
	}

	// Get N-Quads (normalized)
	// Note: The spec says we should skolemize *before* normalization if we want to preserve blank node relationships?
	// Actually, spec says: "Transform to RDF... Replace blank node identifiers... Canonicalize".
	// RDFCredential.CanonicalForm() does Normalize() which produces canonical N-Quads with _:c14n0 labels.
	// We need to intercept the N-Quads *before* they are canonicalized to stable IDs?
	// Or do we take the canonical IDs and HMAC them?
	// Spec: "Replace all blank node identifiers in the N-Quads with identifiers generated by HMAC..."
	// If we use CanonicalForm, we get _:c14n0, _:c14n1...
	// If we HMAC those, it's deterministic based on the content.
	// This seems correct for "Skolemization" in this context - we want stable IDs that are blinded.

	nquadsStr, err := credWithoutProof.CanonicalForm()
	if err != nil {
		return nil, fmt.Errorf("failed to get canonical form: %w", err)
	}

	// Parse N-Quads
	quads := parseNQuads(nquadsStr)

	// 3. Skolemize (HMAC blank nodes)
	// We need to replace _:c14n... with _:HMAC(...)
	// Since we used CanonicalForm, the blank nodes are already canonicalized.
	// We just need to map them.

	skolemizedQuads := make([]string, len(quads))
	for i, quad := range quads {
		skolemizedQuads[i] = skolemizeQuad(quad, hmacKey)
	}

	// 4. Separate Mandatory and Non-Mandatory N-Quads
	// Per W3C spec Section 3.6.2 Base Proof Transformation:
	// Use mandatory pointers to determine which N-Quads are mandatory
	var mandatoryQuads []string
	var nonMandatoryQuads []string

	if len(opts.MandatoryPointers) > 0 {
		// Get the original JSON-LD document for pointer selection
		var docJSON any
		originalJSON := cred.OriginalJSON()
		if originalJSON != "" {
			if err := json.Unmarshal([]byte(originalJSON), &docJSON); err != nil {
				return nil, fmt.Errorf("failed to unmarshal original JSON: %w", err)
			}
		} else {
			// Fallback: marshal the credential
			jsonBytes, err := json.Marshal(cred)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal credential: %w", err)
			}
			if err := json.Unmarshal(jsonBytes, &docJSON); err != nil {
				return nil, fmt.Errorf("failed to unmarshal credential JSON: %w", err)
			}
		}

		// Remove proof from document for pointer selection
		if docJSON, err = removeRootProof(docJSON, cred.ExpansionOptions()); err != nil {
			return nil, fmt.Errorf("failed to remove the document's own proof: %w", err)
		}

		// Select mandatory N-Quads based on pointers from original (non-skolemized) quads
		mandatorySet := make(map[string]bool)
		selectedMandatory := selectMandatoryNQuads(docJSON, quads, opts.MandatoryPointers)
		for _, q := range selectedMandatory {
			mandatorySet[q] = true
		}

		// Now map to skolemized quads - need to track which original quads became which skolemized quads
		mandatoryIndices := make(map[int]bool)
		for i, q := range quads {
			if mandatorySet[q] {
				mandatoryIndices[i] = true
			}
		}

		for i, q := range skolemizedQuads {
			if mandatoryIndices[i] {
				mandatoryQuads = append(mandatoryQuads, q)
			} else {
				nonMandatoryQuads = append(nonMandatoryQuads, q)
			}
		}
	} else {
		// No mandatory pointers - all quads are non-mandatory
		nonMandatoryQuads = skolemizedQuads
	}

	// 5. Generate ephemeral key pair (proof-scoped)
	ephemeralKey, err := ecdsa.GenerateKey(key.Curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	// 6. Sign Individual Non-Mandatory N-Quads
	// Per W3C spec Section 3.6.5 Base Proof Serialization:
	// "Initialize signatures to an array where each element holds the result of digitally signing
	// the UTF-8 representation of each N-Quad string in nonMandatory, in order."
	var signatures [][]byte

	for _, quad := range nonMandatoryQuads {
		// Hash the UTF-8 representation of the N-Quad
		hash := sha256.Sum256([]byte(quad))

		// Sign with ephemeral key
		r, s, err := ecdsa.Sign(rand.Reader, ephemeralKey, hash[:])
		if err != nil {
			return nil, fmt.Errorf("failed to sign N-Quad: %w", err)
		}

		// Serialize signature
		sigBytes := serializeSignature(r, s, ephemeralKey.Curve.Params().BitSize)
		signatures = append(signatures, sigBytes)
	}

	// 7. Create Base Proof
	// Proof Config
	created := opts.Created
	if created.IsZero() {
		created = time.Now().UTC()
	}

	proofConfig := map[string]any{
		"@context":           "https://www.w3.org/ns/credentials/v2",
		"type":               ProofType,
		"cryptosuite":        CryptosuiteSd2023,
		"verificationMethod": opts.VerificationMethod,
		"proofPurpose":       opts.ProofPurpose,
		"created":            created.Format(time.RFC3339),
	}
	if opts.Domain != "" {
		proofConfig["domain"] = opts.Domain
	}
	if opts.Challenge != "" {
		proofConfig["challenge"] = opts.Challenge
	}

	// Canonicalize Proof Config
	proofConfigBytes, err := json.Marshal(proofConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal proof config: %w", err)
	}
	ldOpts := ld.NewJsonLdOptions("")
	ldOpts.Algorithm = ld.AlgorithmURDNA2015
	proofCred, err := credential.NewRDFCredentialFromJSON(proofConfigBytes, ldOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create proof config credential: %w", err)
	}
	proofCanonical, err := proofCred.CanonicalForm()
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize proof config: %w", err)
	}
	proofHash := sha256.Sum256([]byte(proofCanonical))

	// Mandatory Hash
	// Per W3C spec Section 3.4.17 hashMandatoryNQuads:
	// "Join all of the mandatory N-Quad strings together using a single newline between each"
	// "Return the result of SHA-256 hashing the UTF-8 representation of the joined mandatory N-Quads"
	var mandatoryHash []byte
	if len(mandatoryQuads) > 0 {
		// Per W3C spec Section 3.4.17 hashMandatoryNQuads:
		// Join with newlines between each quad, plus trailing newline for final quad
		// Note: Order is determined by pointer evaluation order, not sorted
		mandatoryStr := strings.Join(mandatoryQuads, "\n") + "\n"
		h := sha256.Sum256([]byte(mandatoryStr))
		mandatoryHash = h[:]
	} else {
		// Per spec, if no mandatory quads, hash is SHA-256 of empty string
		h := sha256.Sum256([]byte(""))
		mandatoryHash = h[:]
	}

	// Ephemeral Public Key - use compressed format with multicodec prefix
	// Per W3C spec Section 3.6.5: "multikey expression of the public key"
	// "starting with the bytes 0x80 and 0x24 (multikey p256-pub header as varint)"
	ephemeralPubBytes := ellipticMarshalCompressed(ephemeralKey.PublicKey)

	// Combine for Base Signature
	// Per W3C spec Section 3.5.1 serializeSignData:
	// "Return the concatenation of proofHash, publicKey, and mandatoryHash"
	combined := append(proofHash[:], ephemeralPubBytes...)
	combined = append(combined, mandatoryHash...)

	// Hash the combined data before signing
	// Note: JavaScript WebCrypto API automatically hashes the data when signing with ECDSA,
	// but Go's crypto/ecdsa expects pre-hashed data. We must hash the combined data first.
	combinedHash := sha256.Sum256(combined)

	// Sign with Issuer Key
	sigR, sigS, err := ecdsa.Sign(rand.Reader, key, combinedHash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign base proof: %w", err)
	}
	baseSignature := serializeSignature(sigR, sigS, key.Curve.Params().BitSize)

	// Construct BaseProofValue
	bpv := BaseProofValueArray{
		BaseSignature:     baseSignature,
		PublicKey:         ephemeralPubBytes,
		HmacKey:           hmacKey,
		Signatures:        signatures,
		MandatoryPointers: opts.MandatoryPointers,
	}

	// Encode CBOR with BASE proof header
	// Per W3C spec Section 3.5.2 serializeBaseProofValue:
	// "Initialize a byte array, proofValue, that starts with the ECDSA-SD base proof header bytes 0xd9, 0x5d, and 0x00"
	cborArrayBytes, err := cbor.Marshal(bpv)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal CBOR: %w", err)
	}

	// Add CBOR tag header for BASE proof (tag 23808 = 0x5d00)
	cborBytes := make([]byte, 3+len(cborArrayBytes))
	cborBytes[0] = 0xd9 // CBOR tag marker for 2-byte tag
	cborBytes[1] = 0x5d // High byte of tag 23808
	cborBytes[2] = 0x00 // Low byte of tag 23808
	copy(cborBytes[3:], cborArrayBytes)

	// Encode Multibase (base64url-no-pad header 'u')
	proofValue, err := multibase.Encode(multibase.Base64url, cborBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to encode multibase: %w", err)
	}

	// Add to credential
	credMap, err := credential.DocumentAsMap(cred)
	if err != nil {
		return nil, err
	}

	proofConfig["proofValue"] = proofValue
	credential.AppendProofUnder(credMap, proofConfig,
		credential.ProofKeyFor(credMap, credMap["@context"], cred.ExpansionOptions()))

	newCredBytes, err := json.Marshal(credMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal new credential: %w", err)
	}

	return credential.NewRDFCredentialFromJSON(newCredBytes, ldOpts)
}

// Verify verifies an ecdsa-sd-2023 proof the document attaches to ITSELF.
//
// Selection used to be a recursive walk for the first DataIntegrityProof
// anywhere in the graph - and the traversal crosses map-backed RDF graphs, so
// "anywhere" meant it. The nested-proof shape this change now secures makes
// that actively wrong: an embedded credential's own proof could be picked
// instead of the outer one, nondeterministically, and nothing checked the
// node it landed on was even ecdsa-sd-2023.
//
// The proofs are now read off the document by credential.RootProofs, filtered
// by type and cryptosuite, and each is tried in turn - the same shape the rdfc
// suites use. A base proof is not a proof set, but a document may carry an
// ecdsa-sd-2023 proof beside proofs of other suites, and only this suite's own
// are its business.
func (s *SdSuite) Verify(cred *credential.RDFCredential, key *ecdsa.PublicKey) error {
	if cred == nil {
		return fmt.Errorf("credential is nil")
	}
	if key == nil {
		return fmt.Errorf("public key is nil")
	}

	// One selector, shared with Derive and VerifyRootProof. Three copies of
	// "which proofs are this document's own" is how selection and hashing
	// came to disagree in the first place.
	candidates, err := sdRootProofs(cred)
	if err != nil {
		return err
	}

	var lastErr error
	for _, proofMap := range candidates {
		if err := s.verifySdRootProof(cred, key, proofMap); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	return lastErr
}

// sdRootProof returns the single ecdsa-sd-2023 proof the document attaches to
// ITSELF, refusing anything else. Unlike the rdfc suites there is no trying
// each in turn here: deriving is a one-proof operation, so an ambiguous
// document must be refused rather than silently resolved.
func sdRootProof(cred *credential.RDFCredential) (map[string]any, error) {
	found, err := sdRootProofs(cred)
	if err != nil {
		return nil, err
	}
	if len(found) > 1 {
		return nil, fmt.Errorf("the document carries more than one %s proof of its own", CryptosuiteSd2023)
	}
	return found[0], nil
}

// sdRootProofs returns every ecdsa-sd-2023 proof the document attaches to
// ITSELF. A proof that will not compact is skipped rather than fatal: every
// root proof is removed from the document a signature covers, so appending a
// malformed one does not disturb a genuine proof already there, and failing on
// it would let that append deny verification.
func sdRootProofs(cred *credential.RDFCredential) ([]map[string]any, error) {
	// NO root-stability pre-check here. CompactedRootProofs reaches
	// securedDocument, which runs that check and memoizes the result -
	// running it first repeated a JSON-LD expansion and an RDF
	// serialization on every call, and VerifyRootProof is called once per
	// candidate, so a document at the proof limit paid for it 32 times
	// before anything was authenticated.
	//
	// Compacted once per document, memoized with the secured-document
	// answer, so repeating this per candidate costs nothing.
	compacted, err := credential.CompactedRootProofs(cred)
	if err != nil {
		return nil, err
	}
	if len(compacted) > credential.MaxRootProofs {
		return nil, fmt.Errorf("the document attaches %d proofs to itself, more than the %d this will verify", len(compacted), credential.MaxRootProofs)
	}

	var found []map[string]any
	for _, proofMap := range compacted {
		if !credential.HasProofType(proofMap, ProofType) {
			continue
		}
		if suite, _ := proofMap["cryptosuite"].(string); suite != CryptosuiteSd2023 {
			continue
		}
		found = append(found, proofMap)
	}
	if len(found) == 0 {
		return nil, fmt.Errorf("the document carries no %s proof of its own", CryptosuiteSd2023)
	}
	return found, nil
}

// VerifyRootProof verifies exactly the proof it is given, rather than picking
// one itself.
//
// A caller that selects a proof, resolves a key from it and then asks Verify
// to go and find a proof of its own gets two independent choices that need not
// agree: with a forged proof in front of a genuine one sharing a verification
// method, the suite can verify the genuine proof while the caller reports the
// forged one's metadata. Binding the two is the whole point - the rdfc suites
// return the proof that verified for the same reason.
//
// The proof must be one the DOCUMENT attaches to itself. Hashing is
// root-scoped, so a proof from anywhere else cannot verify here anyway; this
// refuses it with a clear error instead of an opaque signature failure.
func (s *SdSuite) VerifyRootProof(cred *credential.RDFCredential, key *ecdsa.PublicKey, proof map[string]any) (map[string]any, error) {
	if cred == nil {
		return nil, fmt.Errorf("credential is nil")
	}
	if key == nil {
		return nil, fmt.Errorf("public key is nil")
	}
	if proof == nil {
		return nil, fmt.Errorf("proof is nil")
	}

	// MATCHED among the document's own proofs, not required to be the only
	// one. The caller has already said which proof it means - demanding
	// uniqueness here would reject a document Verify accepts, since that
	// tries each root proof in turn.
	candidates, err := sdRootProofs(cred)
	if err != nil {
		return nil, err
	}

	// The WHOLE proof, not its proofValue. A forged proof that copies a
	// genuine signature but changes its proofPurpose or verificationMethod
	// is a different proof: matching on the signature bytes alone would
	// verify the genuine candidate and answer success for the forged map,
	// which is the exact guarantee this method exists to give.
	//
	// The candidate that verified is returned for the same reason - the
	// caller reports what verified rather than what it asked about.
	for _, candidate := range candidates {
		if !credential.SameProof(candidate, proof) {
			continue
		}
		if err := s.verifySdRootProof(cred, key, candidate); err != nil {
			return nil, err
		}
		return candidate, nil
	}

	return nil, fmt.Errorf("the proof offered is not an %s proof this document attaches to itself", CryptosuiteSd2023)
}

// verifySdRootProof verifies one ecdsa-sd-2023 proof. Whether it is a base or
// a derived proof is what the CBOR tag on its proofValue says.
func (s *SdSuite) verifySdRootProof(cred *credential.RDFCredential, key *ecdsa.PublicKey, proofMap map[string]any) error {
	proofValueStr, ok := proofMap["proofValue"].(string)
	if !ok {
		// Try full URIs
		proofValueStr, ok = proofMap["https://w3id.org/security#proofValue"].(string)
		if !ok {
			proofValueStr, ok = proofMap["https://www.w3.org/ns/credentials#proofValue"].(string)
		}
	}
	if !ok {
		return fmt.Errorf("proofValue not found")
	}

	// Decode proofValue
	_, proofValueBytes, err := multibase.Decode(proofValueStr)
	if err != nil {
		return fmt.Errorf("failed to decode proofValue: %w", err)
	}

	// Check for CBOR tag headers per W3C spec
	// BASE proof header: 0xd9 0x5d 0x00 (tag 23808)
	// DERIVED proof header: 0xd9 0x5d 0x01 (tag 23809)
	isBaseProof := false
	isDerivedProof := false
	cborData := proofValueBytes

	if len(proofValueBytes) >= 3 && proofValueBytes[0] == 0xd9 && proofValueBytes[1] == 0x5d {
		if proofValueBytes[2] == 0x00 {
			isBaseProof = true
			cborData = proofValueBytes[3:] // Strip CBOR tag header
		} else if proofValueBytes[2] == 0x01 {
			isDerivedProof = true
			cborData = proofValueBytes[3:] // Strip CBOR tag header
		}
	}

	// Try to decode as BaseProofValue
	var baseProof BaseProofValueArray
	if !isDerivedProof {
		if err := cbor.Unmarshal(cborData, &baseProof); err == nil {
			// Check if it has HmacKey (Base Proof specific)
			if len(baseProof.HmacKey) > 0 {
				isBaseProof = true
			}
		}
	}

	if isBaseProof {
		return s.verifyBaseProof(cred, key, &baseProof, proofMap)
	}

	var derivedProof DerivedProofValueArray
	if err := cbor.Unmarshal(cborData, &derivedProof); err != nil {
		return fmt.Errorf("failed to unmarshal proof value as Base or Derived proof: %w", err)
	}

	return s.verifyDerivedProof(cred, key, &derivedProof, proofMap)
}

func (s *SdSuite) verifyBaseProof(cred *credential.RDFCredential, key *ecdsa.PublicKey, proof *BaseProofValueArray, proofMap map[string]any) error {
	// 1. Verify Base Signature
	// Reconstruct the signed data: hash(proofHash + ephemeralPub + mandatoryHash)

	// Canonicalize Proof Config (without proofValue), on a COPY. The caller
	// holds this map - VerifyRootProof hands it back as the proof that
	// verified - so stripping the signature out of it in passing would
	// return a proof object with no signature in it.
	proofMap = maps.Clone(proofMap)
	delete(proofMap, "proofValue")
	if _, ok := proofMap["@context"]; !ok {
		proofMap["@context"] = credential.ContextV2
	}
	proofConfigBytes, err := json.Marshal(proofMap)
	if err != nil {
		return fmt.Errorf("failed to marshal proof config: %w", err)
	}
	ldOpts := ld.NewJsonLdOptions("")
	ldOpts.Algorithm = ld.AlgorithmURDNA2015
	proofCred, err := credential.NewRDFCredentialFromJSON(proofConfigBytes, ldOpts)
	if err != nil {
		return fmt.Errorf("failed to create proof config credential: %w", err)
	}
	proofCanonical, err := proofCred.CanonicalForm()
	if err != nil {
		return fmt.Errorf("failed to canonicalize proof config: %w", err)
	}
	proofHash := sha256.Sum256([]byte(proofCanonical))

	// Get the credential document for mandatory pointer selection. Root
	// scoped, exactly as Sign computed it.
	credWithoutProof, err := rootScopedWithoutProof(cred)
	if err != nil {
		return err
	}
	nquadsStr, err := credWithoutProof.CanonicalForm()
	if err != nil {
		return fmt.Errorf("failed to get canonical form: %w", err)
	}
	quads := parseNQuads(nquadsStr)

	// Calculate Mandatory Hash
	// If there are mandatory pointers, select the corresponding N-Quads and hash them
	var mandatoryHash [32]byte
	if len(proof.MandatoryPointers) > 0 {
		// Get the original JSON-LD document for pointer selection
		var docJSON any
		originalJSON := cred.OriginalJSON()
		if originalJSON != "" {
			if err := json.Unmarshal([]byte(originalJSON), &docJSON); err != nil {
				return fmt.Errorf("failed to unmarshal original JSON: %w", err)
			}
		} else {
			// Fallback: marshal the credential
			jsonBytes, err := json.Marshal(cred)
			if err != nil {
				return fmt.Errorf("failed to marshal credential: %w", err)
			}
			if err := json.Unmarshal(jsonBytes, &docJSON); err != nil {
				return fmt.Errorf("failed to unmarshal credential JSON: %w", err)
			}
		}

		// Remove proof from document for pointer selection
		if docJSON, err = removeRootProof(docJSON, cred.ExpansionOptions()); err != nil {
			return fmt.Errorf("failed to remove the document's own proof: %w", err)
		}

		// Select mandatory N-Quads based on pointers
		mandatoryQuads := selectMandatoryNQuads(docJSON, quads, proof.MandatoryPointers)

		// Hash mandatory quads (joined with newlines)
		if len(mandatoryQuads) > 0 {
			// Join with newlines between each quad, plus trailing newline for final quad
			mandatoryStr := strings.Join(mandatoryQuads, "\n") + "\n"
			mandatoryHash = sha256.Sum256([]byte(mandatoryStr))
		} else {
			// No mandatory quads found - use empty hash
			mandatoryHash = sha256.Sum256([]byte(""))
		}
	} else {
		// No mandatory pointers - use empty hash
		mandatoryHash = sha256.Sum256([]byte(""))
	}

	// Ephemeral Public Key
	ephemeralPub := proof.PublicKey

	combined := append(proofHash[:], ephemeralPub...)
	combined = append(combined, mandatoryHash[:]...)

	// Hash the combined data before verification
	// Note: JavaScript WebCrypto API automatically hashes the data when verifying with ECDSA,
	// but Go's crypto/ecdsa expects pre-hashed data. We must hash the combined data first.
	combinedHash := sha256.Sum256(combined)

	// Verify Base Signature
	if !verifySignature(key, combinedHash[:], proof.BaseSignature) {
		return fmt.Errorf("base signature verification failed")
	}

	// 2. Verify Individual N-Quad Signatures
	// Per W3C spec Section 3.6.7: verify each signature against the UTF-8 representation
	// of the corresponding non-mandatory N-Quad

	// First, get non-mandatory quads by excluding mandatory ones
	var nonMandatoryQuads []string

	if len(proof.MandatoryPointers) > 0 {
		// Get the original JSON-LD document for pointer selection
		var docJSON any
		originalJSON := cred.OriginalJSON()
		if originalJSON != "" {
			if err := json.Unmarshal([]byte(originalJSON), &docJSON); err != nil {
				return fmt.Errorf("failed to unmarshal original JSON: %w", err)
			}
		} else {
			jsonBytes, err := json.Marshal(cred)
			if err != nil {
				return fmt.Errorf("failed to marshal credential: %w", err)
			}
			if err := json.Unmarshal(jsonBytes, &docJSON); err != nil {
				return fmt.Errorf("failed to unmarshal credential JSON: %w", err)
			}
		}
		if docJSON, err = removeRootProof(docJSON, cred.ExpansionOptions()); err != nil {
			return fmt.Errorf("failed to remove the document's own proof: %w", err)
		}

		// Find mandatory quads based on original (non-skolemized) quads
		mandatorySet := make(map[string]bool)
		selectedMandatory := selectMandatoryNQuads(docJSON, quads, proof.MandatoryPointers)
		for _, q := range selectedMandatory {
			mandatorySet[q] = true
		}

		// Track which original quads are mandatory
		mandatoryIndices := make(map[int]bool)
		for i, q := range quads {
			if mandatorySet[q] {
				mandatoryIndices[i] = true
			}
		}

		// Skolemize and collect non-mandatory quads
		for i, quad := range quads {
			if !mandatoryIndices[i] {
				nonMandatoryQuads = append(nonMandatoryQuads, skolemizeQuad(quad, proof.HmacKey))
			}
		}
	} else {
		// All quads are non-mandatory
		for _, quad := range quads {
			nonMandatoryQuads = append(nonMandatoryQuads, skolemizeQuad(quad, proof.HmacKey))
		}
	}

	// Check signature count matches non-mandatory quad count
	if len(nonMandatoryQuads) != len(proof.Signatures) {
		return fmt.Errorf("number of non-mandatory quads (%d) does not match number of signatures (%d)", len(nonMandatoryQuads), len(proof.Signatures))
	}

	// Parse Ephemeral Key - handles both uncompressed (0x04) and multicodec + compressed (0x8024)
	ephemeralKey, err := parseEphemeralPublicKey(proof.PublicKey, key.Curve)
	if err != nil {
		return fmt.Errorf("failed to parse ephemeral public key: %w", err)
	}

	// Verify each signature against its corresponding N-Quad
	for i, quad := range nonMandatoryQuads {
		hash := sha256.Sum256([]byte(quad))
		if !verifySignature(ephemeralKey, hash[:], proof.Signatures[i]) {
			return fmt.Errorf("signature verification failed for N-Quad %d", i)
		}
	}

	return nil
}

func (s *SdSuite) verifyDerivedProof(cred *credential.RDFCredential, key *ecdsa.PublicKey, proof *DerivedProofValueArray, proofMap map[string]any) error {
	// 1. Verify Base Signature
	// Reconstruct signed data.
	// We need proofHash, ephemeralPub, mandatoryHash.

	// Proof Hash, on a COPY for the same reason as verifyBaseProof.
	proofMap = maps.Clone(proofMap)
	delete(proofMap, "proofValue")
	delete(proofMap, "https://w3id.org/security#proofValue")
	delete(proofMap, "https://www.w3.org/ns/credentials#proofValue")
	// Remove id to match Sign configuration
	delete(proofMap, "id")
	delete(proofMap, "@id")

	if _, ok := proofMap["@context"]; !ok {
		proofMap["@context"] = credential.ContextV2
	}
	proofConfigBytes, err := json.Marshal(proofMap)
	if err != nil {
		return fmt.Errorf("failed to marshal proof config: %w", err)
	}
	ldOpts := ld.NewJsonLdOptions("")
	ldOpts.Algorithm = ld.AlgorithmURDNA2015
	proofCred, err := credential.NewRDFCredentialFromJSON(proofConfigBytes, ldOpts)
	if err != nil {
		return fmt.Errorf("failed to create proof config credential: %w", err)
	}
	proofCanonical, err := proofCred.CanonicalForm()
	if err != nil {
		return fmt.Errorf("failed to canonicalize proof config: %w", err)
	}
	proofHash := sha256.Sum256([]byte(proofCanonical))

	// Mandatory Hash
	// We need to reconstruct mandatory quads from the derived document.
	// The derived document contains mandatory quads AND revealed non-mandatory quads.
	// How do we distinguish?
	// The proof has `MandatoryIndexes`? No, `MandatoryIndexes` in DerivedProofValue is for something else?
	// Spec: "mandatoryIndexes: A list of indices into the mandatory N-Quads list."
	// Wait, if we don't have the full list of mandatory quads, how do we verify the hash?
	// Ah, the Derived Proof does NOT contain the mandatory hash?
	// The Base Signature signs the mandatory hash.
	// So the Verifier must be able to reconstruct the mandatory hash.
	// This implies the Verifier must have ALL mandatory quads.
	// Yes, mandatory quads are always revealed.
	// So we extract mandatory quads from the derived document.
	// But we also have revealed non-mandatory quads.
	// We need to know which are which.
	// The `MandatoryIndexes` might help?
	// Or maybe we just assume all quads in the derived document are either mandatory or revealed non-mandatory.
	// But to verify the Base Signature, we need the hash of ONLY the mandatory quads.
	// If we can't separate them, we can't verify.

	// Spec Section 3.6 Verification:
	// "Transform the derived document to an RDF dataset."
	// "Filter the N-Quads to find those that are mandatory."
	// "This filtering is done by matching the N-Quads against the mandatory pointers."
	// BUT the mandatory pointers are in the Base Proof, which we don't have!
	// The Derived Proof doesn't have mandatory pointers.
	// Wait, does the Derived Proof contain the mandatory pointers?
	// The `BaseProofValue` has them. The `DerivedProofValue` does NOT.
	// So how does the verifier know what is mandatory?
	// Maybe the verifier is supposed to know the schema?
	// Or maybe `MandatoryIndexes` tells us?
	// Spec says: "mandatoryIndexes: A list of integers... indices into the list of mandatory N-Quads."
	// This seems to imply we have a list.

	// Let's check the spec again about `DerivedProofValue`.
	// It has `mandatoryIndexes`.
	// Maybe I missed something.

	// Actually, if `MandatoryPointers` was empty (as we implemented), then `mandatoryHash` is hash of empty string.
	// So we can verify if we assume no mandatory quads.
	// If there ARE mandatory quads, we need to know which ones they are.

	// For now, assume empty mandatory quads.
	mandatoryHash := sha256.Sum256([]byte(""))

	ephemeralPub := proof.PublicKey

	combined := append(proofHash[:], ephemeralPub...)
	combined = append(combined, mandatoryHash[:]...)

	// Hash the combined data before verification
	// Note: JavaScript WebCrypto API automatically hashes the data when verifying with ECDSA,
	// but Go's crypto/ecdsa expects pre-hashed data. We must hash the combined data first.
	combinedHash := sha256.Sum256(combined)

	if !verifySignature(key, combinedHash[:], proof.BaseSignature) {
		return fmt.Errorf("base signature verification failed")
	}

	// 2. Verify Revealed Quads
	// We need to apply the LabelMap BEFORE canonicalization to ensure stable IDs.
	// We replace mapped blank nodes with URNs in the JSON-LD.

	// Instead of re-expanding, we use the original JSON and remove the proof
	// manually to preserve blank node IDs. Only the ROOT's proof, to match
	// the quad set the base proof was made over.
	var credJSON any
	originalJSON := cred.OriginalJSON()
	if originalJSON != "" {
		if err := json.Unmarshal([]byte(originalJSON), &credJSON); err != nil {
			return fmt.Errorf("failed to unmarshal original JSON: %w", err)
		}
	} else {
		// Fallback
		jsonBytes, err := json.Marshal(cred)
		if err != nil {
			return fmt.Errorf("failed to get JSON: %w", err)
		}
		if err := json.Unmarshal(jsonBytes, &credJSON); err != nil {
			return fmt.Errorf("failed to unmarshal JSON: %w", err)
		}
	}

	// Remove the root's proof, and only the root's
	if credJSON, err = removeRootProof(credJSON, cred.ExpansionOptions()); err != nil {
		return fmt.Errorf("failed to remove the document's own proof: %w", err)
	}

	// Replace labels with URNs
	replaceLabelsWithURNs(credJSON, proof.LabelMap)

	// Create new credential from modified map
	modBytes, err := json.Marshal(credJSON)
	if err != nil {
		return fmt.Errorf("failed to marshal modified credential: %w", err)
	}
	ldOpts = ld.NewJsonLdOptions("")
	ldOpts.Algorithm = ld.AlgorithmURDNA2015
	modCred, err := credential.NewRDFCredentialFromJSON(modBytes, ldOpts)
	if err != nil {
		return fmt.Errorf("failed to create modified credential: %w", err)
	}

	// Get Canonical Form (this will preserve URNs)
	nquadsStr, err := modCred.CanonicalForm()
	if err != nil {
		return fmt.Errorf("failed to get canonical form: %w", err)
	}

	// Replace URNs with blank nodes in N-Quads
	// <urn:bn:HMAC> -> _:HMAC
	nquadsStr = replaceURNsInNQuads(nquadsStr)

	mappedQuads := parseNQuads(nquadsStr)

	// Separate mandatory and non-mandatory quads using MandatoryIndexes
	// MandatoryIndexes contains indices into the mapped quads that are mandatory
	mandatorySet := make(map[int]bool)
	for _, idx := range proof.MandatoryIndexes {
		mandatorySet[idx] = true
	}

	// Collect non-mandatory quads - these are the ones we verify signatures for
	var nonMandatoryQuads []string
	for i, quad := range mappedQuads {
		if !mandatorySet[i] {
			nonMandatoryQuads = append(nonMandatoryQuads, quad)
		}
	}

	// Verify signatures for non-mandatory quads
	// proof.Signatures contains signatures for the revealed non-mandatory N-Quads
	if len(nonMandatoryQuads) != len(proof.Signatures) {
		return fmt.Errorf("number of non-mandatory quads (%d) does not match number of signatures (%d)", len(nonMandatoryQuads), len(proof.Signatures))
	}

	// Parse Ephemeral Key - handles both uncompressed (0x04) and multicodec + compressed (0x8024)
	ephemeralKey, err := parseEphemeralPublicKey(proof.PublicKey, key.Curve)
	if err != nil {
		return fmt.Errorf("failed to parse ephemeral public key: %w", err)
	}

	// Verify each signature against its corresponding N-Quad
	for i, quad := range nonMandatoryQuads {
		hash := sha256.Sum256([]byte(quad))

		if !verifySignature(ephemeralKey, hash[:], proof.Signatures[i]) {
			return fmt.Errorf("signature verification failed for N-Quad %d", i)
		}
	}

	return nil
}

// Derive creates a Derived Proof from a Base Proof
func (s *SdSuite) Derive(cred *credential.RDFCredential, revealIndices []int, nonce string) (*credential.RDFCredential, error) {
	if cred == nil {
		return nil, fmt.Errorf("credential is nil")
	}

	// 1. Extract Base Proof - the document's OWN ecdsa-sd-2023 proof. A walk
	// of the graph for the first DataIntegrityProof could reach an embedded
	// credential's proof instead, and derive against a base proof that does
	// not secure this document.
	proofMap, err := sdRootProof(cred)
	if err != nil {
		return nil, err
	}

	processor := ld.NewJsonLdProcessor()
	compactOpts := ld.NewJsonLdOptions("")
	compactOpts.DocumentLoader = credential.GetGlobalLoader()

	proofValueStr, ok := proofMap["proofValue"].(string)
	if !ok {
		return nil, fmt.Errorf("proofValue not found")
	}

	_, proofValueBytes, err := multibase.Decode(proofValueStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode proofValue: %w", err)
	}

	// Handle CBOR tag header (0xd9 0x5d 0x00 for BASE proof)
	cborData := proofValueBytes
	if len(proofValueBytes) >= 3 && proofValueBytes[0] == 0xd9 && proofValueBytes[1] == 0x5d {
		if proofValueBytes[2] != 0x00 {
			return nil, fmt.Errorf("expected BASE proof (0xd9 0x5d 0x00) but got 0xd9 0x5d 0x%02x", proofValueBytes[2])
		}
		cborData = proofValueBytes[3:]
	}

	var baseProof BaseProofValueArray
	if err := cbor.Unmarshal(cborData, &baseProof); err != nil {
		return nil, fmt.Errorf("failed to unmarshal base proof: %w", err)
	}

	// 2. Get Original Quads & Skolemize. Root scoped, exactly as Sign
	// computed it - deriving from a different quad set than the base proof
	// was made over produces a derived proof nobody can verify.
	credWithoutProof, err := rootScopedWithoutProof(cred)
	if err != nil {
		return nil, err
	}
	nquadsStr, err := credWithoutProof.CanonicalForm()
	if err != nil {
		return nil, fmt.Errorf("failed to get canonical form: %w", err)
	}
	quads := parseNQuads(nquadsStr)

	skolemizedQuads := make([]string, len(quads))
	for i, quad := range quads {
		skolemizedQuads[i] = skolemizeQuad(quad, baseProof.HmacKey)
	}

	// 3. Select Revealed Quads Based on Individual N-Quads
	// Per W3C spec, signatures are for individual non-mandatory N-Quads
	// revealIndices specifies which non-mandatory N-Quads to reveal

	// First, separate mandatory from non-mandatory quads
	// Get original JSON-LD document
	originalJSON := cred.OriginalJSON()
	var docJSON any
	if originalJSON != "" {
		if err := json.Unmarshal([]byte(originalJSON), &docJSON); err != nil {
			return nil, fmt.Errorf("failed to unmarshal original JSON: %w", err)
		}
	} else {
		// Fall back to marshaling the credential
		jsonBytes, err := json.Marshal(cred)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal credential: %w", err)
		}
		if err := json.Unmarshal(jsonBytes, &docJSON); err != nil {
			return nil, fmt.Errorf("failed to unmarshal credential JSON: %w", err)
		}
	}
	if docJSON, err = removeRootProof(docJSON, cred.ExpansionOptions()); err != nil {
		return nil, fmt.Errorf("failed to remove the document's own proof: %w", err)
	}

	// Identify mandatory quads based on original (non-skolemized) quads
	mandatorySet := make(map[string]bool)
	if len(baseProof.MandatoryPointers) > 0 {
		selectedMandatory := selectMandatoryNQuads(docJSON, quads, baseProof.MandatoryPointers)
		for _, q := range selectedMandatory {
			mandatorySet[q] = true
		}
	}

	// Build non-mandatory quads list (preserving order)
	var nonMandatoryIndices []int
	var nonMandatorySkolemized []string
	for i, q := range quads {
		if !mandatorySet[q] {
			nonMandatoryIndices = append(nonMandatoryIndices, i)
			nonMandatorySkolemized = append(nonMandatorySkolemized, skolemizedQuads[i])
		}
	}

	// Validate signature count
	if len(baseProof.Signatures) != len(nonMandatorySkolemized) {
		return nil, fmt.Errorf("base proof signatures count (%d) does not match non-mandatory quads count (%d)", len(baseProof.Signatures), len(nonMandatorySkolemized))
	}

	// Select which non-mandatory N-Quads and signatures to reveal
	var derivedSignatures [][]byte
	var revealedSkolemizedQuads []string

	// Label Map: NewID -> HMAC_ID
	labelMap := make(map[string]string)
	hmacToNew := make(map[string]string)

	// Create a set of indices to reveal for quick lookup
	revealSet := make(map[int]bool)
	for _, idx := range revealIndices {
		if idx >= 0 && idx < len(nonMandatorySkolemized) {
			revealSet[idx] = true
		}
	}

	// Collect revealed quads and their signatures
	for i := range nonMandatorySkolemized {
		if revealSet[i] {
			derivedSignatures = append(derivedSignatures, baseProof.Signatures[i])
			revealedSkolemizedQuads = append(revealedSkolemizedQuads, nonMandatorySkolemized[i])

			// Track blank nodes for label mapping
			quad := nonMandatorySkolemized[i]
			re := regexp.MustCompile(`_:[a-zA-Z0-9\-_]+`)
			matches := re.FindAllString(quad, -1)
			for _, match := range matches {
				hmacID := match[2:] // remove _:
				if _, exists := hmacToNew[hmacID]; !exists {
					rnd := make([]byte, 16)
					if _, err := rand.Read(rnd); err != nil {
						return nil, fmt.Errorf("failed to generate random ID: %w", err)
					}
					newID := fmt.Sprintf("b%x", rnd)
					hmacToNew[hmacID] = newID
					labelMap[newID] = hmacID
				}
			}
		}
	}

	// Always include mandatory quads in the derived credential
	var mandatorySkolemized []string
	for i, q := range quads {
		if mandatorySet[q] {
			mandatorySkolemized = append(mandatorySkolemized, skolemizedQuads[i])
			// Track blank nodes in mandatory quads too
			re := regexp.MustCompile(`_:[a-zA-Z0-9\-_]+`)
			matches := re.FindAllString(skolemizedQuads[i], -1)
			for _, match := range matches {
				hmacID := match[2:]
				if _, exists := hmacToNew[hmacID]; !exists {
					rnd := make([]byte, 16)
					if _, err := rand.Read(rnd); err != nil {
						return nil, fmt.Errorf("failed to generate random ID: %w", err)
					}
					newID := fmt.Sprintf("b%x", rnd)
					hmacToNew[hmacID] = newID
					labelMap[newID] = hmacID
				}
			}
		}
	}

	// Combine mandatory and revealed non-mandatory quads
	allRevealedQuads := append(mandatorySkolemized, revealedSkolemizedQuads...)

	// 4. Create Derived Document
	// Replace HMAC IDs with New IDs using URNs
	derivedQuads := make([]string, len(allRevealedQuads))
	for i, quad := range allRevealedQuads {
		re := regexp.MustCompile(`_:[a-zA-Z0-9\-_]+`)
		derivedQuads[i] = re.ReplaceAllStringFunc(quad, func(match string) string {
			hmacID := match[2:]
			var newID string
			if id, ok := hmacToNew[hmacID]; ok {
				newID = id
			} else {
				// Assign new ID if missing
				newID = fmt.Sprintf("b%d", len(hmacToNew))
				hmacToNew[hmacID] = newID
				labelMap[newID] = hmacID
			}
			return fmt.Sprintf("<urn:bn:%s>", newID)
		})
	}

	// Convert derivedQuads to JSON-LD
	derivedNQuadsStr := strings.Join(derivedQuads, "\n")

	// FromRDF
	fromRdfOpts := ld.NewJsonLdOptions("")
	fromRdfOpts.DocumentLoader = credential.GetGlobalLoader()
	fromRdfOpts.Format = "application/n-quads"
	derivedDoc, err := processor.FromRDF(derivedNQuadsStr, fromRdfOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to JSON-LD: %w", err)
	}

	// Calculate mandatory indexes (which of the revealed quads are mandatory)
	mandatoryIndexes := make([]int, 0)
	for i := 0; i < len(mandatorySkolemized); i++ {
		mandatoryIndexes = append(mandatoryIndexes, i)
	}

	// 5. Create Derived Proof
	derivedProofValue := DerivedProofValueArray{
		BaseSignature:    baseProof.BaseSignature,
		PublicKey:        baseProof.PublicKey,
		Signatures:       derivedSignatures,
		LabelMap:         labelMap,
		MandatoryIndexes: mandatoryIndexes,
	}

	cborArrayBytes, err := cbor.Marshal(derivedProofValue)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal derived proof: %w", err)
	}

	// Add CBOR tag header for DERIVED proof (tag 23809 = 0x5d01)
	// Per W3C spec Section 3.5.3 serializeDerivedProofValue:
	// "Initialize a byte array, proofValue, that starts with the ECDSA-SD disclosure proof header bytes 0xd9, 0x5d, and 0x01"
	cborBytes := make([]byte, 3+len(cborArrayBytes))
	cborBytes[0] = 0xd9 // CBOR tag marker for 2-byte tag
	cborBytes[1] = 0x5d // High byte of tag 23809
	cborBytes[2] = 0x01 // Low byte of tag 23809
	copy(cborBytes[3:], cborArrayBytes)

	proofValue, err := multibase.Encode(multibase.Base64url, cborBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to encode proof value: %w", err)
	}

	// Construct Proof Config
	// Copy from original proof but replace proofValue
	newProofConfig := make(map[string]any)
	maps.Copy(newProofConfig, proofMap)
	newProofConfig["proofValue"] = proofValue

	// Get context from original credential
	originalContext, err := cred.Context()
	if err != nil {
		// Fallback if not available
		originalContext = "https://www.w3.org/ns/credentials/v2"
	}

	// Construct new context ensuring V2 is present
	var ctxList []any
	if list, ok := originalContext.([]any); ok {
		ctxList = append(ctxList, list...)
	} else {
		ctxList = append(ctxList, originalContext)
	}

	// Add V2 context if not present
	hasCredentialV2 := false
	for _, c := range ctxList {
		if s, ok := c.(string); ok && s == "https://www.w3.org/ns/credentials/v2" {
			hasCredentialV2 = true
			break
		}
	}
	if !hasCredentialV2 {
		ctxList = append(ctxList, "https://www.w3.org/ns/credentials/v2")
	}

	newContext := ctxList

	// Compact the derived document
	compactedDerived, err := processor.Compact(derivedDoc, map[string]any{"@context": newContext}, compactOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to compact derived credential: %w", err)
	}

	// Compacting a flattened dataset with several nodes comes back as a
	// bare @graph container - a document about nothing. The proof used to be
	// hung on that container, which is why finding it again needed a walk of
	// the graph. Rooted at its own node instead, with the rest moved to
	// @included: same graph, same quads, same signature.
	// Which node the derived document is about has to come from the BASE
	// credential, not from whatever survived disclosure. A credential whose
	// root carries no identifier cannot say: derivation rewrites blank node
	// labels, so there is nothing left to match it by, and the fallback rule
	// - the node nothing refers to - is exactly what a disclosure can choose.
	// Drop every triple of an anonymous root and the subject becomes the only
	// unreferenced node, so the credential's proof would be attached to the
	// subject. That is the re-rooting this refuses.
	knownRootID, err := cred.RootID()
	if err != nil {
		return nil, fmt.Errorf("failed to read the node the base credential is about: %w", err)
	}
	if knownRootID == "" {
		return nil, fmt.Errorf("cannot derive from a credential whose root carries no identifier: disclosure would decide which node the derived credential is about")
	}
	m, err := credential.RootCompactedDocument(compactedDerived, knownRootID, cred.ExpansionOptions())
	if err != nil {
		return nil, fmt.Errorf("failed to root the derived credential: %w", err)
	}

	// Replace URNs back to blank nodes
	replaceURNs(m)

	// Force context to be the list we want, to avoid Framing merging it into a single object
	// which seems to cause issues with term resolution in ToRDF
	m["@context"] = newContext

	// Add proof to compacted credential
	credential.AppendProofUnder(m, newProofConfig,
		credential.ProofKeyFor(m, m["@context"], cred.ExpansionOptions()))

	derivedBytes, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal derived credential: %w", err)
	}

	derivedCred, err := credential.NewRDFCredentialFromJSON(derivedBytes, ld.NewJsonLdOptions(""))
	if err != nil {
		return nil, err
	}

	return derivedCred, nil
}

// Helper functions
