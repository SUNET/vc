// Package nymauth implements the parts of the EUDI nym_auth rulebook that
// an ISSUER needs.
//
// That is a small surface. The rulebook gives the Issuer one sentence -
// it issues a signed attestation with attributes about an identity subject
// - and assigns pseudonym generation, proving, DCQL satisfiability and
// session binding to the Wallet and the Verifier. What is here is the one
// thing an issuer does with a seed after issuance: recompute the pseudonym
// a Verifier reports, so a pseudonym can be remapped to a person.
//
// It is a consumer of pkg/credential/seed and not the other way round:
// seeds and commitments are generic, and the DST below is the part that
// names this rulebook.
package nymauth

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

// Pseudonym configurations from the rulebook's function catalogue. Each
// decides what prover_input and verifier_input are; the DST is built from
// the name, so a pseudonym under one configuration is unrelated to the
// same subject's pseudonym under another.
const (
	ConfigKnownOffenderMatchingSSC = "known-offender-matching-ssc"
	ConfigKnownOffenderMatchingPSC = "known-offender-matching-psc"
	ConfigAccountRecoverySSC       = "account-recovery-ssc"
	ConfigUserManagedXsiteSSC      = "user-managed-pseudonym-xsite-ssc"
)

// SeedBytes is the length the rulebook fixes for both secret_seed and
// private_seed: "a 16-byte random shared secret", and "a 16-byte random
// value known only to the prover".
const SeedBytes = 16

// nullInput is the 32 zero bytes the rulebook specifies where a
// configuration does not use one of the two inputs. Not an empty slice:
// the inputs are concatenated, so a missing one would shift everything
// after it and produce a different pseudonym.
var nullInput = make([]byte, 32)

// Pseudonym computes pseudonym:
//
//	pseudonym = SHA256(DST || seed || prover_input || verifier_input)
//	DST       = "nym_auth/v1/<config>", UTF-8
//
// seed is the OPENING of the commitment in the credential - secret_seed
// for an ssc configuration, private_seed for a psc one - and not the
// commitment itself.
//
// NOTE: the rulebook publishes a vector for the seed/commitment pair and
// none for a pseudonym, so this construction is implemented from the
// specification text and has not been checked against a reference output.
// Treat a disagreement with a Verifier as this being wrong until shown
// otherwise.
func Pseudonym(config string, seed, proverInput, verifierInput []byte) ([]byte, error) {
	if config == "" {
		return nil, fmt.Errorf("nymauth: no pseudonym configuration named")
	}
	// The rulebook fixes both secret_seed and private_seed at 16 bytes.
	// A seed of any other length would hash a concatenation shifted
	// against what the circuit computes, so the pseudonym would simply be
	// wrong - and wrong in a way nothing here could detect, since the
	// output is 32 bytes either way. Reachable through a generic seed
	// source configured with a different seed_bytes, which is exactly the
	// cost of the primitive not being nym_auth-specific.
	if len(seed) != SeedBytes {
		return nil, fmt.Errorf("nymauth: a seed is %d bytes in this rulebook, got %d", SeedBytes, len(seed))
	}
	if len(proverInput) != len(nullInput) || len(verifierInput) != len(nullInput) {
		return nil, fmt.Errorf("nymauth: prover_input and verifier_input must each be %d bytes", len(nullInput))
	}

	h := sha256.New()
	h.Write([]byte("nym_auth/v1/" + config))
	h.Write(seed)
	h.Write(proverInput)
	h.Write(verifierInput)
	return h.Sum(nil), nil
}

// Two strings that both look like a prefix and a colon, and are not the
// same kind of thing at all.
//
// VerifierIDX509SANDNS is an OpenID4VP Client Identifier Prefix. It is
// NOT part of the hashed input, and is named here only so that a value
// carrying it can be refused: see checkVerifierID.
//
// VerifierIDSemantic is part of the `semantic` verifier_id VALUE, not a
// Client Identifier Prefix - nym_auth_rulebook PR #7 says so in those
// words. A semantic Verifier's verifier_id is the whole string
// "semantic_id:<identifier>", and that whole string is what is hashed.
const (
	VerifierIDSemantic   = "semantic_id:"
	VerifierIDX509SANDNS = "x509_san_dns:"
)

// checkVerifierID refuses an identifier no conforming Verifier could have
// reported.
//
// The hashed input is the BARE verifier_id - "verifier.example" for an
// x509_san_dns Verifier, "semantic_id:<identifier>" for a semantic one -
// never the prefixed Client Identifier and never client_id as it appears
// in the request. verifier_id_type is agreed out of band and is not
// hashed.
//
// "Bare" is about the Client Identifier Prefix, not about colons. A
// semantic verifier_id carries "semantic_id:" as part of its own value
// and is hashed whole; refusing it would leave semantic deployments
// unable to derive verifier_input at all.
//
// WHICH RULEBOOK: nym_auth_rulebook PR #7, "verifier_input: SHA-256 over
// the bare verifier_id, never the prefixed client_id" (stacked on #5).
// Pinned explicitly because the published v0.3 on that repo's main says
// the opposite - its matching and account-recovery formulas hash the
// full prefixed identifier - so a reader comparing this against main
// will find a contradiction rather than a bug. #7 supersedes it, states
// the rule with worked digests, and marks the prefixed form MUST NOT:
//
//	SHA256("verifier.example")              = be6a6400...4a41   (MUST)
//	SHA256("x509_san_dns:verifier.example") = 6eae85a0...6bab   (MUST NOT)
//
// #7 also records that the nym_auth circuits SPEC section 3 still shows
// the prefixed form and that its reference values need regenerating; the
// prefix is not bound inside the circuit, which takes verifier_input as
// a 32-byte digest public input, so a conforming verifier passing the
// bare digest verifies against current circuit builds.
//
// So a PREFIXED value is refused here, which is the opposite of what this
// function did when it was written against the earlier reading. The
// reason for refusing rather than stripping is unchanged: hashing
// whatever it is given succeeds and returns a 32-byte pseudonym
// indistinguishable from a correct one, so a remapping loop comparing
// against a Verifier's real pseudonym would simply never match, and the
// operator would conclude the subject is not the one they are looking
// for. A wrong answer, not an error.
//
// Stripping the prefix would be the tempting repair and is worse: it
// would accept a caller that is confused about which value it holds, and
// a caller confused about that is one whose OTHER inputs deserve a second
// look.
// CheckVerifierID is checkVerifierID for callers outside this package -
// the verifier side, which derives verifier_input from the same value
// and must refuse the same inputs. One rule, one implementation: a
// second copy is how the issuer and the verifier end up hashing
// different things and blaming each other's pseudonyms.
func CheckVerifierID(verifierID string) error { return checkVerifierID(verifierID) }

func checkVerifierID(verifierID string) error {
	if verifierID == "" {
		return fmt.Errorf("nymauth: no verifier_id")
	}
	if strings.HasPrefix(verifierID, VerifierIDX509SANDNS) {
		return fmt.Errorf("nymauth: verifier_id %q carries the Client Identifier prefix %q; "+
			"the hashed input is the bare verifier_id, and hashing the prefixed form yields a pseudonym no Verifier reports",
			verifierID, VerifierIDX509SANDNS)
	}
	if verifierID == VerifierIDSemantic {
		// The semantic form with nothing after the colon names no
		// Verifier. It hashes cleanly, like every other wrong value
		// here, so it is refused rather than turned into a pseudonym
		// nobody reports.
		return fmt.Errorf("nymauth: verifier_id %q is the semantic form with no identifier after it", verifierID)
	}
	return nil
}

// KnownOffenderMatching computes the pseudonym a Verifier identified by
// verifierID sees, under either the ssc or psc configuration - they differ
// only in which seed opens which commitment, which is the caller's to
// supply.
//
// prover_input is null; verifier_input is SHA256(verifier_id).
//
// verifierID is the BARE identifier - "verifier.example" - without the
// Client Identifier prefix and without verifier_id_type, which is agreed
// out of band and not hashed. See checkVerifierID.
func KnownOffenderMatching(config string, seed []byte, verifierID string) ([]byte, error) {
	switch config {
	case ConfigKnownOffenderMatchingSSC, ConfigKnownOffenderMatchingPSC:
	default:
		return nil, fmt.Errorf("nymauth: %q is not a known-offender-matching configuration", config)
	}
	if err := checkVerifierID(verifierID); err != nil {
		return nil, err
	}
	verifierInput := sha256.Sum256([]byte(verifierID))
	return Pseudonym(config, seed, nullInput, verifierInput[:])
}

// AccountRecovery computes the pseudonym for account-recovery-ssc.
//
// prover_input is null; verifier_input is
// SHA256(SHA256(verifier_id) || SHA256(verifier_context)), over the BARE
// verifier_id as in KnownOffenderMatching.
func AccountRecovery(seed []byte, verifierID, verifierContext string) ([]byte, error) {
	if err := checkVerifierID(verifierID); err != nil {
		return nil, err
	}
	// The rulebook requires verifier_context for this configuration and
	// bounds it at 1-64 bytes. An absent one is a different pseudonym, not
	// a tolerable omission.
	if l := len(verifierContext); l < 1 || l > 64 {
		return nil, fmt.Errorf("nymauth: verifier_context must be 1-64 bytes for %s", ConfigAccountRecoverySSC)
	}

	idDigest := sha256.Sum256([]byte(verifierID))
	ctxDigest := sha256.Sum256([]byte(verifierContext))

	h := sha256.New()
	h.Write(idDigest[:])
	h.Write(ctxDigest[:])
	verifierInput := h.Sum(nil)

	return Pseudonym(ConfigAccountRecoverySSC, seed, nullInput, verifierInput)
}

// UserManagedXsite computes the pseudonym for
// user-managed-pseudonym-xsite-ssc.
//
// prover_input is the SHA-256 digest of a value the USER chose and shares
// across the sites they want linked; verifier_input is null, which is why
// the same pseudonym goes to every Verifier.
//
// An issuer can only reproduce this if it learns the user's value, which
// it has no way to do on its own - included for completeness, and because
// leaving it out would make the catalogue look like three configurations
// rather than four.
func UserManagedXsite(seed []byte, userValue string) ([]byte, error) {
	if userValue == "" {
		return nil, fmt.Errorf("nymauth: no user-supplied value")
	}
	proverInput := sha256.Sum256([]byte(userValue))
	return Pseudonym(ConfigUserManagedXsiteSSC, seed, proverInput[:], nullInput)
}
