package nymauth

import (
	"fmt"
	"strings"
)

// The verifier_id rule of rulebook v0.4, and the vocabulary around it.
//
// Here rather than beside the issuer's derivations because it belongs to
// both sides and outlives one of them: SHA-256(verifier_id) is
// verifier_input, which an ISSUER needs when it derives a pseudonym and a
// VERIFIER needs when it checks a proof against one. One rule, one
// implementation - a second copy is how the two ends come to hash
// different things and blame each other's pseudonyms.

// Two strings that both look like a prefix and a colon, and are not the
// same kind of thing at all.
//
// VerifierIDX509SANDNS is an OpenID4VP Client Identifier Prefix.
// VerifierIDSemantic is part of the `semantic` verifier_id VALUE rather
// than a Client Identifier Prefix - nym_auth_rulebook PR #7 says so in
// those words.
//
// Under rulebook v0.4 the distinction does not change what is hashed:
// the WHOLE verifier_id is, prefix included, in both forms. They are
// named separately because the refusal below has to tell an operator
// which form they are missing, and because the distinction still matters
// to anything reasoning about Client Identifiers.
const (
	VerifierIDSemantic   = "semantic_id:"
	VerifierIDX509SANDNS = "x509_san_dns:"
)

// CheckVerifierID refuses an identifier no conforming Verifier could
// have published.
func CheckVerifierID(verifierID string) error {
	if verifierID == "" {
		return fmt.Errorf("nymauth: no verifier_id")
	}

	// Rulebook v0.4 defines exactly TWO forms. Anything else is
	// refused rather than hashed.
	//
	// This is the half that went missing when the rule reversed on
	// 2026-10-20. Before, a bare DNS name was the correct value and
	// the prefixed form was refused; after, the prefixed form is
	// correct - and nothing was left checking the shape at all, so a
	// configuration still carrying the old bare value started
	// cleanly and produced pseudonyms no Verifier reports. Found by
	// sirosid-dev starting a gdc image with
	// "sirosid-gdc-vc-verifier.fly.dev" configured.
	//
	// Fail closed, and no normalisation: the rulebook names two
	// forms, so a third is a value nobody agreed the meaning of.
	for _, prefix := range []string{VerifierIDX509SANDNS, VerifierIDSemantic} {
		if verifierID == prefix {
			// The marker with nothing after it names no Verifier. It
			// hashes cleanly, like every other wrong value here, so
			// it is refused rather than turned into a pseudonym
			// nobody reports.
			return fmt.Errorf("nymauth: verifier_id %q is the %s prefix with no identifier after it",
				verifierID, strings.TrimSuffix(prefix, ":"))
		}
		if strings.HasPrefix(verifierID, prefix) {
			return nil
		}
	}

	// A value that looks like a host is the likely mistake, and the
	// likely fix is one prefix - so say it, rather than leaving the
	// operator to infer it from the list of forms.
	hint := ""
	if looksLikeDNSName(verifierID) {
		hint = fmt.Sprintf("; it looks like a DNS name, so the verifier_id is probably %q",
			VerifierIDX509SANDNS+verifierID)
	}
	return fmt.Errorf("nymauth: verifier_id %q starts with neither %q nor %q, and rulebook v0.4 defines no other form%s",
		verifierID, VerifierIDX509SANDNS, VerifierIDSemantic, hint)
}

// looksLikeDNSName reports whether a value is plausibly a hostname
// someone forgot to prefix: dot-separated labels of letters, digits
// and hyphens, and nothing else.
//
// Only used to add a hint to a refusal, so a false negative costs a
// sentence and a false positive costs nothing - it is never a reason
// to accept a value.
func looksLikeDNSName(value string) bool {
	if value == "" || strings.ContainsAny(value, ":/ ") || !strings.Contains(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" {
			return false
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
			default:
				return false
			}
		}
	}
	return true
}
