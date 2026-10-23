// seed_recover reproduces a subject's seed, its commitment, and the
// pseudonym a Verifier reported, from the secret of the issuer's hkdf
// opening (a hash_commitment derivation).
//
// This is what the issuer-known seed model exists for. A Verifier that
// has a pseudonym it wants remapped to a person hands it over; the issuer
// recomputes the candidate pseudonym for each subject it is asked about
// and compares. Nothing is stored and nothing is online: a derived seed is
// a function of the secret and the subject identifier, so the answer can
// be reproduced at any later date.
//
// It reads the issuer's own secret, so it has to run where that is - which
// is the intended restriction, not an inconvenience: whoever can run this
// can link any pseudonym to a person.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/SUNET/vc/pkg/credential/primitives"
	"github.com/SUNET/vc/pkg/credential/seed"
	"github.com/SUNET/vc/pkg/nymauth"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "seed_recover:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		secretPath      = flag.String("secret-path", "", "the secret_path of the hkdf opening (required)")
		subjects        subjectList
		pseudonymConfig = flag.String("pseudonym-config", "", "nym_auth pseudonym configuration to compute, e.g. known-offender-matching-ssc")
		verifierID      = flag.String("verifier-id", "", "the verifier_id EXACTLY as the Verifier publishes it: bare (verifier.example) for an x509_san_dns Verifier, or semantic_id:<identifier> for a semantic one - never the prefixed client_id")
		verifierContext = flag.String("verifier-context", "", "verifier_context, required for account-recovery-ssc")
		userValue       = flag.String("user-value", "", "the user-supplied linking value, for user-managed-pseudonym-xsite-ssc")
		expect          = flag.String("expect", "", "a pseudonym in hex to compare against; exit 0 on a match, 2 on a mismatch")
		showSeed        = flag.Bool("show-seed", false, "also print the seed itself")
	)
	flag.Var(&subjects, "subject",
		"an hkdf input value; repeat IN ORDER for an opening derived from several (required)")
	flag.Parse()

	// Whether -expect was GIVEN, not whether it has a value. The two
	// differ exactly where it matters: `-expect "$reported"` with an
	// empty variable supplies the flag with an empty value, and reading
	// the value alone cannot tell that from the flag being absent.
	expectSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "expect" {
			expectSet = true
		}
	})

	if err := validateInvocation(*secretPath, subjects, expectSet, *expect, *pseudonymConfig); err != nil {
		return err
	}

	deriver, err := (&primitives.HKDFOpeningArgs{SecretPath: *secretPath}).Deriver()
	if err != nil {
		return err
	}

	seedValue, err := deriver.Seed(context.Background(), []string(subjects), "")
	if err != nil {
		return err
	}

	commitment, err := seed.Commit("", seedValue)
	if err != nil {
		return err
	}

	// The seed is the one value here that opens everything derived from
	// it, so it is printed only when asked for. The commitment is what
	// appears in the credential and is not secret.
	if *showSeed {
		fmt.Printf("seed:       %s\n", hex.EncodeToString(seedValue))
	}
	fmt.Printf("commitment: %s\n", hex.EncodeToString(commitment))

	if *pseudonymConfig == "" {
		// No -expect either; the guard above refuses that pairing.
		return nil
	}

	pseudonym, err := computePseudonym(*pseudonymConfig, seedValue, *verifierID, *verifierContext, *userValue)
	if err != nil {
		return err
	}
	fmt.Printf("pseudonym:  %s\n", hex.EncodeToString(pseudonym))

	if !expectSet {
		// Nothing to compare against: the pseudonym was asked for and is
		// printed above. No "match" line, so a caller parsing output
		// cannot read a comparison that did not happen.
		return nil
	}
	want, err := parseExpectation(*expect)
	if err != nil {
		return err
	}
	// Constant time, which matters less here than the habit of it: this
	// compares a value a Verifier supplied against one computed from a
	// secret.
	if subtle.ConstantTimeCompare(want, pseudonym) != 1 {
		fmt.Println("match:      no")
		os.Exit(2)
	}
	fmt.Println("match:      yes")
	return nil
}

// validateInvocation refuses the flag combinations that would make the
// EXIT CODE lie.
//
// This tool's documented use is a loop over candidate subjects driven by
// the exit code - 0 means "this is the person behind that pseudonym" -
// so every path that exits 0 without having compared anything is a false
// accusation waiting to happen. Both -expect guards exist for that one
// reason.
func validateInvocation(secretPath string, subjects []string, expectSet bool, expect, pseudonymConfig string) error {
	switch {
	case secretPath == "":
		return errors.New("-secret-path is required")
	case len(subjects) == 0:
		return errors.New("-subject is required (repeat it, in order, when several identifiers are configured)")
	case expectSet && strings.TrimSpace(expect) == "":
		// `-expect "$reported"` with an unset variable. Treating that as
		// "no expectation" exits 0 having compared nothing, so a loop
		// reports a MATCH for the first candidate it tries - and for
		// every candidate after it.
		return errors.New("-expect was given an empty value: a comparison was asked for and there is nothing to compare against")
	case expectSet && pseudonymConfig == "":
		return errors.New("-expect needs -pseudonym-config: there is nothing to compare against without one")
	}
	return nil
}

// subjectList collects a repeated -subject flag IN ORDER.
//
// Order is part of the derivation - ["a","bc"] and ["ab","c"] are
// different subjects - so recovery has to reproduce the configured
// sequence exactly, which a repeated flag does and a set would not.
type subjectList []string

func (s *subjectList) String() string { return strings.Join(*s, ", ") }

func (s *subjectList) Set(v string) error {
	if v == "" {
		return errors.New("a subject identifier cannot be empty")
	}
	*s = append(*s, v)
	return nil
}

// parseExpectation reads the -expect pseudonym.
//
// Length is checked as well as encoding. A pseudonym is a SHA-256 digest,
// so a valid-hex value of any other length cannot match any subject - and
// reporting that as "match: no" tells the operator the wrong thing: the
// documented remapping loop walks every candidate and reports a mismatch
// for each, when the input was never a pseudonym at all. An input error
// says so once, instead.
func parseExpectation(expect string) ([]byte, error) {
	want, err := hex.DecodeString(strings.TrimSpace(expect))
	if err != nil {
		return nil, fmt.Errorf("-expect is not hex: %w", err)
	}
	if len(want) != sha256.Size {
		return nil, fmt.Errorf("-expect decodes to %d bytes; a pseudonym is %d, so this value cannot match any subject", len(want), sha256.Size)
	}
	return want, nil
}

func computePseudonym(config string, seedValue []byte, verifierID, verifierContext, userValue string) ([]byte, error) {
	switch config {
	case nymauth.ConfigKnownOffenderMatchingPSC:
		// Refused, although the library helper computes it.
		//
		// psc opens a HOLDER-held private_seed. This tool only ever
		// has the issuer's derived seed, so it would compute a
		// pseudonym over the wrong secret, get no match, and report an
		// ordinary mismatch - which in a loop over candidates reads as
		// "this subject is not the one", for every subject including
		// the right one. A tool whose exit code accuses people must not
		// have a mode that exonerates them all.
		return nil, fmt.Errorf("%s opens a holder-held private_seed, which this tool does not have; "+
			"it can only reproduce the issuer-held %s", config, nymauth.ConfigKnownOffenderMatchingSSC)
	case nymauth.ConfigKnownOffenderMatchingSSC:
		return nymauth.KnownOffenderMatching(config, seedValue, verifierID)
	case nymauth.ConfigAccountRecoverySSC:
		return nymauth.AccountRecovery(seedValue, verifierID, verifierContext)
	case nymauth.ConfigUserManagedXsiteSSC:
		return nymauth.UserManagedXsite(seedValue, userValue)
	default:
		return nil, fmt.Errorf("unknown pseudonym configuration %q", config)
	}
}
