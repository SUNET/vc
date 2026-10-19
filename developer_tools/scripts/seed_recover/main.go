// seed_recover reproduces a subject's seed, its commitment, and the
// pseudonym a Verifier reported, from the same configuration the issuer
// runs on.
//
// This is what the issuer-known seed model exists for. A Verifier that
// has a pseudonym it wants remapped to a person hands it over; the issuer
// recomputes the candidate pseudonym for each subject it is asked about
// and compares. Nothing is stored and nothing is online: a derived seed is
// a function of the secret and the subject identifier, so the answer can
// be reproduced at any later date.
//
// It reads the issuer's own config file and secret, so it has to run
// where those are - which is the intended restriction, not an
// inconvenience: whoever can run this can link any pseudonym to a person.
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

	"github.com/SUNET/vc/pkg/configuration"
	"github.com/SUNET/vc/pkg/credential/seed"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/nymauth"

	"github.com/goccy/go-yaml"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "seed_recover:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		configPath      = flag.String("config", "", "path to the issuer config YAML (required)")
		sourceName      = flag.String("seed", "", "name of the seed source in issuer.seeds (required)")
		subjects        subjectList
		derivContext    = flag.String("context", "", "the derivation context, if the credential configuration sets one")
		pseudonymConfig = flag.String("pseudonym-config", "", "nym_auth pseudonym configuration to compute, e.g. known-offender-matching-ssc")
		verifierID      = flag.String("verifier-id", "", "the BARE verifier_id, e.g. verifier.example - not the prefixed client_id")
		verifierContext = flag.String("verifier-context", "", "verifier_context, required for account-recovery-ssc")
		userValue       = flag.String("user-value", "", "the user-supplied linking value, for user-managed-pseudonym-xsite-ssc")
		expect          = flag.String("expect", "", "a pseudonym in hex to compare against; exit 0 on a match, 2 on a mismatch")
		showSeed        = flag.Bool("show-seed", false, "also print the seed itself")
	)
	flag.Var(&subjects, "subject",
		"a subject identifier; repeat IN ORDER for a configuration that derives from several (required)")
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

	if err := validateInvocation(*configPath, *sourceName, subjects, expectSet, *expect, *pseudonymConfig); err != nil {
		return err
	}

	source, err := loadSeedSource(*configPath, *sourceName)
	if err != nil {
		return err
	}

	seedValue, err := source.Seed(context.Background(), []string(subjects), *derivContext)
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
func validateInvocation(configPath, sourceName string, subjects []string, expectSet bool, expect, pseudonymConfig string) error {
	switch {
	case configPath == "":
		return errors.New("-config is required")
	case sourceName == "":
		return errors.New("-seed is required")
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
	case nymauth.ConfigKnownOffenderMatchingSSC, nymauth.ConfigKnownOffenderMatchingPSC:
		return nymauth.KnownOffenderMatching(config, seedValue, verifierID)
	case nymauth.ConfigAccountRecoverySSC:
		return nymauth.AccountRecovery(seedValue, verifierID, verifierContext)
	case nymauth.ConfigUserManagedXsiteSSC:
		return nymauth.UserManagedXsite(seedValue, userValue)
	default:
		return nil, fmt.Errorf("unknown pseudonym configuration %q", config)
	}
}

// loadSeedSource reads the issuer's configuration and builds the named
// source exactly as the issuer does, so that what this prints is what the
// issuer wrote and not an approximation of it.
func loadSeedSource(configPath, name string) (seed.Source, error) {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	cfg := &model.Cfg{}
	if err := yaml.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", configPath, err)
	}

	// The secrets file, the same way the issuer reads it.
	//
	// Without this the recommended setup - the derivation secret in the
	// secrets file rather than inline - lets issuance work and makes
	// RECOVERY fail, reporting that the source sets neither secret_path
	// nor secret. That is the worst place for this tool to break: the
	// whole reason the issuer keeps a derivation secret is that a seed
	// can be reproduced later, and this is what does the reproducing.
	//
	// Through configuration.LoadSecrets rather than a local reader, so
	// the permission check on the secrets file is the issuer's own and
	// the precedence between the two sources cannot drift from it.
	if cfg.Common != nil && cfg.Common.SecretFilePath != "" {
		secrets, err := configuration.LoadSecrets(cfg.Common.SecretFilePath, cfg.Common.SkipSecretsPermCheck)
		if err != nil {
			return nil, fmt.Errorf("loading the secrets file named by %s: %w", configPath, err)
		}
		cfg.ApplySecrets(secrets)
	}

	if cfg.APIGW == nil || len(cfg.APIGW.Seeds) == 0 {
		return nil, fmt.Errorf("%s configures no apigw.seeds", configPath)
	}

	src, ok := cfg.APIGW.Seeds[name]
	if !ok || src == nil {
		named := make([]string, 0, len(cfg.APIGW.Seeds))
		for k := range cfg.APIGW.Seeds {
			named = append(named, k)
		}
		return nil, fmt.Errorf("no seed source %q; %s has %s", name, configPath, strings.Join(named, ", "))
	}
	if src.Model != model.SeedModelDerived {
		return nil, fmt.Errorf("seed source %q has model %q; only %q derives a reproducible seed",
			name, src.Model, model.SeedModelDerived)
	}

	secret, err := seedSecret(src)
	if err != nil {
		return nil, err
	}
	return seed.NewDeriver(secret, src.SeedBytes)
}
