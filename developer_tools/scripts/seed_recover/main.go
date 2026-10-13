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
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

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
		subject         = flag.String("subject", "", "the stable subject identifier (required)")
		derivContext    = flag.String("context", "", "the derivation context, if the credential configuration sets one")
		pseudonymConfig = flag.String("pseudonym-config", "", "nym_auth pseudonym configuration to compute, e.g. known-offender-matching-ssc")
		verifierID      = flag.String("verifier-id", "", "full verifier identifier including its prefix, e.g. x509_san_dns:rp.example")
		verifierContext = flag.String("verifier-context", "", "verifier_context, required for account-recovery-ssc")
		userValue       = flag.String("user-value", "", "the user-supplied linking value, for user-managed-pseudonym-xsite-ssc")
		expect          = flag.String("expect", "", "a pseudonym in hex to compare against; exit 0 on a match, 2 on a mismatch")
		showSeed        = flag.Bool("show-seed", false, "also print the seed itself")
	)
	flag.Parse()

	switch {
	case *configPath == "":
		return errors.New("-config is required")
	case *sourceName == "":
		return errors.New("-seed is required")
	case *subject == "":
		return errors.New("-subject is required")
	}

	source, err := loadSeedSource(*configPath, *sourceName)
	if err != nil {
		return err
	}

	seedValue, err := source.Seed(context.Background(), *subject, *derivContext)
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
		return nil
	}

	pseudonym, err := computePseudonym(*pseudonymConfig, seedValue, *verifierID, *verifierContext, *userValue)
	if err != nil {
		return err
	}
	fmt.Printf("pseudonym:  %s\n", hex.EncodeToString(pseudonym))

	if *expect == "" {
		return nil
	}
	want, err := hex.DecodeString(strings.TrimSpace(*expect))
	if err != nil {
		return fmt.Errorf("-expect is not hex: %w", err)
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
	if cfg.Issuer == nil || len(cfg.Issuer.Seeds) == 0 {
		return nil, fmt.Errorf("%s configures no issuer.seeds", configPath)
	}

	src, ok := cfg.Issuer.Seeds[name]
	if !ok || src == nil {
		named := make([]string, 0, len(cfg.Issuer.Seeds))
		for k := range cfg.Issuer.Seeds {
			named = append(named, k)
		}
		return nil, fmt.Errorf("no seed source %q; %s has %s", name, configPath, strings.Join(named, ", "))
	}
	if src.Model != model.SeedModelDerived {
		return nil, fmt.Errorf("seed source %q has model %q; only %q can be reproduced without the issuer's store",
			name, src.Model, model.SeedModelDerived)
	}

	secret, err := seedSecret(src)
	if err != nil {
		return nil, err
	}
	return seed.NewDeriver(secret, src.SeedBytes)
}
