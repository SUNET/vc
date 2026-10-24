// opening_recover reproduces the opening of a hash_commitment entry, and its
// commitment, from the issuer's config file and a subject's identifiers.
//
// It reads the secret the entry's hkdf opening names, so it runs where the
// issuer's config and secret are. Whoever can run it can reproduce the
// opening of any subject.
package main

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/SUNET/vc/pkg/credential/primitives"
	"github.com/SUNET/vc/pkg/credential/seed"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vci"

	"gopkg.in/yaml.v2"
)

// Exit codes. A mismatch is its own code, so a loop over candidate
// subjects can tell it from an error.
const (
	exitOK       = 0
	exitError    = 1
	exitMismatch = 2
)

func main() {
	code, err := run(context.Background(), os.Args[1:], os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "opening_recover:", err)
	}
	os.Exit(code)
}

// invocation is a parsed command line.
type invocation struct {
	configPath  string
	scope       string
	path        []string
	inputs      []string
	expect      []byte
	showOpening bool
}

func run(ctx context.Context, args []string, out io.Writer) (int, error) {
	inv, err := parseInvocation(args)
	if err != nil {
		return exitError, err
	}
	cfg, err := loadConfig(inv.configPath)
	if err != nil {
		return exitError, err
	}
	entry, err := findEntry(cfg, inv.scope, inv.path)
	if err != nil {
		return exitError, err
	}
	results, err := entry.reproduce(ctx, inv.inputs)
	if err != nil {
		return exitError, err
	}
	matched := false
	for _, r := range results {
		fmt.Fprintf(out, "sources:    %s\n", strings.Join(r.sources, ", "))
		fmt.Fprintf(out, "commitment: %s\n", hex.EncodeToString(r.commitment))
		if inv.showOpening {
			fmt.Fprintf(out, "opening:    %s\n", hex.EncodeToString(r.opening))
		}
		matched = matched || (inv.expect != nil && subtle.ConstantTimeCompare(inv.expect, r.commitment) == 1)
	}
	switch {
	case inv.expect == nil:
		return exitOK, nil
	case matched:
		fmt.Fprintln(out, "match:      yes")
		return exitOK, nil
	default:
		fmt.Fprintln(out, "match:      no")
		return exitMismatch, nil
	}
}

// parseInvocation reads the flags. An -expect given with an empty value is
// refused: a loop calling `-expect "$reported"` with an unset variable
// would otherwise exit 0 for every candidate.
func parseInvocation(args []string) (*invocation, error) {
	flags := flag.NewFlagSet("opening_recover", flag.ContinueOnError)
	var (
		inv      invocation
		pathJSON string
		expect   string
		inputs   inputList
	)
	flags.StringVar(&inv.configPath, "config", "", "the issuer's config file (required)")
	flags.StringVar(&inv.scope, "scope", "", "the credential scope (required)")
	flags.StringVar(&pathJSON, "path", "", `the entry's claims path as JSON, such as ["eu.europa.ec.eudi.nym_auth.1","ssc"]; optional when the scope has one hkdf entry`)
	flags.StringVar(&expect, "expect", "", "a commitment in hex: exit 0 on a match, 2 on a mismatch")
	flags.BoolVar(&inv.showOpening, "show-opening", false, "also print the opening")
	flags.Var(&inputs, "input", "an hkdf input value; repeat in the configured order (required)")
	if err := flags.Parse(args); err != nil {
		return nil, err
	}
	inv.inputs = inputs
	switch {
	case inv.configPath == "":
		return nil, errors.New("-config is required")
	case inv.scope == "":
		return nil, errors.New("-scope is required")
	case len(inv.inputs) == 0:
		return nil, errors.New("-input is required, once per hkdf input in the configured order")
	}
	if pathJSON != "" {
		if err := json.Unmarshal([]byte(pathJSON), &inv.path); err != nil || len(inv.path) == 0 {
			return nil, fmt.Errorf("-path %q is no JSON array of strings", pathJSON)
		}
	}
	if !flagGiven(flags, "expect") {
		return &inv, nil
	}
	want, err := hex.DecodeString(strings.TrimSpace(expect))
	if err != nil || len(want) == 0 {
		return nil, errors.New("-expect is no commitment in hex")
	}
	inv.expect = want
	return &inv, nil
}

func flagGiven(flags *flag.FlagSet, name string) bool {
	given := false
	flags.Visit(func(f *flag.Flag) { given = given || f.Name == name })
	return given
}

// loadConfig parses the config file as the issuer does.
func loadConfig(path string) (*model.Cfg, error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	cfg := &model.Cfg{}
	if err := yaml.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return cfg, nil
}

// entry is a to_wallet entry with the hkdf openings its source scopes
// configure.
type entry struct {
	alg      string
	openings []sourceOpening
}

type sourceOpening struct {
	where string
	hkdf  *primitives.HKDFOpeningArgs
}

// findEntry returns the to_wallet entry of scope at path, or the one with
// an hkdf opening when path is empty.
func findEntry(cfg *model.Cfg, scope string, path []string) (*entry, error) {
	meta := cfg.Common.CredentialMetadata[scope]
	if meta == nil || meta.AuxiliaryData == nil || cfg.APIGW == nil {
		return nil, fmt.Errorf("scope %q configures no auxiliary_data", scope)
	}
	if path == nil {
		var err error
		if path, err = onlyHKDFPath(cfg.APIGW.DataSources, scope); err != nil {
			return nil, err
		}
	}
	i := slices.IndexFunc(meta.AuxiliaryData.ToWallet, func(e openid4vci.AuxiliaryDataEntry) bool { return slices.Equal(e.Path, path) })
	if i < 0 {
		return nil, fmt.Errorf("scope %q has no to_wallet entry %q", scope, path)
	}
	openings := hkdfOpenings(cfg.APIGW.DataSources, scope, path)
	if len(openings) == 0 {
		return nil, fmt.Errorf("no source scope of %q derives %q with hkdf", scope, path)
	}
	return &entry{alg: meta.AuxiliaryData.ToWallet[i].Alg, openings: openings}, nil
}

// hkdfOpenings returns the hkdf opening each source scope of scope
// configures for path.
func hkdfOpenings(sources model.DataSources, scope string, path []string) []sourceOpening {
	var openings []sourceOpening
	for _, src := range sources.SourceScopes() {
		hc := primitives.HashCommitmentFor(src.Derivations, path)
		if src.Scope == scope && hc != nil && hc.Opening.HKDF != nil {
			openings = append(openings, sourceOpening{where: src.Where(), hkdf: hc.Opening.HKDF})
		}
	}
	return openings
}

// onlyHKDFPath returns the path of scope's one hkdf hash_commitment.
func onlyHKDFPath(sources model.DataSources, scope string) ([]string, error) {
	var paths [][]string
	for _, src := range sources.SourceScopes() {
		for _, d := range src.Derivations {
			hc := d.HashCommitment
			if src.Scope == scope && hc != nil && hc.Opening.HKDF != nil && !slices.ContainsFunc(paths, func(p []string) bool { return slices.Equal(p, hc.Path) }) {
				paths = append(paths, hc.Path)
			}
		}
	}
	if len(paths) != 1 {
		return nil, fmt.Errorf("scope %q has %d hkdf entries %q; name one with -path", scope, len(paths), paths)
	}
	return paths[0], nil
}

// result is one opening, with the source scopes that derive it.
type result struct {
	sources    []string
	opening    []byte
	commitment []byte
}

// reproduce derives the opening of each source scope, and merges the
// source scopes that derive the same one.
func (e *entry) reproduce(ctx context.Context, inputs []string) ([]result, error) {
	var results []result
	for _, o := range e.openings {
		opening, err := o.hkdf.OpenValues(ctx, inputs)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", o.where, err)
		}
		i := slices.IndexFunc(results, func(r result) bool { return subtle.ConstantTimeCompare(r.opening, opening) == 1 })
		if i >= 0 {
			results[i].sources = append(results[i].sources, o.where)
			continue
		}
		commitment, err := seed.Commit(e.alg, opening)
		if err != nil {
			return nil, err
		}
		results = append(results, result{sources: []string{o.where}, opening: opening, commitment: commitment})
	}
	return results, nil
}

// inputList collects a repeated -input flag in order.
type inputList []string

func (l *inputList) String() string { return strings.Join(*l, ", ") }

func (l *inputList) Set(v string) error {
	*l = append(*l, v)
	return nil
}
